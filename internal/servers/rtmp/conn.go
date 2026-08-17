package rtmp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bluenviron/gortmplib"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/google/uuid"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/externalcmd"
	"github.com/bluenviron/mediamtx/internal/hooks"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/protocols/rtmp"
	"github.com/bluenviron/mediamtx/internal/stream"
)

type conn struct {
	parentCtx           context.Context
	encryption          bool
	streamKeyApp        string
	rtspAddress         string
	readTimeout         conf.Duration
	writeTimeout        conf.Duration
	runOnConnect        string
	runOnConnectRestart bool
	runOnDisconnect     string
	wg                  *sync.WaitGroup
	nconn               net.Conn
	externalCmdPool     *externalcmd.Pool
	pathManager         serverPathManager
	parent              *Server

	ctx       context.Context
	ctxCancel func()
	uuid      uuid.UUID
	created   time.Time
	mutex     sync.RWMutex
	rconn     *gortmplib.ServerConn
	state     defs.APIRTMPConnState
	pathName  string
	query     string
	user      string
	userAgent string
	reader    *stream.Reader
}

func (c *conn) initialize() {
	c.ctx, c.ctxCancel = context.WithCancel(c.parentCtx)

	c.uuid = uuid.New()
	c.created = time.Now()
	c.state = defs.APIRTMPConnStateIdle

	c.Log(logger.Info, "opened")

	c.wg.Add(1)
	go c.run()
}

func (c *conn) Close() {
	c.ctxCancel()
}

func (c *conn) remoteAddr() net.Addr {
	return c.nconn.RemoteAddr()
}

// Log implements logger.Writer.
func (c *conn) Log(level logger.Level, format string, args ...any) {
	c.parent.Log(level, "[conn %v] "+format, append([]any{c.nconn.RemoteAddr()}, args...)...)
}

func (c *conn) ip() net.IP {
	return c.nconn.RemoteAddr().(*net.TCPAddr).IP
}

func (c *conn) run() { //nolint:dupl
	defer c.wg.Done()

	onDisconnectHook := hooks.OnConnect(hooks.OnConnectParams{
		Logger:              c,
		ExternalCmdPool:     c.externalCmdPool,
		RunOnConnect:        c.runOnConnect,
		RunOnConnectRestart: c.runOnConnectRestart,
		RunOnDisconnect:     c.runOnDisconnect,
		RTSPAddress:         c.rtspAddress,
		Desc:                *c.APIReaderDescribe(),
	})
	defer onDisconnectHook()

	err := c.runInner()

	c.ctxCancel()

	c.parent.closeConn(c)

	c.Log(logger.Info, "closed: %v", err)
}

func (c *conn) runInner() error {
	readerErr := make(chan error)
	go func() {
		readerErr <- c.runReader()
	}()

	select {
	case err := <-readerErr:
		c.nconn.Close()
		return err

	case <-c.ctx.Done():
		c.nconn.Close()
		<-readerErr
		return errors.New("terminated")
	}
}

func (c *conn) runReader() error {
	c.nconn.SetReadDeadline(time.Now().Add(time.Duration(c.readTimeout)))
	c.nconn.SetWriteDeadline(time.Now().Add(time.Duration(c.writeTimeout)))

	conn := &gortmplib.ServerConn{
		RW: c.nconn,
	}
	err := conn.Initialize()
	if err != nil {
		return err
	}

	err = conn.Accept()
	if err != nil {
		return err
	}

	c.mutex.Lock()
	c.rconn = conn
	c.userAgent = conn.FlashVer
	c.mutex.Unlock()

	if !conn.Publish {
		return c.runRead()
	}
	return c.runPublish()
}

func (c *conn) runRead() error {
	pathName := strings.TrimLeft(c.rconn.URL.Path, "/")
	query := c.rconn.URL.Query()
	rawQuery := c.rconn.URL.RawQuery
	queryUser := query.Get("user")
	queryPass := query.Get("pass")

	// ADR-019-003/004 read-side hardening (see parsePublishAccess): Stream Keys are
	// publish-only credentials, so a key — or a truncated key — pasted into a play URL
	// (e.g. a publisher's push URL pointed at a player) must never become a path name or
	// query that reaches routing, logs, API, metrics, hooks or external auth. Fail closed
	// with the same token-free sentinel the publish side uses (rejected by path-name
	// validation before authentication). Disabled deployments are byte-for-byte stock.
	if c.streamKeyApp != "" && conf.StreamKeyBearsKeyMaterial(pathName, rawQuery) {
		pathName = c.streamKeyApp + "/"
		rawQuery = ""
		queryUser = ""
		queryPass = ""
	}

	res, err := c.pathManager.AddReader(defs.PathAddReaderReq{
		Author: c,
		AccessRequest: defs.PathAccessRequest{
			Name:      pathName,
			Query:     rawQuery,
			UserAgent: c.userAgent,
			Proto:     auth.ProtocolRTMP,
			ID:        &c.uuid,
			Credentials: &auth.Credentials{
				User: queryUser,
				Pass: queryPass,
			},
			IP:                   c.ip(),
			EnableAskCredentials: false,
		},
	})
	if err != nil {
		return err
	}

	defer res.Path.RemoveReader(defs.PathRemoveReaderReq{Author: c})

	c.mutex.Lock()
	c.state = defs.APIRTMPConnStateRead
	c.pathName = pathName
	c.query = rawQuery
	c.user = res.User
	c.mutex.Unlock()

	r := &stream.Reader{Parent: c}

	err = rtmp.FromStream(
		res.Stream.OrigDesc,
		res.Stream.OutDescCopy(),
		r,
		c.rconn,
		c.nconn,
		time.Duration(c.writeTimeout),
		c.rconn.FourCcList)
	if err != nil {
		return err
	}

	c.Log(logger.Info, "is reading from path '%s', %s",
		res.Path.Name(), defs.FormatsInfo(r.Formats()))

	onUnreadHook := hooks.OnRead(hooks.OnReadParams{
		Logger:          c,
		ExternalCmdPool: c.externalCmdPool,
		Conf:            res.Path.SafeConf(),
		ExternalCmdEnv:  res.Path.ExternalCmdEnv(),
		Reader:          *c.APIReaderDescribe(),
		Query:           rawQuery,
	})
	defer onUnreadHook()

	c.nconn.SetReadDeadline(time.Time{})

	res.Stream.AddReader(r)
	defer res.Stream.RemoveReader(r)

	c.mutex.Lock()
	c.reader = r
	c.mutex.Unlock()

	select {
	case <-c.ctx.Done():
		return fmt.Errorf("terminated")

	case err = <-r.Error():
		return err
	}
}

// v1 packed Stream-Key layout constants and the key-material shape detector are
// single-sourced in internal/conf (ADR-019-004 invariant (d)); they live there so that
// Conf.Validate rejects a key-shaped rtmpStreamKeyApp with the exact predicate the
// servers enforce at runtime. Aliased here to keep the decode logic readable.
const (
	streamKeyVersion    = conf.StreamKeyVersion
	streamKeyVersionLen = conf.StreamKeyVersionLen
	streamKeyIDLen      = conf.StreamKeyIDLen
	streamKeyDecodedLen = conf.StreamKeyDecodedLen
	streamKeyEncodedLen = conf.StreamKeyEncodedLen
)

// parsePublishAccess ADDS the ADR-019-003/004 RTMP packed Stream-Key auth for PUBLISH.
// It is OPT-IN and OFF by default: the behaviour is active only when streamKeyApp (the
// rtmpStreamKeyApp config option) is non-empty. When disabled (the default, and the case
// for every MediaMTX deployment that does not need this feature — e.g. CameraHost), this
// function is a no-op pass-through and the server keeps its stock auth verbatim.
//
// When enabled, a publish to <streamKeyApp>/<streamKey> (the standard two-segment
// Server-URL + opaque-Stream-Key shape) is decoded per ADR-019-004: the single Stream-Key
// segment is base64url-nopad( version(0x01) || liveStreamId(16B) || token(16B) ). The fork
// decodes it, byte-splits it, reconstructs the canonical lowercase hyphenated UUID from the
// 16 id bytes, and rewrites the canonical path MediaMTX keys on to <streamKeyApp>/<uuid>
// (the token never reaches any routing/telemetry surface). Credentials are populated with
// User=<uuid> and Pass=base64url-nopad(token bytes) — the same string Core hashed at mint
// (ADR-019-003 §"Hashing": the stored hash is over utf8(base64url token)) — and validated
// by the existing internal-auth Pass.Check.
//
// A malformed Stream Key under the enabled app (wrong length, non-base64url char, wrong
// version byte, or wrong decoded length), or any non-two-segment path under that app,
// FAILS CLOSED: the canonical path is rewritten to the bare app prefix (no secret-bearing
// bytes reach telemetry) and credentials are empty, so it cannot authenticate. A well-formed
// key with a wrong/revoked token decodes normally and is rejected by the auth gate
// (auth-denied), preserving an indistinguishable rejection surface for credential failures.
//
// gortmplib v1.0.0 (the v1.20.0 base) changed URL assembly: ServerConn.URL is now the
// client-controlled tcURL joined with the Stream Key argument of the client's publish (or,
// for reads, play) command, and the RTMP connect command's app field is parsed but
// unexported — the server can no longer see which app the client addressed. Two
// consequences are handled here:
//
//   - A client that sends the app only in the connect command (tcURL without a path — legal
//     RTMP, and exactly what gortmplib v0.4.0 used to normalise to "<app>/<key>") now yields
//     a bare single-segment "<key>" path. When enabled, a single segment of the exact packed
//     length that DECODES as a valid v1 Stream Key is therefore accepted as a Stream-Key
//     publish under the enabled app. This is sound without seeing the connect app: the key
//     itself fully determines the canonical path and the credentials, and the auth gate
//     still requires the token hash to match live/<uuid>'s provisioned user.
//   - Fail-closed hardening: when enabled, no path or query bearing Stream-Key material
//     (see conf.StreamKeyBearsKeyMaterial / conf.StreamKeySegmentShaped for the flagged
//     shapes — near-packed-length band, v1-prefix decodes, embedded key windows, and
//     delimiter-split reconstruction) is ever used as part of a raw path name — any such
//     path is rejected as "<streamKeyApp>/" (uniform, secret-free) instead of flowing to
//     routing, logs, API, metrics or hooks. This keeps the ADR-019-003
//     token-never-in-telemetry invariant for corrupted keys, keys addressed to the wrong
//     app, and the other URL shapes gortmplib v1.0.0 can produce from a hostile or
//     misconfigured tcURL. Deliberate consequences (strict app
//     binding): a valid key under a DIFFERENT app fails closed instead of publishing
//     vanilla (pre-v1.20.0 it published vanilla, leaking the key as a path name), and the
//     fail-closed sentinel always names the CONFIGURED app even when the client addressed
//     another one.
//
// Known fail-closed (not restored) client shape: a tcURL that itself carries a query
// ("rtmp://host/live?x=1") makes gortmplib v1.0.0 swallow the Stream Key into RawQuery
// (Path stays "/live"), so such publishes are rejected; DeskPeer-issued push URLs carry
// no query. Every other path — one neither under the enabled app nor carrying
// Stream-Key material — keeps MediaMTX's existing behaviour unchanged (raw path name +
// query-string user/pass). A disabled deployment (streamKeyApp == "") is byte-identical
// to stock in all cases.
func parsePublishAccess(streamKeyApp, rawPath, queryUser, queryPass string) (canonical string, creds auth.Credentials) {
	if streamKeyApp != "" {
		segments := strings.Split(rawPath, "/")
		if segments[0] == streamKeyApp {
			if len(segments) == 2 {
				if id, token, ok := decodeStreamKey(segments[1]); ok {
					return streamKeyApp + "/" + id, auth.Credentials{User: id, Pass: token}
				}
			}
			// Anything under the enabled app that is not a valid packed Stream Key fails
			// closed, with any secret-bearing bytes stripped from the canonical path.
			return streamKeyApp + "/", auth.Credentials{}
		}

		// gortmplib v1.0.0: app carried only in the connect command (unexported there), so
		// the URL path is the bare Stream Key. A valid key is accepted under the enabled
		// app; a key-shaped segment that does not decode fails closed below.
		if len(segments) == 1 && len(segments[0]) == streamKeyEncodedLen {
			if id, token, ok := decodeStreamKey(segments[0]); ok {
				return streamKeyApp + "/" + id, auth.Credentials{User: id, Pass: token}
			}
		}

		// Fail-closed hardening: a path bearing Stream-Key material — a whole key, a
		// truncated/mangled key, or a key split across segments by an inserted '/' — must
		// never become a raw path name (it may be, or contain most of, a live token). The
		// path/query-boundary split is caught at the runPublish level, which has the query.
		if conf.StreamKeyBearsKeyMaterial(rawPath, "") {
			return streamKeyApp + "/", auth.Credentials{}
		}
	}

	return rawPath, auth.Credentials{User: queryUser, Pass: queryPass}
}

// Key-material detection (conf.StreamKeySegmentShaped and friends) is single-sourced in
// internal/conf/streamkey.go — see its doc comments for the flagged shapes, the accepted
// detection boundary, and the documented false-positive class on enabled servers.

// decodeStreamKey decodes a v1 packed Stream Key (ADR-019-004) into the canonical
// lowercase hyphenated liveStreamId and the base64url-nopad token string used for
// Pass.Check. It fails closed (ok=false) on any length / charset / version / shape
// violation, before any hash compare.
func decodeStreamKey(key string) (id string, token string, ok bool) {
	// Stage 1 (pre-decode): exact v1 char count; the base64url alphabet (and the
	// rejection of any '=' padding or out-of-alphabet char) is enforced by the decoder.
	// The len(key)==44 gate plus the post-decode len(raw)==33 recheck also neutralise
	// base64's CR/LF skip (an embedded newline yields <44 significant chars -> not 33
	// decoded bytes -> reject), so no malleable encoding survives.
	if len(key) != streamKeyEncodedLen {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(raw) != streamKeyDecodedLen || raw[0] != streamKeyVersion {
		return "", "", false
	}
	// Stage 2 (post-decode): fixed byte-split (offsets single-sourced from the v1 layout
	// constants), no scanning, no delimiter.
	const idEnd = streamKeyVersionLen + streamKeyIDLen // 17
	u, err := uuid.FromBytes(raw[streamKeyVersionLen:idEnd])
	if err != nil {
		return "", "", false
	}
	// Re-encode the 16 token bytes to the 22-char base64url-nopad string Core hashed
	// (ADR-019-004 §"Token representation chain") -- NOT the raw bytes.
	return u.String(), base64.RawURLEncoding.EncodeToString(raw[idEnd:streamKeyDecodedLen]), true
}

func (c *conn) runPublish() error {
	pathName := strings.TrimLeft(c.rconn.URL.Path, "/")
	query := c.rconn.URL.Query()
	rawQuery := c.rconn.URL.RawQuery

	canonicalName, creds := parsePublishAccess(c.streamKeyApp, pathName, query.Get("user"), query.Get("pass"))

	if c.streamKeyApp != "" {
		sentinel := c.streamKeyApp + "/"
		// parsePublishAccess is path-only. If it passed the path through verbatim (vanilla,
		// no key material in the path alone), the query can still carry key material —
		// swallowed there by gortmplib v1.0.0 when the tcURL has a query, or a key split
		// across the path/query boundary by an inserted '?'. Re-check the path AND query
		// together and fail closed if either, or their delimiter-stripped reconstruction,
		// bears key material.
		vanilla := canonicalName == pathName && canonicalName != sentinel
		if vanilla && conf.StreamKeyBearsKeyMaterial(pathName, rawQuery) {
			canonicalName, creds = sentinel, auth.Credentials{}
		}
		// Whenever the stream-key feature produced the canonical name (accepted key -> uuid,
		// or fail-closed sentinel), the query is not a credential carrier for this publish:
		// strip it so nothing secret-adjacent reaches external auth, hooks or telemetry
		// through the Query field. The sentinel is tested explicitly — the raw path can
		// itself be "<app>/" (empty publish stream key), making the names equal even though
		// the fail-closed branch handled it. Vanilla pass-through publishes keep the query.
		if canonicalName != pathName || canonicalName == sentinel {
			rawQuery = ""
		}
	}

	r := &gortmplib.Reader{
		Conn: c.rconn,
	}
	err := r.Initialize()
	if err != nil {
		return err
	}

	var subStream *stream.SubStream

	medias, err := rtmp.ToStream(r, &subStream)
	if err != nil {
		return err
	}

	res, err := c.pathManager.AddPublisher(defs.PathAddPublisherReq{
		Author:        c,
		Desc:          &description.Session{Medias: medias},
		UseRTPPackets: false,
		ReplaceNTP:    true,
		AccessRequest: defs.PathAccessRequest{
			Name:                 canonicalName,
			Query:                rawQuery,
			Publish:              true,
			UserAgent:            c.userAgent,
			Proto:                auth.ProtocolRTMP,
			ID:                   &c.uuid,
			Credentials:          &creds,
			IP:                   c.ip(),
			EnableAskCredentials: false,
		},
	})
	if err != nil {
		return err
	}

	defer res.Path.RemovePublisher(defs.PathRemovePublisherReq{Author: c})

	subStream = res.SubStream

	c.mutex.Lock()
	c.state = defs.APIRTMPConnStatePublish
	c.pathName = canonicalName
	c.query = rawQuery
	c.user = res.User
	c.mutex.Unlock()

	c.nconn.SetWriteDeadline(time.Time{})

	for {
		c.nconn.SetReadDeadline(time.Now().Add(time.Duration(c.readTimeout)))
		err = r.Read()
		if err != nil {
			return err
		}
	}
}

// APIReaderDescribe implements reader.
func (c *conn) APIReaderDescribe() *defs.APIPathReader {
	return &defs.APIPathReader{
		Type: func() defs.APIPathReaderType {
			if c.encryption {
				return defs.APIPathReaderTypeRTMPSConn
			}
			return defs.APIPathReaderTypeRTMPConn
		}(),
		ID: c.uuid.String(),
	}
}

// APISourceDescribe implements source.
func (c *conn) APISourceDescribe() *defs.APIPathSource {
	return &defs.APIPathSource{
		Type: func() defs.APIPathSourceType {
			if c.encryption {
				return defs.APIPathSourceTypeRTMPSConn
			}
			return defs.APIPathSourceTypeRTMPConn
		}(),
		ID: c.uuid.String(),
	}
}

func (c *conn) apiItem() *defs.APIRTMPConn {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	bytesReceived := uint64(0)
	bytesSent := uint64(0)
	outboundFramesDiscarded := uint64(0)

	if c.rconn != nil {
		bytesReceived = c.rconn.BytesReceived()
		bytesSent = c.rconn.BytesSent()
	}

	if c.reader != nil {
		outboundFramesDiscarded = c.reader.OutboundFramesDiscarded()
	}

	return &defs.APIRTMPConn{
		ID:                      c.uuid,
		Created:                 c.created,
		RemoteAddr:              c.remoteAddr().String(),
		State:                   c.state,
		Path:                    c.pathName,
		Query:                   c.query,
		User:                    c.user,
		UserAgent:               c.userAgent,
		InboundBytes:            bytesReceived,
		OutboundBytes:           bytesSent,
		BytesReceived:           bytesReceived,
		BytesSent:               bytesSent,
		OutboundFramesDiscarded: outboundFramesDiscarded,
	}
}
