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

	res, err := c.pathManager.AddReader(defs.PathAddReaderReq{
		Author: c,
		AccessRequest: defs.PathAccessRequest{
			Name:      pathName,
			Query:     c.rconn.URL.RawQuery,
			UserAgent: c.userAgent,
			Proto:     auth.ProtocolRTMP,
			ID:        &c.uuid,
			Credentials: &auth.Credentials{
				User: query.Get("user"),
				Pass: query.Get("pass"),
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
	c.query = c.rconn.URL.RawQuery
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
		Query:           c.rconn.URL.RawQuery,
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

// v1 packed Stream Key (ADR-019-004): base64url-nopad( version(1B) || liveStreamId(16B)
// || token(16B) ). 33 decoded bytes -> exactly 44 base64url chars, all in [A-Za-z0-9_-].
// The 16/16 byte layout is single-sourced here (ADR-019-004 invariant (d)): a wrong
// literal offset would silently mis-split id/token, so the offsets derive from these.
const (
	streamKeyVersion    = 0x01                                                     // v1 layout discriminator (fail-closed)
	streamKeyVersionLen = 1                                                        // version byte
	streamKeyIDLen      = 16                                                       // liveStreamId (raw UUID) bytes
	streamKeyTokenLen   = 16                                                       // 128-bit token bytes
	streamKeyDecodedLen = streamKeyVersionLen + streamKeyIDLen + streamKeyTokenLen // 33
	streamKeyEncodedLen = 44                                                       // base64url-nopad(33 bytes), no '='
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
// Every path NOT under the enabled app keeps MediaMTX's existing behaviour unchanged (raw
// path name + query-string user/pass), so a disabled deployment is byte-identical to stock.
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
	}

	return rawPath, auth.Credentials{User: queryUser, Pass: queryPass}
}

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

	canonicalName, creds := parsePublishAccess(c.streamKeyApp, pathName, query.Get("user"), query.Get("pass"))

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
			Query:                c.rconn.URL.RawQuery,
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
	c.query = c.rconn.URL.RawQuery
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
