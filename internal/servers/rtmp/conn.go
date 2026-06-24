package rtmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bluenviron/gortmplib"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/externalcmd"
	"github.com/bluenviron/mediamtx/internal/hooks"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/protocols/rtmp"
	"github.com/bluenviron/mediamtx/internal/stream"
)

// rtmpCredentialApp is the fixed publisher-facing RTMP app under which a publish
// credential is carried as a trailing path segment (ADR-019-003). A publish URL of
// the form rtmp(s)://host/live/<liveStreamId>/<token> is authenticated by internal
// auth and the <token> segment is stripped to the canonical path live/<liveStreamId>
// before routing, the paths map, the API, metrics, external commands and logs see it.
const rtmpCredentialApp = "live"

type conn struct {
	parentCtx           context.Context
	encryption          bool
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
	expiresAt *time.Time
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
	errGroup, errGroupCtx := errgroup.WithContext(context.Background())

	errGroup.Go(func() error {
		select {
		case <-c.ctx.Done():
			return fmt.Errorf("terminated")
		case <-errGroupCtx.Done():
			return fmt.Errorf("terminated")
		}
	})

	errGroup.Go(func() error {
		<-errGroupCtx.Done()
		c.nconn.Close()
		return errors.New("terminated")
	})

	errGroup.Go(func() error {
		return c.runReader(errGroupCtx, errGroup)
	})

	return errGroup.Wait()
}

func (c *conn) runReader(errGroupCtx context.Context, errGroup *errgroup.Group) error {
	c.nconn.SetReadDeadline(time.Now().Add(time.Duration(c.readTimeout)))
	c.nconn.SetWriteDeadline(time.Now().Add(time.Duration(c.writeTimeout)))

	conn := &gortmplib.ServerConn{
		RW: c.nconn,
	}
	err := conn.Initialize()
	if err != nil {
		return err
	}

	err = conn.AcceptConn()
	if err != nil {
		return err
	}

	c.mutex.Lock()
	c.rconn = conn
	c.userAgent = conn.FlashVer
	c.mutex.Unlock()

	if !conn.Publish {
		return c.runRead(errGroupCtx, errGroup)
	}
	return c.runPublish(errGroupCtx, errGroup)
}

func (c *conn) runRead(errGroupCtx context.Context, errGroup *errgroup.Group) error {
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
		if _, ok := errors.AsType[*auth.Error](err); ok {
			rejectErr := c.rconn.RejectAction()
			if rejectErr != nil {
				return rejectErr
			}
		}

		return err
	}

	defer res.Path.RemoveReader(defs.PathRemoveReaderReq{Author: c})

	if res.AuthRes.ExpiresAt != nil {
		errGroup.Go(func() error {
			select {
			case <-time.After(time.Until(*res.AuthRes.ExpiresAt)):
				return errors.New("connection expired")
			case <-errGroupCtx.Done():
				return fmt.Errorf("terminated")
			}
		})
	}

	err = c.rconn.AcceptAction()
	if err != nil {
		return err
	}

	c.mutex.Lock()
	c.state = defs.APIRTMPConnStateRead
	c.pathName = pathName
	c.query = c.rconn.URL.RawQuery
	c.user = res.AuthRes.User
	c.expiresAt = res.AuthRes.ExpiresAt
	c.mutex.Unlock()

	r := &stream.Reader{Parent: c}

	w, err := rtmp.FromStream(
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

	errGroup.Go(func() error {
		return w.Wait()
	})

	select {
	case err = <-r.Error():
		return err
	case <-errGroupCtx.Done():
		return fmt.Errorf("terminated")
	}
}

// parsePublishAccess ADDS ADR-019-003 RTMP stream-key path-segment auth for PUBLISH,
// without removing any of MediaMTX's existing auth. When the client path is exactly
// live/<liveStreamId>/<token> (3 segments under the "live" app), the trailing <token>
// segment is consumed as the publish credential: the canonical path MediaMTX keys on
// becomes live/<liveStreamId> (token stripped from every routing/telemetry surface),
// and Credentials are populated with User=<liveStreamId>, Pass=<token>, validated by the
// existing internal-auth Pass.Check. An empty <liveStreamId> or empty <token> still
// takes this branch and fails closed at auth (no permission match / empty-hash mismatch).
//
// Every other path shape — non-"live" apps, the bare live/<liveStreamId> identity path,
// and deeper live/a/b/c paths — keeps MediaMTX's existing behaviour unchanged: the raw
// path name plus query-string (user/pass) credentials. This is purely additive; the
// query carriage and normal path auth are NOT removed (whether a deployment uses only
// the stream-key form is a config decision, enforced by the minted publish permission).
func parsePublishAccess(rawPath, queryUser, queryPass string) (canonical string, creds auth.Credentials) {
	segments := strings.Split(rawPath, "/")

	if len(segments) == 3 && segments[0] == rtmpCredentialApp {
		return rtmpCredentialApp + "/" + segments[1],
			auth.Credentials{User: segments[1], Pass: segments[2]}
	}

	return rawPath, auth.Credentials{User: queryUser, Pass: queryPass}
}

func (c *conn) runPublish(errGroupCtx context.Context, errGroup *errgroup.Group) error {
	pathName := strings.TrimLeft(c.rconn.URL.Path, "/")
	query := c.rconn.URL.Query()

	canonicalName, creds := parsePublishAccess(pathName, query.Get("user"), query.Get("pass"))

	res1, err := c.pathManager.FindPathConf(defs.PathFindPathConfReq{
		Author: c,
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
		if _, ok := errors.AsType[*auth.Error](err); ok {
			rejectErr := c.rconn.RejectAction()
			if rejectErr != nil {
				return rejectErr
			}
		}

		return err
	}

	if res1.AuthRes.ExpiresAt != nil {
		errGroup.Go(func() error {
			select {
			case <-time.After(time.Until(*res1.AuthRes.ExpiresAt)):
				return errors.New("connection expired")
			case <-errGroupCtx.Done():
				return fmt.Errorf("terminated")
			}
		})
	}

	err = c.rconn.AcceptAction()
	if err != nil {
		return err
	}

	r := &gortmplib.Reader{
		Conn: c.rconn,
	}
	err = r.Initialize()
	if err != nil {
		return err
	}

	var subStream *stream.SubStream

	medias, err := rtmp.ToStream(r, &subStream)
	if err != nil {
		return err
	}

	res2, err := c.pathManager.AddPublisher(defs.PathAddPublisherReq{
		Author:        c,
		Desc:          &description.Session{Medias: medias},
		UseRTPPackets: false,
		ReplaceNTP:    true,
		ConfToCompare: res1.Conf,
		AccessRequest: defs.PathAccessRequest{
			Name:     canonicalName,
			Query:    c.rconn.URL.RawQuery,
			Publish:  true,
			SkipAuth: true,
		},
	})
	if err != nil {
		return err
	}

	defer res2.Path.RemovePublisher(defs.PathRemovePublisherReq{Author: c})

	subStream = res2.SubStream

	c.mutex.Lock()
	c.state = defs.APIRTMPConnStatePublish
	c.pathName = canonicalName
	c.query = c.rconn.URL.RawQuery
	c.user = res1.AuthRes.User
	c.expiresAt = res1.AuthRes.ExpiresAt
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
		ExpiresAt:               c.expiresAt,
		UserAgent:               c.userAgent,
		InboundBytes:            bytesReceived,
		OutboundBytes:           bytesSent,
		BytesReceived:           bytesReceived,
		BytesSent:               bytesSent,
		OutboundFramesDiscarded: outboundFramesDiscarded,
	}
}
