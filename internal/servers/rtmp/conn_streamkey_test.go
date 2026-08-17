package rtmp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bluenviron/gortmplib"
	"github.com/bluenviron/gortmplib/pkg/codecs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/stream"
	"github.com/bluenviron/mediamtx/internal/test"
)

// packKey builds a packed Stream Key (ADR-019-004): base64url-nopad( ver || id(16) || tok(16) ).
func packKey(ver byte, idStr string, tok []byte) string {
	u := uuid.MustParse(idStr)
	raw := make([]byte, 0, 33)
	raw = append(raw, ver)
	raw = append(raw, u[:]...)
	raw = append(raw, tok...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// TestParsePublishAccess covers the ADR-019-003/004 RTMP packed Stream-Key auth for PUBLISH.
// The behaviour is OPT-IN via rtmpStreamKeyApp (the streamKeyApp argument): empty = disabled
// (stock MediaMTX, the default for CameraHost and any other shared consumer), non-empty = the
// app under which live/<44-char-packed-key> carries an encoded id+token.
func TestParsePublishAccess(t *testing.T) {
	const app = "live"
	idStr := "12345678-1234-5678-1234-567812345678"
	tok := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	wantPass := base64.RawURLEncoding.EncodeToString(tok)
	goodKey := packKey(streamKeyVersion, idStr, tok)
	if len(goodKey) != streamKeyEncodedLen {
		t.Fatalf("test key is %d chars, want %d", len(goodKey), streamKeyEncodedLen)
	}

	// A second, distinct minted key — the User/Pass must track THIS key's own id+token,
	// so a key for one liveStreamId can never present another's id (the per-path binding
	// the cross-path-reuse rejection rests on, ADR-019-003 route (i)).
	idStr2 := "abcdef01-2345-6789-abcd-ef0123456789"
	tok2 := []byte{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	goodKey2 := packKey(streamKeyVersion, idStr2, tok2)
	wantPass2 := base64.RawURLEncoding.EncodeToString(tok2)

	for _, ca := range []struct {
		name          string
		streamKeyApp  string
		rawPath       string
		queryUser     string
		queryPass     string
		wantCanonical string
		wantUser      string
		wantPass      string
	}{
		// ---- ENABLED (rtmpStreamKeyApp = "live") ----
		{
			name:          "enabled: valid packed key -> canonical uuid + decoded token",
			streamKeyApp:  app,
			rawPath:       app + "/" + goodKey,
			wantCanonical: app + "/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
		},
		{
			name:          "enabled: User/Pass bind to the key's own id+token (per-path binding)",
			streamKeyApp:  app,
			rawPath:       app + "/" + goodKey2,
			wantCanonical: app + "/" + idStr2,
			wantUser:      idStr2,
			wantPass:      wantPass2,
		},
		{
			name:          "enabled: packed key ignores query credentials",
			streamKeyApp:  app,
			rawPath:       app + "/" + goodKey,
			queryUser:     "attacker",
			queryPass:     "querytoken",
			wantCanonical: app + "/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
		},
		{
			name:          "enabled: wrong-length key fails closed (token-free)",
			streamKeyApp:  app,
			rawPath:       app + "/" + goodKey[:streamKeyEncodedLen-1],
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: non-base64url char fails closed",
			streamKeyApp:  app,
			rawPath:       app + "/" + goodKey[:streamKeyEncodedLen-1] + "+", // '+' is not in the URL alphabet
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: wrong version byte fails closed",
			streamKeyApp:  app,
			rawPath:       app + "/" + packKey(0x02, idStr, tok),
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: bare app (1 segment) fails closed",
			streamKeyApp:  app,
			rawPath:       app,
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: legacy 3-segment form under app fails closed (no token leak)",
			streamKeyApp:  app,
			rawPath:       app + "/" + idStr + "/sometoken",
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: valid key under a different app fails closed (strict app binding)",
			streamKeyApp:  app,
			rawPath:       "other/" + goodKey,
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: a different app without key-length segments is vanilla (stock)",
			streamKeyApp:  app,
			rawPath:       "other/mystream",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "other/mystream",
			wantUser:      "u",
			wantPass:      "p",
		},

		// ---- gortmplib v1.0.0 URL assembly (tcURL authoritative, connect app unexported) ----
		{
			name:          "enabled: bare single-segment valid key -> accepted under the enabled app",
			streamKeyApp:  app,
			rawPath:       goodKey,
			wantCanonical: app + "/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
		},
		{
			name:          "enabled: bare single-segment key ignores query credentials",
			streamKeyApp:  app,
			rawPath:       goodKey,
			queryUser:     "attacker",
			queryPass:     "querytoken",
			wantCanonical: app + "/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
		},
		{
			name:          "enabled: bare key with wrong version byte fails closed",
			streamKeyApp:  app,
			rawPath:       packKey(0x02, idStr, tok),
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: bare key-length segment with bad charset fails closed",
			streamKeyApp:  app,
			rawPath:       goodKey[:streamKeyEncodedLen-1] + "+",
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: key-length middle segment fails closed (no token prefix leak)",
			streamKeyApp:  app,
			rawPath:       goodKey + "/x",
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: 3-segment path ending in key-length segment fails closed",
			streamKeyApp:  app,
			rawPath:       "a/b/" + goodKey,
			wantCanonical: app + "/",
		},
		{
			// A 43-char prefix of a real key still decodes to the full id + 15 of the 16
			// token bytes — it must never become a raw path name.
			name:          "enabled: bare truncated key (43 chars, decodes to v1 prefix) fails closed",
			streamKeyApp:  app,
			rawPath:       goodKey[:streamKeyEncodedLen-1],
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: truncated key under a different app fails closed",
			streamKeyApp:  app,
			rawPath:       "other/" + goodKey[:streamKeyEncodedLen-1],
			wantCanonical: app + "/",
		},
		{
			name:          "enabled: empty raw path is vanilla (rejected downstream by path validation)",
			streamKeyApp:  app,
			rawPath:       "",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "",
			wantUser:      "u",
			wantPass:      "p",
		},

		// ---- configurable app name ----
		{
			name:          "configurable app: fires for the configured app",
			streamKeyApp:  "ingest",
			rawPath:       "ingest/" + goodKey,
			wantCanonical: "ingest/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
		},
		{
			name:          "configurable app: key under a different app fails closed to the configured app",
			streamKeyApp:  "ingest",
			rawPath:       app + "/" + goodKey,
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "ingest/",
		},

		// ---- DISABLED (rtmpStreamKeyApp = "", the default) -> byte-identical to stock ----
		{
			name:          "disabled: packed-key path is a vanilla path, no decode",
			streamKeyApp:  "",
			rawPath:       app + "/" + goodKey,
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: app + "/" + goodKey, // raw path preserved verbatim
			wantUser:      "u",
			wantPass:      "p",
		},
		{
			name:          "disabled: ordinary path keeps query creds",
			streamKeyApp:  "",
			rawPath:       "mystream",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "mystream",
			wantUser:      "u",
			wantPass:      "p",
		},
		{
			name:          "disabled: bare single-segment key is a vanilla path, no decode (stock)",
			streamKeyApp:  "",
			rawPath:       goodKey,
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: goodKey,
			wantUser:      "u",
			wantPass:      "p",
		},
	} {
		t.Run(ca.name, func(t *testing.T) {
			canonical, creds := parsePublishAccess(ca.streamKeyApp, ca.rawPath, ca.queryUser, ca.queryPass)
			if canonical != ca.wantCanonical {
				t.Errorf("canonical = %q, want %q", canonical, ca.wantCanonical)
			}
			if creds.User != ca.wantUser {
				t.Errorf("User = %q, want %q", creds.User, ca.wantUser)
			}
			if creds.Pass != ca.wantPass {
				t.Errorf("Pass = %q, want %q", creds.Pass, ca.wantPass)
			}
		})
	}
}

// joinURLv1 is a FROZEN local replica of gortmplib v1.0.0's joinURL (server_conn.go):
// ServerConn.URL is the client-controlled tcURL joined with the publish/play-command
// Stream Key; the connect command's app field is NOT used. Because this is a replica, the
// suite pins the FORK's handling of the URL shapes v1.0.0 produces — it can NOT detect a
// future gortmplib assembly change by itself. Any gortmplib version bump MUST re-diff the
// library's joinURL/buildURL against this replica (TestServerStreamKeyPublish below drives
// the real library end-to-end for the shapes a real client can produce, which partially
// covers that gap).
func joinURLv1(tcURL string, streamKey string) (*url.URL, error) {
	if streamKey != "" && streamKey[0] != '?' {
		tcURL += "/" + streamKey
	}
	return url.Parse(tcURL)
}

// TestParsePublishAccessURLAssembly drives the exact pipeline runPublish uses
// (ServerConn.URL -> TrimLeft(Path, "/") -> parsePublishAccess) with URLs assembled the way
// gortmplib v1.0.0 assembles them, for every tcURL shape a client can legally produce.
func TestParsePublishAccessURLAssembly(t *testing.T) {
	const app = "live"
	idStr := "12345678-1234-5678-1234-567812345678"
	tok := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	goodKey := packKey(streamKeyVersion, idStr, tok)
	wantPass := base64.RawURLEncoding.EncodeToString(tok)

	for _, ca := range []struct {
		name          string
		tcURL         string
		streamKey     string
		wantCanonical string
		wantUser      string
		wantPass      string
	}{
		{
			// The shape gortmplib v0.4.0 used to normalise via the connect-command app and
			// v1.0.0 no longer does: tcURL without a path, app only in the connect command.
			name:          "path-less tcURL, app in connect command only -> accepted",
			tcURL:         "rtmp://host:1935",
			streamKey:     goodKey,
			wantCanonical: app + "/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
		},
		{
			name:          "tcURL carries the app (OBS/FFmpeg/GStreamer shape) -> accepted",
			tcURL:         "rtmp://host:1935/" + app,
			streamKey:     goodKey,
			wantCanonical: app + "/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
		},
		{
			// v1.0.0 joins "rtmp://host/live?x=1" + "/<key>" so the key lands in RawQuery
			// and Path stays "/live": fail closed, token stays out of the path name.
			name:          "tcURL with query swallows the key into RawQuery -> fails closed",
			tcURL:         "rtmp://host:1935/" + app + "?x=1",
			streamKey:     goodKey,
			wantCanonical: app + "/",
		},
		{
			name:          "tcURL with trailing slash yields empty middle segment -> fails closed",
			tcURL:         "rtmp://host:1935/" + app + "/",
			streamKey:     goodKey,
			wantCanonical: app + "/",
		},
		{
			// Whole publish URL stuffed into tcURL, empty Stream Key (OBS with empty key).
			name:          "app and key both in tcURL, empty stream key -> accepted",
			tcURL:         "rtmp://host:1935/" + app + "/" + goodKey,
			streamKey:     "",
			wantCanonical: app + "/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
		},
		{
			// Hostile shape: key smuggled as the tcURL path with a decoy Stream Key.
			name:          "key as tcURL path plus decoy stream key -> fails closed",
			tcURL:         "rtmp://host:1935/" + goodKey,
			streamKey:     "x",
			wantCanonical: app + "/",
		},
		{
			// gortmplib v1.0.0 drops a '?'-prefixed Stream Key entirely (URL = tcURL
			// verbatim), leaving the bare app: fail closed.
			name:          "query-only stream key is dropped by joinURL -> fails closed",
			tcURL:         "rtmp://host:1935/" + app,
			streamKey:     "?user=u&pass=p",
			wantCanonical: app + "/",
		},
		{
			// Path-less tcURL and no Stream Key at all: empty path, vanilla pass-through,
			// rejected downstream by path-name validation ("cannot be empty").
			name:          "path-less tcURL with empty stream key -> empty vanilla path",
			tcURL:         "rtmp://host:1935",
			streamKey:     "",
			wantCanonical: "",
		},
	} {
		t.Run(ca.name, func(t *testing.T) {
			u, err := joinURLv1(ca.tcURL, ca.streamKey)
			if err != nil {
				t.Fatalf("joinURLv1: %v", err)
			}
			pathName := strings.TrimLeft(u.Path, "/")
			query := u.Query()
			canonical, creds := parsePublishAccess(app, pathName, query.Get("user"), query.Get("pass"))
			if canonical != ca.wantCanonical {
				t.Errorf("canonical = %q, want %q", canonical, ca.wantCanonical)
			}
			if creds.User != ca.wantUser {
				t.Errorf("User = %q, want %q", creds.User, ca.wantUser)
			}
			if creds.Pass != ca.wantPass {
				t.Errorf("Pass = %q, want %q", creds.Pass, ca.wantPass)
			}
		})
	}
}

// TestKeyMaterialDetection pins the fail-closed detection helpers used by both the
// publish gate and the read-side hardening (single-sourced in internal/conf).
func TestKeyMaterialDetection(t *testing.T) {
	idStr := "12345678-1234-5678-1234-567812345678"
	tok := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	goodKey := packKey(streamKeyVersion, idStr, tok)

	// The near-packed-length band is always key material, decodable or not: it covers
	// single/few-char insertion, deletion and substitution mangles.
	require.True(t, conf.StreamKeySegmentShaped(goodKey))
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:streamKeyEncodedLen-1]+"+"))
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:43]))
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:41]))
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:40]))
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:40]+"."))
	require.True(t, conf.StreamKeySegmentShaped(goodKey+"A"))
	require.True(t, conf.StreamKeySegmentShaped(goodKey+"."))
	require.True(t, conf.StreamKeySegmentShaped(goodKey+"="))
	require.True(t, conf.StreamKeySegmentShaped("x"+goodKey))
	require.True(t, conf.StreamKeySegmentShaped("abcd"+goodKey))
	// Mid-key junk insertions and junk-prefix+truncation combos stay inside the band.
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:20]+"."+goodKey[20:]))
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:20]+" "+goodKey[20:]))
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:20]+".."+goodKey[20:]))
	require.True(t, conf.StreamKeySegmentShaped("xy"+goodKey[:43]))
	require.True(t, conf.StreamKeySegmentShaped("x"+goodKey[:42]))
	require.True(t, conf.StreamKeySegmentShaped("x"+goodKey[:40]))
	require.True(t, conf.StreamKeySegmentShaped("abc"+goodKey[:38]+"de"))
	// Deeper truncations that still decode to a v1 prefix (token bits present).
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:24]))
	require.True(t, conf.StreamKeySegmentShaped(goodKey[:25]))
	// Full key embedded in a long segment (window scan).
	require.True(t, conf.StreamKeySegmentShaped("junk-"+goodKey+"-junk"))
	// Too short to carry any token bits: not flagged.
	require.False(t, conf.StreamKeySegmentShaped(goodKey[:22]))
	// Ordinary names, empty segments, and canonical lowercase UUIDs are never flagged
	// (a UUID is 36 chars — outside the band — and lowercase hex can't decode to a 0x01
	// version byte).
	require.False(t, conf.StreamKeySegmentShaped("mystream"))
	require.False(t, conf.StreamKeySegmentShaped(""))
	require.False(t, conf.StreamKeySegmentShaped(idStr))
	require.False(t, conf.StreamKeySegmentShaped("this_is_a_long_vanilla_stream_name_00"))
	require.False(t, conf.StreamKeySegmentShaped("a_49_char_vanilla_name_that_is_beyond_the_band_x0"))

	// Combined path+query checker: per-segment, per-token, and delimiter-split
	// reconstruction.
	require.True(t, conf.StreamKeyBearsKeyMaterial(goodKey, ""))
	require.True(t, conf.StreamKeyBearsKeyMaterial("a/"+goodKey+"/b", ""))
	require.True(t, conf.StreamKeyBearsKeyMaterial("", "x=1/"+goodKey))
	require.True(t, conf.StreamKeyBearsKeyMaterial("", "user=u&pass="+goodKey))
	// A key split by a single inserted '/' across two path segments (neither in-band).
	require.True(t, conf.StreamKeyBearsKeyMaterial("live/"+goodKey[:10]+"/"+goodKey[10:], ""))
	// A key split by a single inserted '?' across the path/query boundary.
	require.True(t, conf.StreamKeyBearsKeyMaterial("live/"+goodKey[:10], goodKey[10:]))
	// Canonical paths never match — with or without a lowercase query.
	require.False(t, conf.StreamKeyBearsKeyMaterial("live/mystream", ""))
	require.False(t, conf.StreamKeyBearsKeyMaterial("live/"+idStr, ""))
	require.False(t, conf.StreamKeyBearsKeyMaterial("live/"+idStr, "user=u&pass=p"))
	require.False(t, conf.StreamKeyBearsKeyMaterial("live/mystream", ""))
}

// TestServerStreamKeyPublish drives the REAL gortmplib client and server end-to-end (RTMP
// handshake, connect-command app split, v1.0.0 URL re-assembly) against a stream-key
// enabled server, so the fork's gate is exercised with the library's actual URL assembly
// rather than the joinURLv1 replica. Shapes a stock client cannot produce (path-less
// tcURL, hostile tcURL) remain covered by TestParsePublishAccessURLAssembly above.
func TestServerStreamKeyPublish(t *testing.T) {
	idStr := "12345678-1234-5678-1234-567812345678"
	tok := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	goodKey := packKey(streamKeyVersion, idStr, tok)
	wantPass := base64.RawURLEncoding.EncodeToString(tok)

	for _, ca := range []struct {
		name     string
		key      string
		query    string
		wantName string
		wantUser string
		wantPass string
		wantOK   bool
	}{
		{
			name:     "valid key: canonical rewrite + key credentials",
			key:      goodKey,
			wantName: "live/" + idStr,
			wantUser: idStr,
			wantPass: wantPass,
			wantOK:   true,
		},
		{
			name:     "corrupted key: fail-closed sentinel, no token in path",
			key:      packKey(0x02, idStr, tok),
			wantName: "live/",
			wantOK:   false,
		},
		{
			// Discriminates the publish-side query strip: an accepted key must not carry
			// its query onward, since the key — not the query — authenticated it.
			name:     "valid key with a query: query is stripped",
			key:      goodKey,
			query:    "?user=u&pass=p&param=value",
			wantName: "live/" + idStr,
			wantUser: idStr,
			wantPass: wantPass,
			wantOK:   true,
		},
		{
			name:     "corrupted key with a query: sentinel and query stripped",
			key:      packKey(0x02, idStr, tok),
			query:    "?user=u&pass=p",
			wantName: "live/",
			wantOK:   false,
		},
	} {
		t.Run(ca.name, func(t *testing.T) {
			gotReq := make(chan defs.PathAccessRequest, 1)

			pathManager := &test.PathManager{
				AddPublisherImpl: func(req defs.PathAddPublisherReq) (*defs.PathAddPublisherRes, error) {
					gotReq <- req.AccessRequest
					if !ca.wantOK {
						return nil, fmt.Errorf("rejected")
					}
					strm := &stream.Stream{
						OrigDesc:          req.Desc,
						WriteQueueSize:    512,
						RTPMaxPayloadSize: 1450,
						Parent:            test.NilLogger,
					}
					err := strm.Initialize()
					require.NoError(t, err)
					subStream := &stream.SubStream{
						Stream:        strm,
						UseRTPPackets: false,
					}
					err = subStream.Initialize()
					require.NoError(t, err)
					return &defs.PathAddPublisherRes{
						Path:      &dummyPath{},
						User:      req.AccessRequest.Credentials.User,
						SubStream: subStream,
					}, nil
				},
			}

			s := &Server{
				Address:             "127.0.0.1:1941",
				ReadTimeout:         conf.Duration(10 * time.Second),
				WriteTimeout:        conf.Duration(10 * time.Second),
				Encryption:          false,
				RTSPAddress:         "",
				RunOnConnect:        "",
				RunOnConnectRestart: false,
				RunOnDisconnect:     "",
				ExternalCmdPool:     nil,
				PathManager:         pathManager,
				Parent:              test.NilLogger,
				StreamKeyApp:        "live",
			}
			err := s.Initialize()
			require.NoError(t, err)
			defer s.Close()

			u, err := url.Parse("rtmp://127.0.0.1:1941/live/" + ca.key + ca.query)
			require.NoError(t, err)

			conn := &gortmplib.Client{
				URL:     u,
				Publish: true,
			}
			err = conn.Initialize(context.Background())
			require.NoError(t, err)
			defer conn.Close()

			w := &gortmplib.Writer{
				Conn: conn,
				Tracks: []*gortmplib.Track{
					{Codec: &codecs.H264{
						SPS: test.FormatH264.SPS,
						PPS: test.FormatH264.PPS,
					}},
				},
			}
			err = w.Initialize()
			require.NoError(t, err)

			// The server assembles the track list from the incoming stream before it calls
			// AddPublisher, and its probe only completes once the stream's DTS span covers
			// the analyze period — hence a frame stamped well past zero. In the fail-closed
			// case the server may close the connection while this write is in flight, so
			// its error is only meaningful for the accepted-publish case.
			err = w.WriteH264(w.Tracks[0], 2*time.Second, 2*time.Second, [][]byte{{5, 2, 3, 4}})
			if ca.wantOK {
				require.NoError(t, err)
			}

			select {
			case req := <-gotReq:
				require.Equal(t, ca.wantName, req.Name)
				require.Equal(t, ca.wantUser, req.Credentials.User)
				require.Equal(t, ca.wantPass, req.Credentials.Pass)
				require.Equal(t, "", req.Query)
			case <-time.After(5 * time.Second):
				t.Fatal("AddPublisher was not called")
			}
		})
	}
}

// TestServerStreamKeyRead drives the REAL gortmplib client in play mode against a
// stream-key enabled server, pinning the read-side hardening: a Stream Key pasted into a
// play URL must reach AddReader only as the token-free sentinel with blanked query and
// credentials, while a disabled server keeps stock pass-through behaviour.
func TestServerStreamKeyRead(t *testing.T) {
	idStr := "12345678-1234-5678-1234-567812345678"
	tok := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	goodKey := packKey(streamKeyVersion, idStr, tok)

	for _, ca := range []struct {
		name         string
		streamKeyApp string
		playPath     string
		wantName     string
		wantQuery    string
		wantUser     string
		wantPass     string
	}{
		{
			name:         "enabled: key-bearing play URL fails closed to the sentinel",
			streamKeyApp: "live",
			playPath:     "live/" + goodKey,
			wantName:     "live/",
			wantQuery:    "",
		},
		{
			// Discriminates the query/credential blanking: the query survives the
			// gortmplib round-trip (see the clean case below), so it must be blanked by
			// the read-side hardening rather than merely absent.
			name:         "enabled: key-bearing play URL blanks the query and credentials",
			streamKeyApp: "live",
			playPath:     "live/" + goodKey + "?user=u&pass=p",
			wantName:     "live/",
			wantQuery:    "",
		},
		{
			// Key material carried only by the query (path alone is clean).
			name:         "enabled: key in the query alone fails closed and blanks it",
			streamKeyApp: "live",
			playPath:     "live/" + idStr + "?token=" + goodKey,
			wantName:     "live/",
			wantQuery:    "",
		},
		{
			// A key split across the path/query boundary by one inserted '?'.
			name:         "enabled: delimiter-split key fails closed",
			streamKeyApp: "live",
			playPath:     "live/" + goodKey[:10] + "?" + goodKey[10:],
			wantName:     "live/",
			wantQuery:    "",
		},
		{
			name:         "enabled: clean play URL passes through with its query",
			streamKeyApp: "live",
			playPath:     "live/" + idStr + "?user=u&pass=p",
			wantName:     "live/" + idStr,
			wantQuery:    "user=u&pass=p",
			wantUser:     "u",
			wantPass:     "p",
		},
		{
			name:         "disabled: key-bearing play URL is stock pass-through",
			streamKeyApp: "",
			playPath:     "live/" + goodKey + "?user=u&pass=p",
			wantName:     "live/" + goodKey,
			wantQuery:    "user=u&pass=p",
			wantUser:     "u",
			wantPass:     "p",
		},
	} {
		t.Run(ca.name, func(t *testing.T) {
			gotReq := make(chan defs.PathAccessRequest, 1)

			pathManager := &test.PathManager{
				AddReaderImpl: func(req defs.PathAddReaderReq) (*defs.PathAddReaderRes, error) {
					gotReq <- req.AccessRequest
					// Rejecting is enough — the assertions below cover what reached the
					// path manager; no media flow is needed on the read side.
					return nil, fmt.Errorf("rejected")
				},
			}

			s := &Server{
				Address:             "127.0.0.1:1943",
				ReadTimeout:         conf.Duration(10 * time.Second),
				WriteTimeout:        conf.Duration(10 * time.Second),
				Encryption:          false,
				RTSPAddress:         "",
				RunOnConnect:        "",
				RunOnConnectRestart: false,
				RunOnDisconnect:     "",
				ExternalCmdPool:     nil,
				PathManager:         pathManager,
				Parent:              test.NilLogger,
				StreamKeyApp:        ca.streamKeyApp,
			}
			err := s.Initialize()
			require.NoError(t, err)
			defer s.Close()

			u, err := url.Parse("rtmp://127.0.0.1:1943/" + ca.playPath)
			require.NoError(t, err)

			conn := &gortmplib.Client{
				URL:     u,
				Publish: false,
			}
			err = conn.Initialize(context.Background())
			require.NoError(t, err)
			defer conn.Close()

			select {
			case req := <-gotReq:
				require.Equal(t, ca.wantName, req.Name)
				require.Equal(t, ca.wantQuery, req.Query)
				require.Equal(t, ca.wantUser, req.Credentials.User)
				require.Equal(t, ca.wantPass, req.Credentials.Pass)
			case <-time.After(5 * time.Second):
				t.Fatal("AddReader was not called")
			}
		})
	}
}
