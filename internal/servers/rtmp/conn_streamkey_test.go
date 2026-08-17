package rtmp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluenviron/gortmplib"
	"github.com/bluenviron/gortmplib/pkg/amf0"
	"github.com/bluenviron/gortmplib/pkg/bytecounter"
	"github.com/bluenviron/gortmplib/pkg/codecs"
	"github.com/bluenviron/gortmplib/pkg/handshake"
	"github.com/bluenviron/gortmplib/pkg/message"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/externalcmd"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/stream"
	"github.com/bluenviron/mediamtx/internal/test"
)

// streamKeyTestPath is a minimal defs.Path for the path-manager mocks below.
type streamKeyTestPath struct{}

func (p *streamKeyTestPath) Name() string { return "teststream" }

func (p *streamKeyTestPath) SafeConf() *conf.Path { return &conf.Path{} }

func (p *streamKeyTestPath) ExternalCmdEnv() externalcmd.Environment {
	return externalcmd.Environment{}
}

func (p *streamKeyTestPath) RemovePublisher(_ defs.PathRemovePublisherReq) {}

func (p *streamKeyTestPath) RemoveReader(_ defs.PathRemoveReaderReq) {}

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

// joinURLv106 is a FROZEN local replica of gortmplib v1.0.6's joinURL (server_conn.go
// lines 67-100, the version go.mod pins): ServerConn.URL is the client-controlled tcURL
// joined with the publish/play-command Stream Key; the connect command's app field is NOT
// used. The tcURL and the key are parsed SEPARATELY and merged: paths are concatenated
// with a "/", queries are joined with "&", and a '?'-prefixed key that is already the
// suffix of the tcURL is dropped. (v1.0.0 concatenated the strings and parsed once, so a
// tcURL query swallowed the key; this is no longer so.) Because this is a replica, the
// suite pins the FORK's handling of the URL shapes v1.0.6 produces; it can NOT detect a
// future gortmplib assembly change by itself. Every gortmplib version bump MUST re-diff
// the library's joinURL against this replica and re-derive the table below
// (TestServerStreamKeyPublish drives the real library end-to-end for the shapes a real
// client can produce, which partially covers that gap).
func joinURLv106(tcURL string, streamKey string) (*url.URL, error) {
	tu, err := url.Parse(tcURL)
	if err != nil {
		return nil, err
	}

	if streamKey == "" || (streamKey[0] == '?' && strings.HasSuffix(tcURL, streamKey)) {
		return tu, nil
	}

	su, err := url.Parse("./" + streamKey)
	if err != nil {
		return nil, err
	}

	basePath := tu.EscapedPath()
	streamPath := strings.TrimPrefix(su.EscapedPath(), "./")
	tu.Path += "/" + strings.TrimPrefix(su.Path, "./")
	tu.RawPath = basePath + "/" + streamPath

	if tu.RawPath == tu.Path {
		tu.RawPath = ""
	}

	if su.RawQuery != "" {
		if tu.RawQuery != "" {
			tu.RawQuery += "&"
		}
		tu.RawQuery += su.RawQuery
	}
	tu.ForceQuery = tu.ForceQuery || su.ForceQuery

	if su.Fragment != "" {
		tu.Fragment = su.Fragment
		tu.RawFragment = su.RawFragment
	}

	return tu, nil
}

// TestParsePublishAccessURLAssembly drives the exact pipeline runPublish uses
// (ServerConn.URL -> TrimLeft(Path, "/") -> parsePublishAccess) with URLs assembled the way
// gortmplib v1.0.6 assembles them (joinURLv106), for every tcURL shape a client can
// legally produce. Each expectation was re-derived from the library's joinURL.
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
			// v1.0.6 parses tcURL and key separately (server_conn.go: tu.Path += "/" + su.Path)
			// so "rtmp://host/live?x=1" + key gives Path "/live/<key>", RawQuery "x=1": the
			// key is in the PATH, accepted (v1.0.0 swallowed it into RawQuery and failed
			// closed). runPublish then strips the "x=1" query; it is not seen here.
			name:          "tcURL with query + key: key in the path -> accepted",
			tcURL:         "rtmp://host:1935/" + app + "?x=1",
			streamKey:     goodKey,
			wantCanonical: app + "/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
		},
		{
			// Same shape with the key already inside the tcURL's path and a query on it:
			// empty stream key returns the tcURL as parsed (server_conn.go: streamKey == "").
			name:          "tcURL with key in the path and a query, empty stream key -> accepted",
			tcURL:         "rtmp://host:1935/" + app + "/" + goodKey + "?x=1",
			streamKey:     "",
			wantCanonical: app + "/" + idStr,
			wantUser:      idStr,
			wantPass:      wantPass,
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
			// v1.0.6 drops a '?'-prefixed stream key only when the tcURL already ends with
			// it (server_conn.go: HasSuffix), leaving the bare app: fail closed.
			name:          "query-only stream key that ends the tcURL is dropped -> fails closed",
			tcURL:         "rtmp://host:1935/" + app + "?user=u&pass=p",
			streamKey:     "?user=u&pass=p",
			wantCanonical: app + "/",
		},
		{
			// Otherwise the '?' key is parsed as "./?user=u&pass=p": an empty path part
			// (Path "/live/") and the query merged in; the path "live/" has an empty
			// second segment, which is no key: fail closed (the credentials in the query
			// are not read for a stream-key app path).
			name:          "query-only stream key, not the tcURL's suffix -> empty segment, fails closed",
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
			u, err := joinURLv106(ca.tcURL, ca.streamKey)
			if err != nil {
				t.Fatalf("joinURLv106: %v", err)
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
// handshake, connect-command app split, v1.0.6 URL re-assembly) against a stream-key
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
		rawURL   string // overrides the URL built from key and query
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
		{
			// A tcURL that itself carries a query, with the key as the separate publish
			// stream key (the URL fragment for gortmplib's client). gortmplib v1.0.6
			// (joinURL, server_conn.go) merges path and query separately, so the key lands
			// in the path: accepted, and the tcURL's query is stripped like any other.
			// (The v1.0.0 replica this test used to encode failed this shape closed:
			// Codex round 1, finding 4.)
			name:     "tcURL with query + valid key: key in the path, query stripped",
			rawURL:   "rtmp://127.0.0.1:1941/live?x=1#" + goodKey,
			wantName: "live/" + idStr,
			wantUser: idStr,
			wantPass: wantPass,
			wantOK:   true,
		},
	} {
		t.Run(ca.name, func(t *testing.T) {
			gotReq := make(chan defs.PathAccessRequest, 1)

			pathManager := &test.PathManager{
				// Since MediaMTX v1.21 the credentials are checked by FindPathConf, which
				// is where the stream-key rewrite (canonical name, credentials, stripped
				// query) is observable; the AddPublisher call that follows only repeats
				// the name and skips auth. FindPathConf accepts here so that the fail-closed
				// cases still reach AddPublisher, as they did when AddPublisher authenticated.
				FindPathConfImpl: func(req defs.PathFindPathConfReq) (*defs.PathFindPathConfRes, error) {
					gotReq <- req.AccessRequest
					return &defs.PathFindPathConfRes{
						AuthRes: &auth.Result{User: req.AccessRequest.Credentials.User},
					}, nil
				},
				AddPublisherImpl: func(req defs.PathAddPublisherReq) (*defs.PathAddPublisherRes, error) {
					require.Equal(t, ca.wantName, req.AccessRequest.Name)
					require.Equal(t, "", req.AccessRequest.Query)
					require.True(t, req.AccessRequest.SkipAuth)
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
						Path:      &streamKeyTestPath{},
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

			rawURL := ca.rawURL
			if rawURL == "" {
				rawURL = "rtmp://127.0.0.1:1941/live/" + ca.key + ca.query
			}
			u, err := url.Parse(rawURL)
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
				t.Fatal("FindPathConf was not called")
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
					// path manager; no media flow is needed on the read side. An auth
					// error makes the server answer the play request with a failure
					// (gortmplib v1.0.6 clients wait for that answer).
					return nil, &auth.Error{Wrapped: fmt.Errorf("rejected")}
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
			require.ErrorContains(t, err, "NetStream.Play.Failed")

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

// TestRedactConnErr pins the log-redaction of connection errors at the one log sink
// (Codex round 1 finding 1, round 2 finding A): gortmplib's AcceptConn URL assembly
// (joinURL) calls url.Parse on text that holds the publish/play stream key, and a bad
// escape makes a *url.Error that quotes the whole input; Initialize quotes the whole
// connect command. With the feature on no logged error may carry key material; with it
// off the error is stock, untouched.
func TestRedactConnErr(t *testing.T) {
	idStr := "12345678-1234-5678-1234-567812345678"
	tok := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	goodKey := packKey(streamKeyVersion, idStr, tok)

	// The error exactly as gortmplib v1.0.6 builds it for stream key goodKey+"%zz".
	_, parseErr := url.Parse("./" + goodKey + "%zz")
	require.Error(t, parseErr)
	require.Contains(t, parseErr.Error(), goodKey, "precondition: the library error quotes the key")

	// And for a key that sits in the tcURL (the first url.Parse of joinURL).
	_, tcErr := url.Parse("rtmp://host/live/" + goodKey + "%zz")
	require.Error(t, tcErr)
	require.Contains(t, tcErr.Error(), goodKey, "precondition: the tcURL error quotes the key")

	assertNoKeyWindow := func(t *testing.T, text string) {
		t.Helper()
		// No 20-char window of the key (far below any scanner band, so nothing usable).
		for i := 0; i+20 <= len(goodKey); i++ {
			require.NotContains(t, text, goodKey[i:i+20])
		}
	}

	t.Run("enabled: *url.Error is replaced by a secret-free error", func(t *testing.T) {
		for _, e := range []error{parseErr, tcErr, fmt.Errorf("wrapped: %w", parseErr)} {
			got := redactConnErr("live", e)
			require.Error(t, got)
			assertNoKeyWindow(t, got.Error())
			require.Contains(t, got.Error(), "invalid RTMP URL")
		}
	})

	t.Run("enabled: any other error that bears key material is replaced", func(t *testing.T) {
		got := redactConnErr("live", fmt.Errorf("unexpected command %q", goodKey))
		require.Error(t, got)
		assertNoKeyWindow(t, got.Error())
	})

	t.Run("enabled: Initialize error quoting the whole connect command", func(t *testing.T) {
		// gortmplib v1.0.6 server_conn.go (Initialize): fmt.Errorf("invalid connect command: %+v", connectCmd)
		// when "app" is missing or not a string; the command holds the tcUrl, key included.
		cmd := &message.CommandAMF0{
			ChunkStreamID: 3,
			Name:          "connect",
			CommandID:     1,
			Arguments: []any{amf0.Object{
				{Key: "flashVer", Value: "LNX 9,0,124,2"},
				{Key: "tcUrl", Value: "rtmp://127.0.0.1:1941/live/" + goodKey},
			}},
		}
		libErr := fmt.Errorf("invalid connect command: %+v", cmd)
		require.Contains(t, libErr.Error(), goodKey, "precondition: the library error quotes the key")

		got := redactConnErr("live", libErr)
		require.Error(t, got)
		assertNoKeyWindow(t, got.Error())

		require.Equal(t, libErr, redactConnErr("", libErr), "feature off: stock")
	})

	t.Run("enabled: an error without key material is kept", func(t *testing.T) {
		e := fmt.Errorf("invalid publish command arguments")
		require.Equal(t, e, redactConnErr("live", e))
		require.NoError(t, redactConnErr("live", nil))
	})

	t.Run("disabled: the error is stock, byte for byte", func(t *testing.T) {
		require.Equal(t, parseErr, redactConnErr("", parseErr))
		require.Equal(t, parseErr.Error(), redactConnErr("", parseErr).Error())
	})
}

// recordingLogger is a Server parent that keeps every log line.
type recordingLogger struct {
	mutex sync.Mutex
	lines []string
}

func (l *recordingLogger) Log(level logger.Level, format string, args ...any) {
	line := fmt.Sprintf("%v: ", level) + fmt.Sprintf(format, args...)
	l.mutex.Lock()
	l.lines = append(l.lines, line)
	l.mutex.Unlock()
}

func (l *recordingLogger) OnFatalError(context.Context, error) {}

func (l *recordingLogger) snapshot() []string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return append([]string(nil), l.lines...)
}

// TestServerStreamKeyAcceptErrLog drives the REAL gortmplib client against the real
// server with a stream key (the URL fragment, which the client sends verbatim as the
// publish/play stream name) that is a valid packed key next to a bad escape. The
// library's url.Parse fails and AcceptConn returns an error quoting the key; the server
// logs it at INFO as "closed: ...". With the feature on the log must not hold the key
// (Codex round 1, finding 1); with it off the line is stock (the library error).
func TestServerStreamKeyAcceptErrLog(t *testing.T) {
	idStr := "12345678-1234-5678-1234-567812345678"
	tok := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	goodKey := packKey(streamKeyVersion, idStr, tok)

	for _, ca := range []struct {
		name         string
		streamKeyApp string
		publish      bool
		streamKey    string
		wantKeyInLog bool
	}{
		{"enabled, publish", "live", true, goodKey + "%zz", false},
		{"enabled, play", "live", false, goodKey + "%zz", false},
		{"enabled, key behind the bad escape", "live", true, "%zz" + goodKey, false},
		{"disabled, publish: stock log line", "", true, goodKey + "%zz", true},
	} {
		t.Run(ca.name, func(t *testing.T) {
			pathManager := &test.PathManager{
				FindPathConfImpl: func(defs.PathFindPathConfReq) (*defs.PathFindPathConfRes, error) {
					t.Error("FindPathConf must not be reached")
					return nil, fmt.Errorf("unexpected")
				},
				AddReaderImpl: func(defs.PathAddReaderReq) (*defs.PathAddReaderRes, error) {
					t.Error("AddReader must not be reached")
					return nil, fmt.Errorf("unexpected")
				},
			}

			parent := &recordingLogger{}
			s := &Server{
				Address:      "127.0.0.1:1944",
				ReadTimeout:  conf.Duration(10 * time.Second),
				WriteTimeout: conf.Duration(10 * time.Second),
				PathManager:  pathManager,
				Parent:       parent,
				StreamKeyApp: ca.streamKeyApp,
			}
			err := s.Initialize()
			require.NoError(t, err)
			defer s.Close()

			// Built field by field: url.Parse would reject the bad escape.
			conn := &gortmplib.Client{
				URL: &url.URL{
					Scheme:   "rtmp",
					Host:     "127.0.0.1:1944",
					Path:     "/live",
					Fragment: ca.streamKey,
				},
				Publish: ca.publish,
			}
			err = conn.Initialize(context.Background())
			require.Error(t, err)

			var closed string
			require.Eventually(t, func() bool {
				for _, l := range parent.snapshot() {
					if strings.Contains(l, "closed:") {
						closed = l
						return true
					}
				}
				return false
			}, 5*time.Second, 10*time.Millisecond, "no 'closed:' log line")

			if ca.wantKeyInLog {
				// feature off: the line is the unredacted library error, as stock prints it
				require.Contains(t, closed, "closed: parse \"./"+goodKey+"%zz\": invalid URL escape")
				return
			}
			all := strings.Join(parent.snapshot(), "\n")
			for i := 0; i+20 <= len(goodKey); i++ {
				require.NotContains(t, all, goodKey[i:i+20], "stream key fragment in the log: %s", closed)
			}
			require.Contains(t, closed, "invalid RTMP URL")
		})
	}
}

// TestServerStreamKeyConnectErrLog sends a hand-built connect command (the stock gortmplib
// client always sends a proper "app", so the handshake and the command are written with the
// library's lower-level packages) whose tcUrl carries a valid packed key and whose "app" is
// missing or not a string. gortmplib's ServerConn.Initialize then fails with
// "invalid connect command: %+v" quoting the whole command, key included, and the
// connection logs that at INFO as "closed: ..." (Codex round 2, finding A). With the
// feature on, no log line may hold the key; with it off the line is stock.
func TestServerStreamKeyConnectErrLog(t *testing.T) {
	idStr := "12345678-1234-5678-1234-567812345678"
	tok := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	goodKey := packKey(streamKeyVersion, idStr, tok)

	for _, ca := range []struct {
		name         string
		streamKeyApp string
		app          any // nil: the "app" entry is left out
		wantKeyInLog bool
	}{
		{"enabled, app missing", "live", nil, false},
		{"enabled, app not a string", "live", float64(5), false},
		{"disabled, app missing: stock log line", "", nil, true},
	} {
		t.Run(ca.name, func(t *testing.T) {
			pathManager := &test.PathManager{
				FindPathConfImpl: func(defs.PathFindPathConfReq) (*defs.PathFindPathConfRes, error) {
					t.Error("FindPathConf must not be reached")
					return nil, fmt.Errorf("unexpected")
				},
				AddReaderImpl: func(defs.PathAddReaderReq) (*defs.PathAddReaderRes, error) {
					t.Error("AddReader must not be reached")
					return nil, fmt.Errorf("unexpected")
				},
			}

			parent := &recordingLogger{}
			s := &Server{
				Address:      "127.0.0.1:1945",
				ReadTimeout:  conf.Duration(10 * time.Second),
				WriteTimeout: conf.Duration(10 * time.Second),
				PathManager:  pathManager,
				Parent:       parent,
				StreamKeyApp: ca.streamKeyApp,
			}
			err := s.Initialize()
			require.NoError(t, err)
			defer s.Close()

			nconn, err := net.Dial("tcp", "127.0.0.1:1945")
			require.NoError(t, err)
			defer nconn.Close()
			nconn.SetDeadline(time.Now().Add(10 * time.Second))

			bc := bytecounter.NewReadWriter(nconn)
			_, _, err = handshake.DoClient(bc, false, false)
			require.NoError(t, err)

			connectArg := amf0.Object{
				{Key: "flashVer", Value: "LNX 9,0,124,2"},
				{Key: "tcUrl", Value: "rtmp://127.0.0.1:1945/live/" + goodKey},
				{Key: "objectEncoding", Value: float64(0)},
			}
			if ca.app != nil {
				connectArg = append(amf0.Object{{Key: "app", Value: ca.app}}, connectArg...)
			}

			mrw := message.NewReadWriter(bc, bc, false)
			err = mrw.Write(&message.CommandAMF0{
				ChunkStreamID: 3,
				Name:          "connect",
				CommandID:     1,
				Arguments:     []any{connectArg},
			})
			require.NoError(t, err)

			var closed string
			require.Eventually(t, func() bool {
				for _, l := range parent.snapshot() {
					if strings.Contains(l, "closed:") {
						closed = l
						return true
					}
				}
				return false
			}, 5*time.Second, 10*time.Millisecond, "no 'closed:' log line")

			if ca.wantKeyInLog {
				// feature off: the line is the unredacted library error, as stock prints it
				require.Contains(t, closed, "closed: invalid connect command: &{ChunkStreamID:3")
				require.Contains(t, closed, "rtmp://127.0.0.1:1945/live/"+goodKey)
				return
			}
			all := strings.Join(parent.snapshot(), "\n")
			for i := 0; i+20 <= len(goodKey); i++ {
				require.NotContains(t, all, goodKey[i:i+20], "stream key fragment in the log: %s", closed)
			}
			require.Contains(t, closed, "closed: invalid RTMP request")
		})
	}
}
