package rtmp

import (
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
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
			name:          "enabled: a different app is vanilla (stock)",
			streamKeyApp:  app,
			rawPath:       "other/" + goodKey,
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "other/" + goodKey,
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
			name:          "configurable app: does NOT fire for a different app",
			streamKeyApp:  "ingest",
			rawPath:       app + "/" + goodKey,
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: app + "/" + goodKey,
			wantUser:      "u",
			wantPass:      "p",
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
