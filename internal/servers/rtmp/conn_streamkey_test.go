package rtmp

import (
	"testing"
)

// TestParsePublishAccess covers the ADR-019-003 RTMP stream-key path-segment auth for
// PUBLISH. The behaviour is OPT-IN via the rtmpStreamKeyApp config (the streamKeyApp
// argument): empty = disabled (stock MediaMTX, the default for CameraHost and any other
// shared consumer), non-empty = the app under which live/<id>/<token> carries a token.
func TestParsePublishAccess(t *testing.T) {
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
		// ---- feature ENABLED (rtmpStreamKeyApp = "live") ----
		{
			name:          "enabled: strips token to canonical path, binds user to id",
			streamKeyApp:  "live",
			rawPath:       "live/abcdef/secrettoken",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef", // bound to the liveStreamId (per-path scope)
			wantPass:      "secrettoken",
		},
		{
			name:          "enabled: stream-key ignores query credentials (path token wins)",
			streamKeyApp:  "live",
			rawPath:       "live/abcdef/pathtoken",
			queryUser:     "attacker",
			queryPass:     "querytoken",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef",
			wantPass:      "pathtoken",
		},
		{
			name:          "enabled: empty token (trailing slash) -> fails closed at auth",
			streamKeyApp:  "live",
			rawPath:       "live/abcdef/",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef",
			wantPass:      "", // empty pass -> hash check fails downstream
		},
		{
			name:          "enabled: empty id -> empty user, rejected downstream",
			streamKeyApp:  "live",
			rawPath:       "live//secrettoken",
			wantCanonical: "live/",
			wantUser:      "",
			wantPass:      "secrettoken",
		},
		{
			name:          "enabled: bare identity path keeps existing query auth (2 segments)",
			streamKeyApp:  "live",
			rawPath:       "live/abcdef",
			queryUser:     "abcdef",
			queryPass:     "secrettoken",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef",
			wantPass:      "secrettoken",
		},
		{
			name:          "enabled: more than 3 segments keeps existing query auth",
			streamKeyApp:  "live",
			rawPath:       "live/abcdef/secrettoken/extra",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "live/abcdef/secrettoken/extra",
			wantUser:      "u",
			wantPass:      "p",
		},
		{
			name:          "enabled: non-matching app (3 segments) is vanilla",
			streamKeyApp:  "live",
			rawPath:       "foo/bar/baz",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "foo/bar/baz",
			wantUser:      "u",
			wantPass:      "p",
		},

		// ---- configurable app name (not hardcoded to "live") ----
		{
			name:          "configurable app: fires for the configured app",
			streamKeyApp:  "ingest",
			rawPath:       "ingest/abcdef/tok",
			wantCanonical: "ingest/abcdef",
			wantUser:      "abcdef",
			wantPass:      "tok",
		},
		{
			name:          "configurable app: does NOT fire for a different app",
			streamKeyApp:  "ingest",
			rawPath:       "live/abcdef/tok",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "live/abcdef/tok",
			wantUser:      "u",
			wantPass:      "p",
		},

		// ---- feature DISABLED (rtmpStreamKeyApp = "", the default) ----
		{
			name:          "disabled: live/<id>/<token> is a vanilla path, no token parsing",
			streamKeyApp:  "",
			rawPath:       "live/abcdef/secrettoken",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "live/abcdef/secrettoken", // raw path preserved verbatim
			wantUser:      "u",
			wantPass:      "p",
		},
		{
			name:          "disabled: live/<id>/<token> with no query -> empty creds (stock)",
			streamKeyApp:  "",
			rawPath:       "live/abcdef/secrettoken",
			wantCanonical: "live/abcdef/secrettoken",
			wantUser:      "",
			wantPass:      "",
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
