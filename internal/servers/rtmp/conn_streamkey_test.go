package rtmp

import (
	"testing"
)

// TestParsePublishAccess covers the ADR-019-003 RTMP stream-key path-segment auth for
// PUBLISH. The change is ADDITIVE: only the exact live/<id>/<token> form is treated as a
// stream-key; every other path shape keeps MediaMTX's existing query/path auth.
func TestParsePublishAccess(t *testing.T) {
	for _, ca := range []struct {
		name          string
		rawPath       string
		queryUser     string
		queryPass     string
		wantCanonical string
		wantUser      string
		wantPass      string
	}{
		{
			name:          "stream-key: strips token to canonical path, binds user to id",
			rawPath:       "live/abcdef/secrettoken",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef", // bound to the liveStreamId (per-path scope)
			wantPass:      "secrettoken",
		},
		{
			name:          "stream-key ignores any query credentials (path token wins)",
			rawPath:       "live/abcdef/pathtoken",
			queryUser:     "attacker",
			queryPass:     "querytoken",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef",
			wantPass:      "pathtoken",
		},
		{
			name:          "stream-key empty token (trailing slash) -> fails closed at auth",
			rawPath:       "live/abcdef/",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef",
			wantPass:      "", // empty pass -> hash check fails downstream
		},
		{
			name:          "stream-key empty id -> empty user, no permission matches downstream",
			rawPath:       "live//secrettoken",
			wantCanonical: "live/",
			wantUser:      "",
			wantPass:      "secrettoken",
		},
		{
			// ADDITIVE: not the 3-segment form -> existing MediaMTX query auth is preserved.
			name:          "bare live identity path keeps existing query auth (2 segments)",
			rawPath:       "live/abcdef",
			queryUser:     "abcdef",
			queryPass:     "secrettoken",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef",
			wantPass:      "secrettoken",
		},
		{
			// ADDITIVE: deeper than the stream-key form -> NOT rejected, stays vanilla.
			name:          "more than 3 segments under live keeps existing query auth",
			rawPath:       "live/abcdef/secrettoken/extra",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "live/abcdef/secrettoken/extra",
			wantUser:      "u",
			wantPass:      "p",
		},
		{
			name:          "non-live 3-segment path is vanilla, not treated as stream-key",
			rawPath:       "foo/bar/baz",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "foo/bar/baz",
			wantUser:      "u",
			wantPass:      "p",
		},
		{
			name:          "single-segment path keeps existing query auth",
			rawPath:       "mystream",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "mystream",
			wantUser:      "u",
			wantPass:      "p",
		},
	} {
		t.Run(ca.name, func(t *testing.T) {
			canonical, creds := parsePublishAccess(ca.rawPath, ca.queryUser, ca.queryPass)
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
