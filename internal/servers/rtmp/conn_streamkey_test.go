package rtmp

import (
	"testing"
)

// TestParsePublishAccess covers the ADR-019-003 RTMP stream-key path-carriage
// segment-count contract for PUBLISH.
func TestParsePublishAccess(t *testing.T) {
	for _, ca := range []struct {
		name          string
		rawPath       string
		queryUser     string
		queryPass     string
		wantCanonical string
		wantUser      string
		wantPass      string
		wantOK        bool
	}{
		{
			name:          "target carriage strips token to canonical path",
			rawPath:       "live/abcdef/secrettoken",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef", // bound to the liveStreamId (per-path scope)
			wantPass:      "secrettoken",
			wantOK:        true,
		},
		{
			name:          "interim query carriage is unchanged (2 segments)",
			rawPath:       "live/abcdef",
			queryUser:     "abcdef",
			queryPass:     "secrettoken",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef",
			wantPass:      "secrettoken",
			wantOK:        true,
		},
		{
			name:          "more than 3 segments under live is rejected",
			rawPath:       "live/abcdef/secrettoken/extra",
			wantCanonical: "",
			wantOK:        false,
		},
		{
			name:          "empty token (trailing slash) flows through to fail-closed auth",
			rawPath:       "live/abcdef/",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef",
			wantPass:      "", // empty pass -> hash check fails downstream
			wantOK:        true,
		},
		{
			name:          "empty id flows through with empty user (no permission matches)",
			rawPath:       "live//secrettoken",
			wantCanonical: "live/",
			wantUser:      "",
			wantPass:      "secrettoken",
			wantOK:        true,
		},
		{
			name:          "non-live multi-segment path is vanilla, not treated as token",
			rawPath:       "foo/bar/baz",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "foo/bar/baz",
			wantUser:      "u",
			wantPass:      "p",
			wantOK:        true,
		},
		{
			name:          "single-segment path is vanilla with query credentials",
			rawPath:       "mystream",
			queryUser:     "u",
			queryPass:     "p",
			wantCanonical: "mystream",
			wantUser:      "u",
			wantPass:      "p",
			wantOK:        true,
		},
		{
			name:          "target carriage ignores any query credentials",
			rawPath:       "live/abcdef/pathtoken",
			queryUser:     "attacker",
			queryPass:     "querytoken",
			wantCanonical: "live/abcdef",
			wantUser:      "abcdef",
			wantPass:      "pathtoken", // path-segment token wins, query ignored
			wantOK:        true,
		},
	} {
		t.Run(ca.name, func(t *testing.T) {
			canonical, creds, ok := parsePublishAccess(ca.rawPath, ca.queryUser, ca.queryPass)
			if ok != ca.wantOK {
				t.Fatalf("ok = %v, want %v", ok, ca.wantOK)
			}
			if !ok {
				return
			}
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
