// Fork extension (ADR-019-003/004).
//
// This file is the single source of the packed Stream-Key v1 layout constants and of the
// key-material shape detector. It lives in internal/conf (rather than the RTMP server,
// which aliases these symbols) so that Conf.Validate can reject a key-shaped
// rtmpStreamKeyApp value at config-load time with the exact same predicate the servers
// enforce at runtime — a divergent duplicate would let a value pass validation and then
// kill the process when the RTMP server refuses to initialize.

package conf

import (
	"encoding/base64"
	"slices"
	"strings"
)

// v1 packed Stream Key (ADR-019-004): base64url-nopad( version(1B) || liveStreamId(16B)
// || token(16B) ). 33 decoded bytes -> exactly 44 base64url chars, all in [A-Za-z0-9_-].
// The 16/16 byte layout is single-sourced here (ADR-019-004 invariant (d)): a wrong
// literal offset would silently mis-split id/token, so the offsets derive from these.
const (
	StreamKeyVersion    = 0x01                                                     // v1 layout discriminator (fail-closed)
	StreamKeyVersionLen = 1                                                        // version byte
	StreamKeyIDLen      = 16                                                       // liveStreamId (raw UUID) bytes
	StreamKeyTokenLen   = 16                                                       // 128-bit token bytes
	StreamKeyDecodedLen = StreamKeyVersionLen + StreamKeyIDLen + StreamKeyTokenLen // 33
	StreamKeyEncodedLen = 44                                                       // base64url-nopad(33 bytes), no '='

	// A segment within this many chars of the packed length is treated as key material
	// unconditionally: it covers up to four characters of combined insertion/truncation
	// mangling (stray punctuation from chat/email line wrapping, copy-paste artifacts),
	// which decode-based rules cannot see once the corruption breaks base64 alignment.
	streamKeyShapedLenSlack = 4
)

// streamKeyDecodesToPrefix reports whether a string base64url-decodes to a v1 key
// prefix: version byte 0x01 with at least the version+id bytes present — the point from
// which a decoded blob starts carrying token bits.
func streamKeyDecodesToPrefix(s string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) >= StreamKeyVersionLen+StreamKeyIDLen && raw[0] == StreamKeyVersion
}

// streamKeyWindowScan reports whether s contains a 44-char base64url run that decodes to
// a full v1 packed key (33 bytes, version 0x01). Unlike the length band it fires only on
// a genuine embedded key, so it is safe to run over reconstructed (delimiter-stripped)
// path/query text: a canonical "<app>/<uuid>" path is 40 chars with no 44-run, and a
// 0x01-led window requires an 'A' at its start, which lowercase canonical data lacks.
func streamKeyWindowScan(s string) bool {
	for i := 0; i+StreamKeyEncodedLen <= len(s); i++ {
		if raw, err := base64.RawURLEncoding.DecodeString(s[i : i+StreamKeyEncodedLen]); err == nil &&
			len(raw) == StreamKeyDecodedLen && raw[0] == StreamKeyVersion {
			return true
		}
	}
	return false
}

// streamKeyStripURLDelimiters removes the RTMP-URL structural characters that could split
// a Stream Key across path segments, query tokens, or the path/query boundary.
func streamKeyStripURLDelimiters(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '/', '?', '&', '=', ';':
			return -1
		}
		return r
	}, s)
}

// StreamKeySegmentShaped reports whether a path segment must be treated as Stream-Key
// material and therefore may never appear in a raw path name, log line, API field, hook
// or auth request. Flagged shapes:
//
//   - length within streamKeyShapedLenSlack of the packed-key length, whether or not it
//     decodes (a corrupted key: single/few-char insertions, deletions, substitutions);
//   - a segment decoding to a v1 key prefix (a truncated key — e.g. a 43-char prefix of
//     a real key still decodes to the full id plus 15 of the 16 token bytes);
//   - the same after cutting to the longest 4-aligned prefix (base64 cannot decode
//     len%4==1 inputs or out-of-alphabet bytes, so some truncations would otherwise
//     slip past the decoder);
//   - a full packed key embedded anywhere inside a longer segment (key with junk
//     prepended/appended).
//
// This is the PER-SEGMENT test. A key split across segments or the path/query boundary by
// an inserted URL delimiter is caught by StreamKeyBearsKeyMaterial's reconstruction pass,
// not here.
//
// Accepted detection boundary (documented, not covered): a key mangled by MORE than
// streamKeyShapedLenSlack characters of combined junk and truncation, corrupted in a way
// that also breaks base64 alignment, can evade every rule. Closing that would require
// flagging arbitrary base64url-looking text and break vanilla path names wholesale.
//
// The deliberate cost is a false-positive class: on a server with rtmpStreamKeyApp
// enabled, a vanilla path segment or query token that happens to be key-shaped (within
// a few chars of 44, base64url text decoding to a 0x01-led blob of 17+ bytes, or
// containing a 44-char base64url run that decodes to a 0x01-led 33-byte blob — long
// random base64url values such as JWT signatures will frequently match) is failed closed
// too. That constraint is documented with the rtmpStreamKeyApp option; disabled
// deployments are unaffected.
func StreamKeySegmentShaped(seg string) bool {
	if d := len(seg) - StreamKeyEncodedLen; d >= -streamKeyShapedLenSlack && d <= streamKeyShapedLenSlack {
		return true
	}
	if streamKeyDecodesToPrefix(seg) {
		return true
	}
	if aligned := len(seg) - len(seg)%4; aligned > 0 && streamKeyDecodesToPrefix(seg[:aligned]) {
		return true
	}
	return streamKeyWindowScan(seg)
}

// StreamKeyBearsKeyMaterial reports whether the raw path and raw query of an RTMP request
// together bear Stream-Key material that must never become a path name, query, log line,
// API field, hook env or auth request. It runs the per-segment shape test over every path
// segment and query token (catching a single in-band segment — a truncated or lightly
// mangled key, or a whole key swallowed into the query as gortmplib v1.0.0 does when the
// tcURL carries a query), and additionally reconstructs the request with URL structural
// delimiters removed and window-scans it, so a key split by a single inserted '/' or '?'
// (a copy-paste or line-wrap artifact) across segments or the path/query boundary is
// still caught. The reconstruction uses window-scan only (never the length band), so a
// canonical "<app>/<uuid>" path — 40 chars, lowercase, no 44-run — never matches.
func StreamKeyBearsKeyMaterial(rawPath, rawQuery string) bool {
	if slices.ContainsFunc(strings.Split(rawPath, "/"), StreamKeySegmentShaped) {
		return true
	}
	if rawQuery != "" && slices.ContainsFunc(streamKeyQueryTokens(rawQuery), StreamKeySegmentShaped) {
		return true
	}
	return streamKeyWindowScan(streamKeyStripURLDelimiters(rawPath) + streamKeyStripURLDelimiters(rawQuery))
}

func streamKeyQueryTokens(rawQuery string) []string {
	return strings.FieldsFunc(rawQuery, func(r rune) bool {
		return r == '&' || r == '=' || r == '/' || r == '?' || r == ';'
	})
}
