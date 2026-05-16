package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// bearerToken's empty-after-trim guard is unreachable through the HTTP
// handler — Go's server strips trailing header whitespace before the handler
// sees it — so it is exercised here directly, white-box.
func TestBearerToken(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		wantTok string
		wantOK  bool
	}{
		{"valid", "Bearer abc.def.ghi", "abc.def.ghi", true},
		{"case-insensitive scheme", "bEaReR xyz", "xyz", true},
		{"surrounding whitespace trimmed", "Bearer   tok  ", "tok", true},
		{"shorter than the scheme", "Bear", "", false},
		{"exactly the prefix", "Bearer ", "", false},
		{"wrong scheme, same length", "Basic Zm9vYmFy", "", false},
		{"prefix then only whitespace", "Bearer     ", "", false},
		{"empty header", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, ok := bearerToken(tc.header)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantTok, tok)
		})
	}
}
