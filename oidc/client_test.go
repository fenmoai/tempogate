package oidc_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/fenmoai/tempogate/oidc"
)

type ClientRegistrySuite struct {
	suite.Suite
}

func TestClientRegistrySuite(t *testing.T) {
	suite.Run(t, new(ClientRegistrySuite))
}

func (s *ClientRegistrySuite) TestParse() {
	cases := []struct {
		name    string
		raw     string
		want    oidc.ClientRegistry
		wantErr bool
	}{
		{
			name: "empty string yields empty registry",
			raw:  "",
			want: oidc.ClientRegistry{},
		},
		{
			name: "single entry keeps scheme after first colon",
			raw:  "ui:https://app.example.com/cb",
			want: oidc.ClientRegistry{"ui": "https://app.example.com/cb"},
		},
		{
			name: "multiple entries with surrounding spaces",
			raw:  "ui:https://app.example.com/cb, cli:http://127.0.0.1",
			want: oidc.ClientRegistry{
				"ui":  "https://app.example.com/cb",
				"cli": "http://127.0.0.1",
			},
		},
		{
			name:    "missing colon is an error",
			raw:     "noseparator",
			wantErr: true,
		},
		{
			name:    "empty id is an error",
			raw:     ":https://app.example.com",
			wantErr: true,
		},
		{
			name:    "empty prefix is an error",
			raw:     "ui:",
			wantErr: true,
		},
		{
			name:    "duplicate client_id is an error",
			raw:     "ui:https://a.example.com,ui:https://b.example.com",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			got, err := oidc.ParseClientRegistry(tc.raw)
			if tc.wantErr {
				s.Require().Error(err)
				return
			}
			s.Require().NoError(err)
			s.Equal(tc.want, got)
		})
	}
}

func (s *ClientRegistrySuite) TestValidate() {
	reg := oidc.ClientRegistry{"ui": "https://app.example.com/auth"}

	cases := []struct {
		name        string
		clientID    string
		redirectURI string
		wantErr     error
	}{
		{
			name:        "known client under prefix",
			clientID:    "ui",
			redirectURI: "https://app.example.com/auth/callback",
		},
		{
			name:        "unknown client",
			clientID:    "other",
			redirectURI: "https://app.example.com/auth/callback",
			wantErr:     oidc.ErrUnknownClient,
		},
		{
			name:        "redirect_uri outside prefix",
			clientID:    "ui",
			redirectURI: "https://evil.example.com/auth/callback",
			wantErr:     oidc.ErrRedirectURINotAllowed,
		},
		{
			name:        "empty redirect_uri",
			clientID:    "ui",
			redirectURI: "",
			wantErr:     oidc.ErrRedirectURINotAllowed,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			err := reg.Validate(tc.clientID, tc.redirectURI)
			if tc.wantErr != nil {
				s.Require().Error(err)
				s.Truef(errors.Is(err, tc.wantErr), "want %v, got %v", tc.wantErr, err)
				return
			}
			s.Require().NoError(err)
		})
	}
}
