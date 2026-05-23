package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/fenmoai/tempogate/keys"
	"github.com/fenmoai/tempogate/oidc"
)

type FxSuite struct {
	suite.Suite
}

func TestFxSuite(t *testing.T) {
	suite.Run(t, new(FxSuite))
}

func (s *FxSuite) supplyConfig(clients string) fx.Option {
	return fx.Options(
		fx.Provide(func() oidc.AuthRequestStore { return &memAuthStore{} }),
		fx.Provide(func() oidc.CallbackStore { return &memCallbackStore{} }),
		fx.Provide(func() oidc.TokenStore { return newMemTokenStore() }),
		fx.Provide(func() oidc.DeviceCodeStore { return &memDeviceCodeStore{} }),
		fx.Provide(func() oidc.Upstream { return &fakeUpstream{} }),
		fx.Provide(func() *keys.Signer { return keys.NewSigner() }),
		fx.Provide(func() *keys.Verifier { return keys.NewVerifier() }),
		fx.Supply(
			fx.Annotated{Name: "oidc_issuer", Target: testIssuer},
			fx.Annotated{Name: "oidc_clients", Target: clients},
			fx.Annotated{Name: "oidc_client_secrets", Target: ""},
			fx.Annotated{Name: "oidc_allowed_domains", Target: "example.com"},
			fx.Annotated{Name: "google_client_id", Target: testGoogleCID},
			fx.Annotated{Name: "google_auth_endpoint", Target: testGoogleAuth},
		),
	)
}

type registrarParams struct {
	fx.In
	Registrars []func(huma.API) `group:"api_registrars"`
}

func (s *FxSuite) TestProvidesRegistrarIntoGroup() {
	var got registrarParams
	app := fxtest.New(s.T(),
		s.supplyConfig("ui:https://app.example.com/auth,tempogate-device:cli"),
		oidc.Fx(),
		fx.Populate(&got),
	)
	app.RequireStart()
	defer app.RequireStop()

	s.Require().Len(got.Registrars, 5)
}

// TestDeviceAuthorizationIsWiredIntoPublicAPI is the registration regression
// guard: graph construction must produce a POST /device_authorization route
// on the same Huma API the api package collects registrars onto. A missing
// fx provider would leave the registrar slice short; a missing fx.As binding
// on state/sqlite would fail graph construction before reaching here.
func (s *FxSuite) TestDeviceAuthorizationIsWiredIntoPublicAPI() {
	var got registrarParams
	app := fxtest.New(s.T(),
		s.supplyConfig("ui:https://app.example.com/auth,tempogate-device:cli"),
		oidc.Fx(),
		fx.Populate(&got),
	)
	app.RequireStart()
	defer app.RequireStop()

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("fx_test", "0.0.0"))
	for _, fn := range got.Registrars {
		fn(api)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// A real POST hits the wired handler; an unregistered path would 404.
	// We only assert the route exists — the response body shape is the
	// concern of device_authorization_test.go.
	resp, err := http.Post(srv.URL+"/device_authorization",
		"application/x-www-form-urlencoded",
		strings.NewReader("client_id=tempogate-device"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.NotEqual(http.StatusNotFound, resp.StatusCode,
		"POST /device_authorization must be registered against the public huma API")
}

func (s *FxSuite) TestMalformedClientsFailsGraph() {
	app := fx.New(
		fx.NopLogger,
		s.supplyConfig("no-colon-here"),
		oidc.Fx(),
		fx.Invoke(func(registrarParams) {}),
	)
	s.Require().Error(app.Err())
}
