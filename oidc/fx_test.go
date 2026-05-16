package oidc_test

import (
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

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
		fx.Supply(
			fx.Annotated{Name: "oidc_issuer", Target: testIssuer},
			fx.Annotated{Name: "oidc_clients", Target: clients},
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
		s.supplyConfig("ui:https://app.example.com/auth"),
		oidc.Fx(),
		fx.Populate(&got),
	)
	app.RequireStart()
	defer app.RequireStop()

	s.Require().Len(got.Registrars, 1)
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
