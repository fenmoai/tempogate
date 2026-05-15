package app_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/fenmoai/tempogate/app"
)

type AppSuite struct {
	suite.Suite
}

func TestAppSuite(t *testing.T) {
	suite.Run(t, new(AppSuite))
}

// TestNew proves the fx graph resolves end-to-end (config + log + sqlite +
// api + cmd) and that lifecycle hooks fire. The default subcommand prints
// help and triggers Shutdown, so the schema-check inside `serve` is not
// invoked here.
func (s *AppSuite) TestNew() {
	s.T().Setenv("STATE__SQLITE__PATH", filepath.Join(s.T().TempDir(), "state.db"))

	ran := false
	a := fxtest.New(s.T(),
		app.New(),
		fx.Invoke(func() { ran = true }),
	)
	a.RequireStart().RequireStop()
	s.True(ran)
}
