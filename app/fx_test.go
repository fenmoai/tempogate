package app_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/fenmoai/tempogate/app"
)

// TestNew proves the fx graph resolves end-to-end (config + log + cmd) and
// that lifecycle hooks fire. Set LOG__LEVEL or HTTP__LISTENER in the env to
// exercise the env-override path.
func TestNew(t *testing.T) {
	ran := false
	a := fxtest.New(t,
		app.New(),
		fx.Invoke(func() { ran = true }),
	)
	a.RequireStart().RequireStop()
	assert.True(t, ran)
}
