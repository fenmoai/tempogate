package app_test

import (
	"testing"

	"go.uber.org/fx/fxtest"

	"github.com/fenmoai/tempogate/app"
)

// TestComposition proves the fx graph resolves and the lifecycle hooks
// registered by app.New() start and stop cleanly. With only the version
// subcommand wired, the cobra dispatcher prints root help on no-args and
// signals shutdown; fxtest tolerates that within RequireStart/RequireStop.
func TestComposition(t *testing.T) {
	t.Parallel()

	a := fxtest.New(t, app.New())
	a.RequireStart().RequireStop()
}
