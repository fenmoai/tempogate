package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
)

// TestRootCommandRegistersGroupedSubcommands is the regression guard for the
// command-registry wiring: every provider that contributes a *cobra.Command
// into the "commands" group must end up registered on root. It exercises the
// real seam — CLICommandsFx for the always-present CLI commands plus a
// stand-in server command (proving server-bound providers, wired only by the
// full app assembly, flow through the same group) — without standing up the
// fx lifecycle / SQLite that the full graph would need.
func TestRootCommandRegistersGroupedSubcommands(t *testing.T) {
	var root *cobra.Command

	app := fxtest.New(t,
		fx.Provide(zap.NewNop),
		CLICommandsFx(),
		fx.Provide(asCommand(func() *cobra.Command { return &cobra.Command{Use: "serve"} })),
		fx.Invoke(func(p rootParams) { root = rootCommand(p) }),
	)
	app.RequireStart().RequireStop()

	require.NotNil(t, root)
	got := map[string]bool{}
	for _, c := range root.Commands() {
		got[c.Name()] = true
	}
	for _, want := range []string{"version", "login", "token", "serve"} {
		require.Truef(t, got[want], "subcommand %q must be registered on root", want)
	}
}
