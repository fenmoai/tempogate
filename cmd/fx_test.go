package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestRootCommandRegistersEverySubcommand is the regression guard that a new
// subcommand is actually wired into the binary — the failure mode where a
// command exists but `tempogate <name>` says "unknown command".
func TestRootCommandRegistersEverySubcommand(t *testing.T) {
	root := rootCommand(RunParams{Logger: zap.NewNop()})

	got := map[string]bool{}
	for _, c := range root.Commands() {
		got[c.Name()] = true
	}

	for _, want := range []string{"serve", "migrate", "keys", "login", "token", "version"} {
		require.Truef(t, got[want], "subcommand %q must be registered on root", want)
	}
}
