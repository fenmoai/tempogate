//go:build !lean

package app

import (
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/api"
	"github.com/fenmoai/tempogate/cmd/servercmd"
	"github.com/fenmoai/tempogate/keys"
	"github.com/fenmoai/tempogate/oidc"
	"github.com/fenmoai/tempogate/oidc/google"
	"github.com/fenmoai/tempogate/state/sqlite"
)

// serverModules wires the HTTP server stack (SQLite state store, signing
// keys, OIDC issuer, Google upstream, the API surface) and the server-bound
// subcommands (serve, migrate, keys).
//
// It is excluded from the lean CLI build (-tags lean, see modules_lean.go):
// nothing in the lean binary imports these packages, so the Go linker drops
// the entire SQLite/libc/OIDC/API subtree (~4 MB) — smaller artifact, smaller
// attack surface, and no SQLite is opened just to run `login`/`token`.
func serverModules() []fx.Option {
	return []fx.Option{
		sqlite.Fx(),
		keys.Fx(),
		oidc.Fx(),
		google.Fx(),
		api.Fx(),
		servercmd.Fx(),
	}
}
