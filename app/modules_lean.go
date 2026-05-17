//go:build lean

package app

import "go.uber.org/fx"

// serverModules is empty in the lean CLI build (-tags lean): no SQLite/OIDC/
// API stack and no serve/migrate/keys subcommands. The distributed CLI keeps
// only login/token/version. See modules_full.go for the full set.
func serverModules() []fx.Option { return nil }
