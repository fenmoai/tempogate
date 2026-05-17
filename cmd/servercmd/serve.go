// Package servercmd holds the server-bound subcommands (serve, migrate,
// keys) — the ones that need the SQLite state store and the OIDC/API stack.
//
// It is wired into the cobra command group only by the full app assembly
// (app/modules_full.go). The lean CLI build never imports this package, so
// the Go linker drops the entire server subtree (SQLite/libc/OIDC/API) from
// that binary. Build tags live exclusively in package app — leanness here is
// a property of not being imported, not of a //go:build constraint.
package servercmd

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gojekfarm/xrun"
	xloadtype "github.com/gojekfarm/xtools/xload/type"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/fenmoai/tempogate/api"
	"github.com/fenmoai/tempogate/keys"
	"github.com/fenmoai/tempogate/state/sqlite"
)

const readHeaderTimeout = 10 * time.Second

type serveParams struct {
	fx.In

	Logger    *zap.Logger
	Store     *sqlite.Store
	Keys      *keys.Keys
	API       *api.Result
	Readiness *api.Readiness
	Listener  xloadtype.Listener `name:"http"`
}

func newServeCmd(p serveParams) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the tempogate HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if err := p.Store.Ping(ctx); err != nil {
				return fmt.Errorf("state store unreachable: %w", err)
			}
			if err := p.Store.IsCurrent(ctx); err != nil {
				return err
			}

			// Load (or bootstrap) the signing keypair before the listener
			// binds so /.well-known/jwks.json serves the active key from the
			// first accepted request.
			if err := p.Keys.Init(ctx); err != nil {
				return fmt.Errorf("keys init: %w", err)
			}

			mux := http.NewServeMux()
			if p.API.Prefix == "" {
				mux.Handle("/", p.API.Handler)
			} else {
				mux.Handle(p.API.Prefix+"/", http.StripPrefix(p.API.Prefix, p.API.Handler))
			}

			addr := p.Listener.String()
			logger := p.Logger.Named("server")

			return xrun.All(
				xrun.NoTimeout,
				httpServer(httpServerOptions{
					server: &http.Server{
						Addr:              addr,
						Handler:           mux,
						ReadHeaderTimeout: readHeaderTimeout,
					},
					onListening: func() {
						logger.Info("starting http server", zap.String("addr", addr))
						p.Readiness.Mark()
					},
					onStopping: func() {
						logger.Info("stopping http server", zap.String("addr", addr))
					},
				}),
			).Run(ctx)
		},
	}
}
