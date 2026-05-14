package cmd

import (
	"net/http"

	"github.com/gojekfarm/xrun"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newServeCmd(p RunParams) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the tempogate HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
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
					server: &http.Server{Addr: addr, Handler: mux},
					onListening: func() {
						logger.Info("starting http server", zap.String("addr", addr))
						p.Readiness.Mark()
					},
					onStopping: func() {
						logger.Info("stopping http server", zap.String("addr", addr))
					},
				}),
			).Run(cmd.Context())
		},
	}
}
