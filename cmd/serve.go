package cmd

import (
	"net/http"

	"github.com/spf13/cobra"
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

			s := &server{
				Server: &http.Server{
					Addr:    p.Listener.String(),
					Handler: mux,
				},
				logger:        p.Logger.Named("server"),
				shutdownOnErr: wrapShutdowner(p.Shutdowner, p.Logger),
				onListening:   p.Readiness.Mark,
			}
			return s.run(cmd.Context())
		},
	}
}
