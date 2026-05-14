package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func Fx() fx.Option {
	return fx.Options(
		fx.Provide(func() *cobra.Command { return NewRootCmd() }),
		fx.Invoke(Run),
	)
}

// Run is the cobra dispatcher fx invokes after the graph builds.
//
// On lifecycle start, it executes the root command in a goroutine and signals
// shutdown when the command returns. One-shot commands (version) exit cleanly
// this way. Long-running commands (serve, E1.3) will register their own OnStop
// hooks for server lifecycle and block until shutdown.
func Run(lc fx.Lifecycle, sd fx.Shutdowner, rootCmd *cobra.Command) {
	lc.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			go func() {
				if err := rootCmd.Execute(); err != nil {
					_ = sd.Shutdown(fx.ExitCode(1))
					return
				}
				_ = sd.Shutdown()
			}()
			return nil
		},
	})
}
