package cmd

import (
	"context"

	xloadtype "github.com/gojekfarm/xtools/xload/type"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/fenmoai/tempogate/api"
)

func Fx() fx.Option { return fx.Invoke(Run) }

// RunParams collects everything cobra subcommands need from the fx graph.
// New deps go here as new subcommands land.
type RunParams struct {
	fx.In

	Lifecycle  fx.Lifecycle
	Shutdowner fx.Shutdowner
	Logger     *zap.Logger

	Listener  xloadtype.Listener `name:"http"`
	API       *api.Result
	Readiness *api.Readiness
}

// Run is the cobra dispatcher fx invokes after the graph builds.
//
// On OnStart it spawns the cobra command in a goroutine; the dispatcher's
// ctx is cancelled on OnStop so long-running subcommands (serve) that block
// on ctx can unwind gracefully. One-shot subcommands (version) finish
// immediately and trigger Shutdowner themselves.
func Run(p RunParams) {
	ctx, cancel := context.WithCancel(context.Background())
	rootCmd := NewRootCmd(WithSubcommand(newServeCmd(p)))
	done := make(chan struct{})

	runCmd := func(ctx context.Context) {
		defer close(done)
		if err := rootCmd.ExecuteContext(ctx); err != nil {
			_ = p.Shutdowner.Shutdown(fx.ExitCode(1))
			return
		}
		_ = p.Shutdowner.Shutdown()
	}

	p.Lifecycle.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			go runCmd(ctx)
			return nil
		},
		OnStop: func(_ context.Context) error {
			cancel()
			<-done
			return nil
		},
	})
}
