package cmd

import (
	"go.uber.org/fx"
	"go.uber.org/zap"
)

func wrapShutdowner(sh fx.Shutdowner, l *zap.Logger) func(error) {
	return func(err error) {
		if err := sh.Shutdown(fx.ExitCode(1)); err != nil {
			l.Error("error shutting down", zap.Error(err))
		}
	}
}
