// Package log provides a zap-backed logger and a slog handler that share the
// same core, so callers can pick either API and still emit through one sink.
package log

import (
	"io"
	"log/slog"
	"os"

	"go.uber.org/fx"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

// Level is a string log level (e.g. "debug", "info", "warn", "error").
// Defined here so config can expose it without importing zap.
type Level string

type Params struct {
	fx.In

	Level Level
	Sink  io.Writer `optional:"true"`
}

type Result struct {
	fx.Out

	Zap  *zap.Logger
	Slog *slog.Logger
}

func New(p Params) (Result, error) {
	lvl, err := zapcore.ParseLevel(string(p.Level))
	if err != nil {
		return Result{}, err
	}

	sink := p.Sink
	if sink == nil {
		sink = os.Stdout
	}

	enc := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	core := zapcore.NewCore(enc, zapcore.Lock(zapcore.AddSync(sink)), lvl)

	return Result{
		Zap:  zap.New(core),
		Slog: slog.New(zapslog.NewHandler(core, zapslog.WithCaller(true))),
	}, nil
}
