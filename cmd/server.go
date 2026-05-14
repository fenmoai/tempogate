package cmd

import (
	"context"
	"errors"
	"net"
	"net/http"

	"go.uber.org/zap"
)

type server struct {
	*http.Server
	logger        *zap.Logger
	shutdownOnErr func(error)
	onListening   func()
}

func (s *server) start(_ context.Context) error {
	lis, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	if s.onListening != nil {
		s.onListening()
	}
	go s.serve(lis)
	return nil
}

func (s *server) run(ctx context.Context) error {
	if err := s.start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return s.stop(context.Background())
}

func (s *server) serve(lis net.Listener) {
	s.logger.Info("starting http server", zap.String("addr", s.Addr))

	if err := s.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.Error("error at runtime in http server",
			zap.String("addr", s.Addr), zap.Error(err))
		s.shutdownOnErr(err)
	}
}

func (s *server) stop(ctx context.Context) error {
	s.logger.Info("stopping http server", zap.String("addr", s.Addr))
	return s.Shutdown(ctx)
}
