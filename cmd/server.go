package cmd

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/gojekfarm/xrun"
)

type httpServerOptions struct {
	server *http.Server

	// onListening fires after net.Listen succeeds and before Serve starts
	// accepting. Use this to flip /readyz, expose the bound port, etc.
	onListening func()

	// onStopping fires when ctx is cancelled, before srv.Shutdown is called.
	onStopping func()
}

// httpServer returns an xrun.ComponentFunc that binds the listener up-front
// (so onListening fires only once the OS confirms we're holding the port,
// preserving accurate /readyz semantics), serves until ctx cancels, then
// gracefully Shuts down.
//
// Compared to xrun/component.HTTPServer this trades the convenience of
// ListenAndServe for the ability to observe a successful bind separately
// from the goroutine that runs Serve.
func httpServer(opts httpServerOptions) xrun.ComponentFunc {
	return func(ctx context.Context) error {
		lis, err := net.Listen("tcp", opts.server.Addr)
		if err != nil {
			return err
		}
		if opts.onListening != nil {
			opts.onListening()
		}

		errCh := make(chan error, 1)
		go func() {
			if err := opts.server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()

		select {
		case <-ctx.Done():
		case err := <-errCh:
			return err
		}

		if opts.onStopping != nil {
			opts.onStopping()
		}
		return opts.server.Shutdown(context.Background())
	}
}
