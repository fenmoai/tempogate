package cmd

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/gojekfarm/xrun"
)

type httpServerOptions struct {
	Server *http.Server

	// OnListening fires after net.Listen succeeds and before Serve starts
	// accepting. Use this to flip /readyz, expose the bound port, etc.
	OnListening func()

	// OnStopping fires when ctx is cancelled, before srv.Shutdown is called.
	OnStopping func()
}

// httpServer returns an xrun.ComponentFunc that binds the listener up-front
// (so OnListening fires only once the OS confirms we're holding the port,
// preserving accurate /readyz semantics), serves until ctx cancels, then
// gracefully Shuts down.
//
// Compared to xrun/component.HTTPServer this trades the convenience of
// ListenAndServe for the ability to observe a successful bind separately
// from the goroutine that runs Serve.
func httpServer(opts httpServerOptions) xrun.ComponentFunc {
	return func(ctx context.Context) error {
		lis, err := net.Listen("tcp", opts.Server.Addr)
		if err != nil {
			return err
		}
		if opts.OnListening != nil {
			opts.OnListening()
		}

		errCh := make(chan error, 1)
		go func() {
			if err := opts.Server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()

		select {
		case <-ctx.Done():
		case err := <-errCh:
			return err
		}

		if opts.OnStopping != nil {
			opts.OnStopping()
		}
		return opts.Server.Shutdown(context.Background())
	}
}
