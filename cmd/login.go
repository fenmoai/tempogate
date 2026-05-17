package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/fenmoai/tempogate/cli"
)

// issuerEnvVar is the client-side issuer override. It is deliberately distinct
// from the server's OIDC__ISSUER: `tempogate login` runs on a developer laptop
// and points at a *remote* tempogate, so it carries its own env var rather
// than reusing server configuration that is irrelevant on a client.
const issuerEnvVar = "TEMPOGATE__ISSUER"

// loginRunner builds the loopback Flow and runs it. It is a package var purely
// so tests can drive the command against a mock issuer without launching a
// real system browser; production code never reassigns it.
var loginRunner = func(ctx context.Context, opts ...cli.Option) (string, time.Time, error) {
	return cli.New(opts...).Run(ctx)
}

func newLoginCmd(p RunParams) *cobra.Command {
	var issuer, clientID string
	var port int

	c := &cobra.Command{
		Use:   "login",
		Short: "Sign in via browser and print a personal Temporal JWT",
		Long: "Starts a one-shot loopback HTTP server, opens the system browser to\n" +
			"the tempogate issuer, completes the OIDC authorization-code flow, and\n" +
			"prints the access token to stdout. Progress is written to stderr, so\n" +
			"  export TEMPORAL_AUTH_TOKEN=$(tempogate login)\n" +
			"captures just the token.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if issuer == "" {
				issuer = os.Getenv(issuerEnvVar)
			}
			if issuer == "" {
				return fmt.Errorf("issuer is required: pass --issuer or set %s", issuerEnvVar)
			}

			logger := p.Logger.Named("login")
			logger.Info("starting loopback login", zap.String("issuer", issuer))

			token, expiresAt, err := loginRunner(cmd.Context(),
				cli.WithIssuer(issuer),
				cli.WithPort(port),
				cli.WithClientID(clientID),
				cli.WithOutput(cmd.ErrOrStderr()),
			)
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Signed in. Token valid until %s.\n",
				expiresAt.Format(time.RFC3339))
			cmd.Println(token)
			return nil
		},
	}

	c.Flags().StringVar(&issuer, "issuer", "", fmt.Sprintf("tempogate base URL (default $%s)", issuerEnvVar))
	c.Flags().IntVar(&port, "port", 0, "loopback port (0 = a free ephemeral port, recommended)")
	c.Flags().StringVar(&clientID, "client-id", "", "OAuth2 client_id registered with tempogate (default \"tempogate-cli\")")
	return c
}
