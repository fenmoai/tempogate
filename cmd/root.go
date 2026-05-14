package cmd

import (
	"github.com/spf13/cobra"
)

type rootConfig struct {
	subcommands []*cobra.Command
}

type Option func(*rootConfig)

// WithSubcommand registers an additional cobra subcommand on the root.
// Bootstrap subcommands (version) are always registered; this hook is for
// future packages (serve, login, keys, migrate) to add their own.
func WithSubcommand(c *cobra.Command) Option {
	return func(cfg *rootConfig) { cfg.subcommands = append(cfg.subcommands, c) }
}

func NewRootCmd(opts ...Option) *cobra.Command {
	cfg := &rootConfig{}
	for _, o := range opts {
		o(cfg)
	}

	rootCmd := &cobra.Command{
		Use:           "tempogate",
		Short:         "OIDC + OAuth2 authorization server for self-hosted Temporal",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(newVersionCmd())
	for _, sc := range cfg.subcommands {
		rootCmd.AddCommand(sc)
	}
	return rootCmd
}
