package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func newKeysCmd(p RunParams) *cobra.Command {
	root := &cobra.Command{
		Use:   "keys",
		Short: "Manage tempogate signing keys",
	}
	root.AddCommand(newKeysGenerateCmd(p))
	return root
}

func newKeysGenerateCmd(p RunParams) *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "generate",
		Short: "Generate the JWT signing keypair (fails if one exists; use --force to rotate)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if err := p.Store.Ping(ctx); err != nil {
				return fmt.Errorf("state store unreachable: %w", err)
			}
			if err := p.Store.IsCurrent(ctx); err != nil {
				return err
			}

			kp, err := p.Keys.Generate(ctx, force)
			if err != nil {
				return err
			}

			cmd.Printf("generated keypair: kid=%s alg=%s created_at=%s\n",
				kp.Kid, kp.Alg, kp.CreatedAt.UTC().Format(time.RFC3339))
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "rotate by adding a new keypair even if one already exists")
	return c
}
