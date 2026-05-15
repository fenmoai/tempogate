package keys

import (
	"context"
	"fmt"
)

// Init is the boot-flow helper: load all keypairs from the store; if the
// store is empty, generate one and persist it. The in-memory cache is
// populated in CreatedAt-ascending order so Latest returns the most recent.
//
// Init is intentionally separate from the fx graph: long-running commands
// (e.g. serve) opt in by calling Init in their RunE, while one-shot CLIs
// (e.g. keys generate) bypass Init and go straight to Generate.
func (k *Keys) Init(ctx context.Context) error {
	existing, err := k.store.LoadKeypairs(ctx)
	if err != nil {
		return fmt.Errorf("keys: load keypairs: %w", err)
	}

	if len(existing) == 0 {
		kp, err := GenerateKeypair(k.generateOptions()...)
		if err != nil {
			return err
		}
		if err := k.store.SaveKeypair(ctx, kp); err != nil {
			return fmt.Errorf("keys: save keypair: %w", err)
		}
		existing = []Keypair{kp}
	}

	sortByCreatedAt(existing)

	k.mu.Lock()
	k.keypairs = existing
	k.mu.Unlock()
	return nil
}
