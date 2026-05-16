package sqlite

import (
	"context"
	"errors"
	"fmt"

	sqlite3 "modernc.org/sqlite"
	sqlite3lib "modernc.org/sqlite/lib"

	"github.com/fenmoai/tempogate/oidc"
)

// ErrDuplicateInternalState is returned by SaveAuthRequest when an auth
// request with the given internal_state already exists. With 256 bits of
// entropy a collision is not expected; callers may still distinguish it.
var ErrDuplicateInternalState = errors.New("sqlite: auth request with this internal_state already exists")

func (s *Store) SaveAuthRequest(ctx context.Context, ar oidc.AuthRequest) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_requests
		   (internal_state, client_id, redirect_uri, scope, client_state,
		    code_challenge, code_challenge_method, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ar.InternalState, ar.ClientID, ar.RedirectURI, ar.Scope, ar.ClientState,
		ar.CodeChallenge, ar.CodeChallengeMethod, ar.CreatedAt, ar.ExpiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return fmt.Errorf("%w: %s", ErrDuplicateInternalState, ar.InternalState)
		}
		return fmt.Errorf("sqlite: save auth request: %w", err)
	}
	return nil
}
