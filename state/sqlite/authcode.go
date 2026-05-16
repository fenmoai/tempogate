package sqlite

import (
	"context"
	"errors"
	"fmt"

	sqlite3 "modernc.org/sqlite"
	sqlite3lib "modernc.org/sqlite/lib"

	"github.com/fenmoai/tempogate/oidc"
)

// ErrDuplicateAuthCode is returned by SaveAuthCode when a code with the same
// value already exists. With 256 bits of entropy a collision is not expected;
// callers may still distinguish it.
var ErrDuplicateAuthCode = errors.New("sqlite: auth code with this value already exists")

func (s *Store) SaveAuthCode(ctx context.Context, ac oidc.AuthCode) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_codes
		   (code, client_id, redirect_uri, email, scope,
		    code_challenge, code_challenge_method, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ac.Code, ac.ClientID, ac.RedirectURI, ac.Email, ac.Scope,
		ac.CodeChallenge, ac.CodeChallengeMethod, ac.CreatedAt, ac.ExpiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return fmt.Errorf("%w: %s", ErrDuplicateAuthCode, ac.Code)
		}
		return fmt.Errorf("sqlite: save auth code: %w", err)
	}
	return nil
}
