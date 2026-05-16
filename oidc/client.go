package oidc

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrUnknownClient is returned when a client_id is not in the registry.
	ErrUnknownClient = errors.New("oidc: unknown client_id")
	// ErrRedirectURINotAllowed is returned when a redirect_uri is empty or
	// does not fall under the client's registered prefix.
	ErrRedirectURINotAllowed = errors.New("oidc: redirect_uri not under registered prefix")
)

// ClientRegistry is the v1 client allowlist: client_id → redirect_uri prefix.
// There is no admin UI; it is populated once from the OIDC__CLIENTS env var.
type ClientRegistry map[string]string

// ParseClientRegistry parses a comma-separated list of "id:redirect_uri_prefix"
// entries. Only the first ':' of an entry splits id from prefix, so the prefix
// keeps its scheme (e.g. "ui:https://app.example.com/cb"). An empty string
// yields an empty registry. Malformed or duplicate entries are an error so a
// misconfiguration fails fast at graph construction rather than per request.
func ParseClientRegistry(raw string) (ClientRegistry, error) {
	reg := ClientRegistry{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, prefix, ok := strings.Cut(entry, ":")
		if !ok || id == "" || prefix == "" {
			return nil, fmt.Errorf("oidc: malformed client entry %q (want id:redirect_uri_prefix)", entry)
		}
		if _, dup := reg[id]; dup {
			return nil, fmt.Errorf("oidc: duplicate client_id %q in registry", id)
		}
		reg[id] = prefix
	}
	return reg, nil
}

// Validate checks that clientID is registered and redirectURI falls under its
// registered prefix. It returns ErrUnknownClient or ErrRedirectURINotAllowed
// so callers can map each to the right OAuth2 error response.
func (r ClientRegistry) Validate(clientID, redirectURI string) error {
	prefix, ok := r[clientID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownClient, clientID)
	}
	if redirectURI == "" || !strings.HasPrefix(redirectURI, prefix) {
		return fmt.Errorf("%w: %s", ErrRedirectURINotAllowed, redirectURI)
	}
	return nil
}
