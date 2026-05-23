package oidc

import "time"

// BrowserSession is the first-party session row indexed by the signed
// HttpOnly cookie that the device-flow verification page sets after the user
// completes the upstream IdP round-trip. SID is the opaque 32-byte random
// identifier (base64url) the cookie carries; Email is the authenticated
// identity bound to it; ExpiresAt is the absolute upper bound on session
// lifetime. TTL enforcement is the handler's concern — the store will hand
// back an expired row without complaint, mirroring AuthCode / Refresh.
type BrowserSession struct {
	SID       string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}
