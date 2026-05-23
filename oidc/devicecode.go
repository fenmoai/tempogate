package oidc

import "time"

// DeviceCode is the per-flow row backing RFC 8628 — OAuth 2.0 Device
// Authorization Grant. It is created when a headless client posts to
// /device_authorization (§3.1), then transitions through pending → approved
// (or denied) as the user completes the verification flow on a second
// device, and is finally consumed by the polling /token call (§3.4) that
// mints the JWT.
//
// Code is the long, machine-side token the polling client presents; UserCode
// is the short, human-typeable token shown on the device and entered on the
// verification page (already normalised — uppercase, no dashes — so a lookup
// is a plain UNIQUE-index probe).
//
// Email is empty until Approve stamps the authenticated user onto the row;
// ApprovedAt and DeniedAt carry the pending → approved/denied transition,
// with both nil meaning "still awaiting user action". LastPolledAt and
// IntervalSeconds back the server-enforced slow_down rule (§3.5): a poll
// arriving sooner than IntervalSeconds since the last one returns slow_down
// and bumps the stored interval by +5.
type DeviceCode struct {
	Code            string
	UserCode        string
	ClientID        string
	Scope           string
	Email           string
	ApprovedAt      *time.Time
	DeniedAt        *time.Time
	LastPolledAt    *time.Time
	IntervalSeconds int

	CreatedAt time.Time
	ExpiresAt time.Time
}
