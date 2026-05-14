package api

import "sync/atomic"

// Readiness is a process-wide flag toggled when the HTTP server has bound
// its listener and is accepting connections. /readyz reads it; the serve
// command flips it via Mark() once the listener is up.
type Readiness struct {
	ready atomic.Bool
}

func NewReadiness() *Readiness { return &Readiness{} }

func (r *Readiness) Mark()         { r.ready.Store(true) }
func (r *Readiness) IsReady() bool { return r.ready.Load() }
