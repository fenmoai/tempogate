package cli

// Test-only options. Living in an _test.go file keeps the PKCE-verifier and
// state generators unexported in the production API while letting the external
// cli_test package drive their failure branches deterministically.

// WithVerifierGenerator swaps the PKCE code_verifier generator. For tests.
func WithVerifierGenerator(fn func() (string, error)) Option {
	return func(f *Flow) { f.newVerifier = fn }
}

// WithStateGenerator swaps the CSRF state generator. For tests.
func WithStateGenerator(fn func() (string, error)) Option {
	return func(f *Flow) { f.newState = fn }
}
