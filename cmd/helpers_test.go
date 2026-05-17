package cmd

// testWriter discards cobra's stdout/stderr so command tests assert on the
// returned error rather than rendered output.
type testWriter struct{}

func (testWriter) Write(p []byte) (int, error) { return len(p), nil }
