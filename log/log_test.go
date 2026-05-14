package log

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNew_BothAPIsEmit(t *testing.T) {
	var buf bytes.Buffer

	r, err := New(Params{Level: Level("info"), Sink: &buf})
	require.NoError(t, err)

	r.Zap.Info("from-zap", zap.String("k1", "v1"))
	r.Slog.Info("from-slog", "k2", "v2")

	out := buf.String()
	assert.Contains(t, out, "from-zap")
	assert.Contains(t, out, "from-slog")
	assert.Contains(t, out, "v1")
	assert.Contains(t, out, "v2")
}

func TestNew_RespectsLevel(t *testing.T) {
	var buf bytes.Buffer

	r, err := New(Params{Level: Level("warn"), Sink: &buf})
	require.NoError(t, err)

	r.Zap.Info("info-suppressed")
	r.Slog.Info("info-suppressed-slog")
	r.Zap.Warn("warn-emitted")

	out := buf.String()
	assert.NotContains(t, out, "info-suppressed")
	assert.NotContains(t, out, "info-suppressed-slog")
	assert.Contains(t, out, "warn-emitted")
}

func TestNew_RejectsBadLevel(t *testing.T) {
	_, err := New(Params{Level: Level("not-a-level")})
	assert.Error(t, err)
}
