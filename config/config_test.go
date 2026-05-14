package config

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Defaults(t *testing.T) {
	cfg, err := New(Params{})
	require.NoError(t, err)

	assert.Equal(t, "info", cfg.Log.Level)
	assert.True(t, cfg.HTTP.Listener.IP.Equal(net.IPv4(127, 0, 0, 1)),
		"want 127.0.0.1, got %v", cfg.HTTP.Listener.IP)
	assert.Equal(t, 8000, cfg.HTTP.Listener.Port)
}

func TestNew_EnvOverride(t *testing.T) {
	t.Setenv("LOG__LEVEL", "debug")
	t.Setenv("HTTP__LISTENER", "0.0.0.0:9000")

	cfg, err := New(Params{})
	require.NoError(t, err)

	assert.Equal(t, "debug", cfg.Log.Level)
	assert.True(t, cfg.HTTP.Listener.IP.Equal(net.IPv4(0, 0, 0, 0)),
		"want 0.0.0.0, got %v", cfg.HTTP.Listener.IP)
	assert.Equal(t, 9000, cfg.HTTP.Listener.Port)
}
