package config

import (
	"context"

	"github.com/gojekfarm/xtools/xload"
	"github.com/gojekfarm/xtools/xload/providers/viper"
	"go.uber.org/fx"
)

// Path is an fx-injected optional config-file path. Empty means: search the
// default locations (cwd and three parents) and use whichever yaml is found.
type Path string

type Params struct {
	fx.In

	Path Path `optional:"true"`
}

// New is the fx constructor: applies defaults, layers in yaml + env, and
// returns the resolved *Config. Errors fail fx graph construction.
func New(p Params) (*Config, error) {
	c := defaultConfig()
	if _, err := Load(c, string(p.Path)); err != nil {
		return nil, err
	}
	return c, nil
}

// Load merges defaults (already in `into`) with values from a yaml file (if
// found at `filePath` or under default search paths) and OS env vars. OS env
// wins over yaml. Returns the resolved yaml path actually used (empty if none).
//
// Env keys flatten nested struct prefixes with `__`, e.g. `LOG__LEVEL`,
// `HTTP__LISTENER`.
func Load(into *Config, filePath string) (string, error) {
	opts := []viper.Option{
		viper.ConfigPaths{"./", "../", "../../", "../../../"},
		viper.ValueMapper(func(in map[string]any) map[string]string {
			return xload.FlattenMap(in, "__")
		}),
	}
	if filePath != "" {
		opts = append(opts, viper.ConfigFile(filePath))
	}

	ldr, err := viper.New(opts...)
	if err != nil {
		return "", err
	}

	if err := xload.Load(
		context.Background(),
		into,
		xload.SerialLoader(ldr, xload.OSLoader()),
		xload.SkipCollisionDetection,
	); err != nil {
		return "", err
	}

	return ldr.ConfigFileUsed(), nil
}
