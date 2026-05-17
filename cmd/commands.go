package cmd

import "go.uber.org/fx"

// asCommand annotates a *cobra.Command-returning constructor so its result is
// fed into the "commands" value group consumed by the root dispatcher.
func asCommand(constructor any) any {
	return fx.Annotate(constructor, fx.ResultTags(`group:"commands"`))
}

// CLICommandsFx provides the subcommands present in every build, including the
// lean CLI: they depend only on the logger / buildinfo, never on server
// modules. Server-bound subcommands (serve, migrate, keys) are provided
// separately by cmd/servercmd, wired only by the full app assembly.
func CLICommandsFx() fx.Option {
	return fx.Provide(
		asCommand(newVersionCmd),
		asCommand(newLoginCmd),
		asCommand(newTokenCmd),
	)
}
