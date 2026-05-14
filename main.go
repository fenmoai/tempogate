package main

import (
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/app"
)

func main() {
	fx.New(app.New()).Run()
}
