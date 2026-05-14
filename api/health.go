package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/fenmoai/tempogate/buildinfo"
)

type healthBody struct {
	Status  string `json:"status" example:"ok" doc:"Liveness status"`
	Version string `json:"version" example:"dev" doc:"Build version of the running binary"`
}

type healthOutput struct {
	Body healthBody
}

type readyBody struct {
	Status string `json:"status" example:"ready"`
}

type readyOutput struct {
	Body readyBody
}

func registerHealth(api huma.API, readiness *Readiness) {
	huma.Register(api, huma.Operation{
		OperationID: "healthz",
		Method:      http.MethodGet,
		Path:        "/healthz",
		Summary:     "Liveness probe",
		Tags:        []string{"health"},
	}, func(_ context.Context, _ *struct{}) (*healthOutput, error) {
		return &healthOutput{Body: healthBody{
			Status:  "ok",
			Version: buildinfo.Version(),
		}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "readyz",
		Method:      http.MethodGet,
		Path:        "/readyz",
		Summary:     "Readiness probe (503 until the HTTP listener is bound)",
		Tags:        []string{"health"},
	}, func(_ context.Context, _ *struct{}) (*readyOutput, error) {
		if !readiness.IsReady() {
			return nil, huma.Error503ServiceUnavailable("not ready")
		}
		return &readyOutput{Body: readyBody{Status: "ready"}}, nil
	})
}
