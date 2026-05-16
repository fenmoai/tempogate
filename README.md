# tempogate

> Drop-in **OIDC provider** and **OAuth2 authorization server** for self-hosted [Temporal](https://temporal.io/).

[![ci](https://github.com/fenmoai/tempogate/actions/workflows/ci.yml/badge.svg)](https://github.com/fenmoai/tempogate/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/fenmoai/tempogate.svg)](https://pkg.go.dev/github.com/fenmoai/tempogate)

---

## Why

Self-hosted Temporal ships two extension points: the Web UI consumes any OIDC issuer via `TEMPORAL_AUTH_*` env vars, and the gRPC frontend verifies JWTs via a configurable JWKS endpoint and a `permissions: ["<namespace>:<action>", ...]` claim. Together they cover the SSO + machine-auth story **without forking `temporal-server` and without a sidecar reverse proxy** — provided someone supplies the issuer.

`tempogate` is that issuer. Point your Web UI at `https://tempogate.<your-domain>` and your frontend's `global.authorization.jwtKeyProvider.keySourceURIs` at `https://tempogate.<your-domain>/.well-known/jwks.json`. Mint long-lived integration keys via an admin API; mint 4-hour personal tokens via `tempogate login` from a developer laptop. Multi-tenant namespace scoping is in the JWT itself.

## Architecture

```
┌──────────────┐     OIDC      ┌────────────────────┐
│ Temporal Web │ ─────────────▶│      tempogate     │ ──wraps──▶ Google OAuth2
│      UI      │◀── our JWT ───│  (OIDC + OAuth2 AS)│
└──────┬───────┘               └────────────────────┘
       │ Bearer <tempogate JWT>          ▲
       ▼                                 │
┌──────────────┐         JWKS            │
│  temporal-   │ ◀───────────────────────┘
│  frontend    │  (stock default JWT ClaimMapper)
└──────────────┘
```

A single binary, distroless-shipped, with subcommands `serve`, `login`, `keys`, `migrate`, `version`. State is pluggable; the default is SQLite-on-PVC via pure-Go `modernc.org/sqlite`.

## Quick start

> **Status:** v0 — `/healthz`, `/readyz`, `/.well-known/jwks.json`, and a partial `/.well-known/openid-configuration` are wired. The SSO flow endpoints (authorize / token / userinfo) land in subsequent releases.

Once a release is cut, pull a tagged multi-arch image:

```bash
docker run --rm -p 8000:8000 ghcr.io/fenmoai/tempogate:latest
curl http://127.0.0.1:8000/healthz
```

Image tags:

| Tag | Meaning |
| --- | --- |
| `:vX.Y.Z`, `:X.Y`, `:X`, `:latest` | Stable releases (pushed on `git tag vX.Y.Z`) |
| `:vX.Y.Z-rc.N` | Pre-releases |
| `:sha-<short>` | One-off builds dispatched manually from a specific commit |

Until the first tag is cut, build from source:

```bash
git clone git@github.com:fenmoai/tempogate.git
cd tempogate
make build
./.bin/tempogate serve            # listens on 127.0.0.1:8000
```

Or build the container locally:

```bash
docker build -t tempogate:dev .
docker run --rm -p 8000:8000 tempogate:dev
```

A `docker-compose` example wiring tempogate alongside `temporalio/server` + `temporalio/ui` lands in `examples/docker-compose/` once E3 (OIDC) ships.

## Configuration

Configuration is layered: defaults → optional `application.yaml` → environment variables (env wins). Nested keys flatten with `__` as the separator.

| Env var          | Default          | Notes                                |
| ---------------- | ---------------- | ------------------------------------ |
| `LOG__LEVEL`     | `info`           | `debug` / `info` / `warn` / `error`  |
| `HTTP__LISTENER` | `127.0.0.1:8000` | `host:port` for the public listener |
| `OIDC__ISSUER`   | `http://127.0.0.1:8000` | Externally reachable base URL; advertised as `issuer` and used to derive `jwks_uri` in the discovery document (e.g. `https://tempogate.internal.<domain>`) |

More keys (admin listener, JWKS storage, upstream Google client) arrive with their respective releases.

## Why not a sidecar proxy or a forked Temporal?

| Approach                                   | Pros                                                              | Cons                                                                                                |
| ------------------------------------------ | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **tempogate (OIDC + OAuth2 AS, this repo)** | Stateless integration with stock Temporal. No fork, no proxy.     | A second component to operate.                                                                      |
| Sidecar reverse-proxy in front of UI/gRPC | Auth logic outside Temporal.                                      | Has to demux gRPC + HTTP; brittle around streaming; obscures Temporal's own auth machinery.         |
| Forked `temporal-server`                  | Total control.                                                    | Permanent rebase tax; loses Temporal upstream support; defeats "self-hosted but supported" posture. |

Tempogate is the path Temporal's own docs already bless — it just hadn't been packaged.

## Development

```bash
make tools         # install pinned gci + golangci-lint into ./.bin
make check         # fmt + vet + gci; fails on dirty tree
make lint          # golangci-lint
make test          # check + race + coverage
make ci            # what GitHub Actions runs
```

Go 1.26+ required. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/fenmoai/tempogate/security/advisories/new) — see [SECURITY.md](SECURITY.md). **Do not** open public issues for security reports.

## License

Apache 2.0 — see [LICENSE](LICENSE).
