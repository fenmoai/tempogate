# Releasing tempogate

Every release produces **two artifacts** from one trigger:

1. A **multi-arch container image** → `ghcr.io/fenmoai/tempogate` (the full
   server: `serve`/`migrate`/`keys` + all modules), built by the `publish`
   job (Docker buildx + QEMU).
2. A **lean standalone CLI** (`login`/`token`/`version` only — no
   SQLite/OIDC/API code) as GitHub Release assets for `linux`/`darwin` ×
   `amd64`/`arm64` + `checksums.txt`, built by the `binaries` job
   (GoReleaser, `-tags lean`).

Both jobs live in [`.github/workflows/release.yml`](.github/workflows/release.yml)
and fire off the same trigger.

## TL;DR

| Goal | Do this | You get |
| --- | --- | --- |
| **Full release** | `git tag vX.Y.Z && git push origin vX.Y.Z` | Images `:vX.Y.Z` `:X.Y` `:X` `:latest` · published GitHub Release with lean CLI binaries + `checksums.txt` · `Casks/tempogate.rb` bumped on `main` (`brew install tempogate`) |
| **Release candidate** | `git tag vX.Y.Z-rc.N && git push origin vX.Y.Z-rc.N` | Image `:vX.Y.Z-rc.N` only · GitHub Release marked **pre-release** with the same binaries · Homebrew **not** touched |
| **Test / dev build** | Actions → **release** workflow → **Run workflow** → pick branch/SHA | Image `:sha-<short>` · snapshot binaries attached to the **workflow run** (no GitHub Release, ~14-day retention) · Homebrew **not** touched |

## Versioning rules

- Semantic versioning, `v`-prefixed tags: `vMAJOR.MINOR.PATCH`.
- A pre-release suffix (anything after `-`, e.g. `-rc.1`) makes it a
  **release candidate**: GoReleaser auto-marks the GitHub Release as a
  pre-release, the container build suppresses the `:X.Y` / `:X` / `:latest`
  aliases, and the Homebrew cask is **not** updated (`skip_upload: auto`).
- Never move or re-tag a published stable version. To fix a bad stable
  release, cut the next patch (`vX.Y.(Z+1)`).

## Before you tag

1. `main` is green: `make ci` passes (fmt/vet/imports + lint + tests) and the
   "Lean CLI build guard" is happy.
2. Release notes are auto-generated from commit subjects since the previous
   tag, so use Conventional Commits (`feat:`, `fix:`, …). `docs:`, `test:`,
   `chore:`, `ci:` and merge commits are filtered out of the notes.
3. Decide the version bump from the change set; tag the exact commit on `main`
   you want released.

## Cutting it

```bash
git checkout main && git pull
git tag vX.Y.Z            # or vX.Y.Z-rc.N for a candidate
git push origin vX.Y.Z
```

Watch the **release** workflow: the `publish` job pushes the image tags; the
`binaries` job runs GoReleaser. On a stable tag GoReleaser also commits the
regenerated `Casks/tempogate.rb` back to `main` (in-repo Homebrew tap) — that
bot commit is `paths-ignore`d by CI so it doesn't spawn a no-op run, and
`release.yml` has no `push: main` trigger so it doesn't re-fire.

For a **dev build**, don't tag — run the workflow manually and choose the
branch/SHA. You get a `:sha-<short>` image and the binaries as a downloadable
artifact on that workflow run.

## What ships where

- **Container image = full server.** Run `serve`, `migrate`, `keys` and the
  OIDC issuer from the image. These are server/admin operations and need the
  SQLite state store.
- **Downloaded CLI binary = lean client.** `login`, `token`, `version` only.
  It is intentionally ~5 MB smaller with no server/SQLite/OIDC-issuer code —
  smaller download, smaller attack surface, and it never opens a database
  just to mint a token. Don't expect `serve`/`migrate`/`keys` on it.

## Verify a release

```bash
# binaries
gh release download vX.Y.Z --repo fenmoai/tempogate --pattern checksums.txt \
  --pattern 'tempogate_*'
sha256sum -c --ignore-missing checksums.txt
./tempogate version --detailed          # tag / commit / buildDate populated

# container
docker pull ghcr.io/fenmoai/tempogate:vX.Y.Z

# homebrew (stable only): confirm the Casks/tempogate.rb bump landed on main
brew update && brew upgrade tempogate
```

## Homebrew tap

The cask lives in this repository under `Casks/tempogate.rb` (no separate tap
repo, no extra token — GoReleaser pushes it with the workflow's default
`GITHUB_TOKEN`). Users install with:

```bash
brew tap fenmoai/tempogate https://github.com/fenmoai/tempogate
brew install tempogate
```

While the repository is access-restricted, `brew` needs credentials to reach
the private release assets — set `HOMEBREW_GITHUB_API_TOKEN` (a token with
read access) or rely on a configured git credential helper. `gh release
download` works with your existing `gh auth` and needs no extra setup.

If `main` ever becomes branch-protected against direct pushes, switch the
cask to PR mode (the `pull_request:` block is commented in
[`.goreleaser.yaml`](.goreleaser.yaml)) so GoReleaser opens a PR instead of
committing the bump directly.

## Rollback

- Bad **release candidate**: delete the GitHub pre-release and its tag, fix,
  re-tag a higher `-rc.N`.
- Bad **stable**: do not delete or move the tag. Cut `vX.Y.(Z+1)` with the
  fix; `:latest` and the cask move forward on the next stable release.
