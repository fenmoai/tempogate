## What

<!-- One or two sentences. What does this PR change? -->

## Why

<!-- Link the issue / RFC / Linear ticket. If there's no issue, explain the
     motivation here. -->

Fixes #

## How

<!-- Brief notes on the approach. Call out anything that needed judgment:
     trade-offs, alternatives considered, surprising bits. -->

## Test plan

<!-- What did you actually run? -->

- [ ] `make ci` is green locally
- [ ] New behavior is covered by tests (red → green)
- [ ] Manually verified against a running `tempogate serve` (if relevant)

## Checklist

- [ ] Commits are signed off (`git commit -s`) — see [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] No issue/ticket IDs leaked into Pydantic-style docstrings or generated OpenAPI
- [ ] `make check` clean (formatting, imports, vet)
- [ ] Updated `README.md` / `CONTRIBUTING.md` if behavior or workflow changed
