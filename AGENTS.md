# Repository Guidelines

## Project Structure & Module Organization

The root `goauth` package defines `User`, `Identity`, capability interfaces, and errors. Platform adapters live in `wechat/`, `qq/`, `douyin/`, `weibo/`, `alipay/`, `github/`, `google/`, and `facebook/`. Shared HTTP handling belongs in `internal/httpx/`; test helpers belong in `internal/testutil/`. Tests sit beside source files as `*_test.go`. `examples/login/` contains the runnable CLI example.

Before changing platform protocols, consult `docs/protocols.md`. For domain terminology or architectural changes, consult `GLOSSARY.md`, `docs/design.md`, and `docs/adr/`, updating relevant documents alongside implementation.

## Build, Test, and Development Commands

Use Go 1.22 or later. Run commands from the repository root:

- `go build ./...` — compile all packages and the example.
- `go test ./...` — run local, simulated HTTP tests.
- `go test ./wechat -run TestExchange` — focus on one adapter.
- `go test -race ./...` — check concurrent behavior.
- `go test -cover ./...` — inspect coverage.
- `go vet ./...` — perform static checks.
- `gofmt -w <changed-files>` — format edited Go files.
- `go run ./examples/login -provider wechat -profile` — exercise a real login using environment configuration documented in `README.md`; output includes tokens.

## Coding Style & Naming Conventions

Use `gofmt` formatting, tab indentation, lowercase package names, and descriptive identifiers. Follow the existing `Config`, `Provider`, and `New` constructor pattern. Keep dependencies limited to the standard library. Implement only supported `CodeExchanger` or `TokenVerifier` capabilities, with `context.Context` and injectable HTTP clients. Return classified errors rather than panicking on unsupported behavior.

## Testing Guidelines

Use Go’s `testing` package and local HTTP servers through `internal/testutil`. Name tests `TestBehavior`, using table-driven subtests for failure variants. Cover application ownership, malformed responses, cancellation, signature failures, raw-data precision, and zero-value results on failure. Tests must not require live credentials. No numeric coverage threshold is defined; add meaningful regression cases for behavior changes.

## Commit & Pull Request Guidelines

There is no commit history yet. Prefer concise, imperative subjects such as `wechat: preserve token response fields`. Keep changes focused. PRs should explain behavior changes, reference relevant issues, identify API or protocol compatibility effects, and list validation commands and results.

## Authentication Boundaries

Account registration, linking, and session issuance belong to callers. Preserve scoped identity keys. `User` intentionally includes tokens; use `User.Identity()` when only identity is needed. Keep credentials out of logs, errors, and committed fixtures.

## Agent-Specific Instructions

For `architecture-review` reports, do not use the `baoyu-design` skill or perform visual validation solely because that skill requires it.
