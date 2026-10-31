# AGENTS.md

## Project overview

A Git credential helper that authenticates to any OAuth-protected Git host using standard RFCs, with no hardcoded provider knowledge.

## Repository layout
- `cmd/` - entrypoints for commands; should only include minimal code then call Execute of the relevant package
- `internal/` - application packages; not importable by other modules
- `pkg/` - application packages; importable by others

## Build, test, lint
Run these before considering any change complete:
- Build: `go build ./...`
- Test: `go test -race ./...`
- Vet: `go vet ./...`
- Lint: `golangci-lint run`
- Format: `gofmt -s -w .`; never commit unformatted code

## Code conventions
- Go version: [1.26], per `go.mod`. Don't bump it unless asked.
- Logging: use `log/slog` with structured key/value attributes. No `fmt.Println` or `log.Printf` in service code.
- Errors: wrap with `fmt.Errorf("doing x: %w", err)`. Return errors rather than logging and continuing, unless at the top level or the parent contains a `*slog.Logger`.
- Context: pass `context.Context` as the first parameter for anything doing I/O; respect cancellation.
- Concurrency: guard shared state with `sync.RWMutex` (or channels). Run tests with `-race`.
- Interfaces: define them where they're consumed, keep them small. Decorators (caching, metrics) wrap the interface rather than modifying the implementation.
- Dependencies: prefer the standard library. Ask before adding a new module dependency. Run `go mod tidy` after any dependency change.

## Documentation
- Command line flag or behaviour changes must be reflected in `README.md`

## Testing
- Table-driven tests with `t.Run` subtests.
- Use fakes implementing the package interfaces; no network or external services in unit tests.
- New behaviour needs a test; bug fixes need a test that fails without the fix.

## Releases
- Releases are prepared by release-please (`release-please-config.json`, `.release-please-manifest.json`), which keeps a `chore(release): vX.Y.Z` PR open with the version bump and `CHANGELOG.md` entry, derived from conventional commit messages on `main`.
- Merging the release PR creates the `vX.Y.Z` tag and GitHub release; the tag triggers GoReleaser, which adds the artifacts to that release.
- Don't edit `CHANGELOG.md` or `.release-please-manifest.json` by hand; release-please maintains them.
- PRs are squash merged with the PR title as the commit message, so PR titles must be conventional commits (`feat:`, `fix(scope):`, `feat!:` for breaking changes); the PR title check enforces this. Only `feat`, `fix`, `perf`, `revert` and breaking changes trigger a release.
- Never delete, move, or force-push an existing tag. The Go module proxy caches versions immutably, so a retagged version won't be picked up. Fix forward with a new patch version.
- Don't edit `.goreleaser.yaml` or CI config unless the task is specifically about them.
- Do not create or push a tag unless specifically directed to as this triggers the release workflow.

## Boundaries
- Don't commit secrets, tokens, or real config values.
- Don't modify generated files; regenerate them with `go generate ./...`.
- Keep changes scoped to the task. No drive-by refactors or renames.

## Agent skills

### Issue tracker

Issues are tracked in this repo's GitHub Issues (andrewheberle/git-credential-oauth-generic). See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` plus `docs/adr/` at the repo root (created lazily). See `docs/agents/domain.md`.
