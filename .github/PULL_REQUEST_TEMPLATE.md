<!-- Thanks! Two minutes here saves a review round-trip. -->

## What & why

<!-- What changes, and the reason it should. If it fixes an issue: Fixes #NNN -->

## Checklist

- [ ] The gates are green locally: `gofmt -l internal cmd web` prints nothing,
      `go vet ./...`, `staticcheck ./...`, `go test ./...`, `go build ./...`
- [ ] Touching a driver? The live tests ran for real (they **skip silently**
      without `TABLEX_TEST_*` variables — a skipped test is not a passing one)
- [ ] Behavior changes come with the test that would have caught the bug
- [ ] Docs updated in the same commit where they describe what changed

See [CONTRIBUTING](../CONTRIBUTING.md) for the conventions reviewers hold the
line on (SQL safety, the `Dialect` boundary, CSRF on state changes, no new
dependencies without justification).
