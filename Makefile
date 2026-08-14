# TableX — build, test and packaging targets.
# Assets are embedded via go:embed; everything builds with the Go toolchain only.

VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
BIN     := bin/tablex
# Extra flags for the cover target's go test run. CI passes "-race -v";
# locally it defaults to empty because -race needs a C toolchain (see racetest).
GOTESTFLAGS ?=

.PHONY: all build run test racetest cover cover-floor vet fmt fmt-check lint vuln clean cross docker

all: lint test build

build: ## Build the single binary for the host platform
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/tablex

run: ## Run locally on :8080
	go run ./cmd/tablex

test: ## Run the unit + integration test suite (SQLite, no Docker needed)
	go test ./...

racetest: ## Run the test suite under the race detector (CI parity; needs a C toolchain)
	CGO_ENABLED=1 go test -race ./...

cover: ## Run tests with cross-package coverage (CI parity: make cover GOTESTFLAGS="-race -v")
	go test $(GOTESTFLAGS) -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# -coverpkg=./... so the cross-package exercise counts: internal/server drives
# the handlers and drivers over real HTTP, and per-package coverage would credit
# none of it. The floor is a ratchet, not a target — raise it when it is beaten,
# never lower it to make a red build green.
cover-floor: ## Enforce the coverage floor over coverage.out (run `make cover` first)
	@test -f coverage.out || { echo "coverage.out missing — run 'make cover' first"; exit 1; }
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {print $$3}' | tr -d '%'); \
	echo "total coverage: $${total}%"; \
	if awk -v t="$$total" 'BEGIN { exit !(t + 0 < 55) }'; then \
		echo "::error::coverage $${total}% is below the 55% floor"; \
		exit 1; \
	fi

vet: ## go vet
	go vet ./...

fmt: ## Format all Go code
	gofmt -w internal cmd web

fmt-check: ## Fail if any Go file needs gofmt (no rewriting)
	@test -z "$$(gofmt -l internal cmd web)" || (echo "gofmt needed:"; gofmt -l internal cmd web; exit 1)

lint: fmt-check vet ## Format check + vet + staticcheck (CI gate; needs staticcheck on PATH)
	staticcheck ./...

vuln: ## Scan for known vulnerabilities (requires govulncheck)
	govulncheck ./...

clean:
	rm -rf bin dist coverage.out

# Cross-compiled release binaries for every released platform. The target list
# and the tablex_$(VERSION)_os_arch naming mirror release.yml — one contract,
# two producers, so a local `make cross` reproduces the BINARIES a tag ships.
# Only the binaries: a tag also publishes archives (binary + LICENSE +
# THIRD-PARTY-NOTICES), .deb/.rpm packages, an SBOM, signed checksums and an
# image. This target is for checking that every target still compiles.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
cross: ## Build reproducible release binaries into dist/
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o dist/tablex_$(VERSION)_$${os}_$${arch}$$ext ./cmd/tablex; \
	done

docker: ## Build the distroless Docker image
	docker build --build-arg VERSION=$(VERSION) -t tablex:$(VERSION) .
