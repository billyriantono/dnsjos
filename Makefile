# DnsJos build (SPEC §16). Requires Go 1.25 and pnpm.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO      ?= go
LDFLAGS := -s -w -X main.version=$(VERSION)
ARCHES  := amd64 arm64
AGENT_BIN := internal/panel/install/bin
SHA256  := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum -a 256)

export CGO_ENABLED = 0

.PHONY: all release web agent panel test smoke dev clean fmt vet hooks

all: release

# Panel binary with the SPA and both agent binaries embedded.
release: web agent panel

web:
	pnpm -C web install --frozen-lockfile
	pnpm -C web build

# Stripped static agents for the installer (/dl/agent/linux/<arch> + .sha256), plus
# dnsjos-agent.version: the panel reads it to flag nodes with an outdated agent (SPEC §18).
agent:
	@for arch in $(ARCHES); do \
		echo "agent linux/$$arch"; \
		GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(AGENT_BIN)/dnsjos-agent-linux-$$arch ./cmd/dnsjos-agent || exit 1; \
		(cd $(AGENT_BIN) && $(SHA256) dnsjos-agent-linux-$$arch | cut -d' ' -f1 > dnsjos-agent-linux-$$arch.sha256) || exit 1; \
	done
	echo "$(VERSION)" > $(AGENT_BIN)/dnsjos-agent.version

# Embeds the Vite build (web/dist → webdist/dist, never committed) with -tags release.
# Without a web build a plain `go build` embeds webdist/placeholder instead.
panel:
	@test -f web/dist/index.html || { echo "web/dist not built: run make web first"; exit 1; }
	rm -rf webdist/dist && cp -R web/dist webdist/dist
	$(GO) build -tags release -trimpath -ldflags "$(LDFLAGS)" -o bin/dnsjos ./cmd/dnsjos

test:
	$(GO) test ./...
	pnpm -C web typecheck
	pnpm -C web lint

# Every panel route against a real panel + fresh local Postgres DB (see test/smoke/smoke.sh).
smoke:
	GO="$(GO)" test/smoke/smoke.sh

# Panel on :8080 against local Postgres + Vite dev server (proxies /api to the panel).
DEV_DB ?= postgres://$(USER)@127.0.0.1:5432/dnsjos?sslmode=disable
dev:
	trap 'kill 0' EXIT INT TERM; \
	DNSJOS_DATABASE_URL=$(DEV_DB) DNSJOS_DATA_DIR=./data DNSJOS_LOG_LEVEL=debug $(GO) run ./cmd/dnsjos serve & \
	pnpm -C web dev

# Install the git hooks that block deployment data (patterns kept outside the repo).
hooks:
	install -m 0755 scripts/pre-commit .git/hooks/pre-commit
	install -m 0755 scripts/pre-push .git/hooks/pre-push

clean:
	rm -rf bin $(AGENT_BIN)/dnsjos-agent-* $(AGENT_BIN)/dnsjos-agent.version
	rm -rf webdist/dist

fmt:
	gofmt -w cmd internal migrations webdist

vet:
	$(GO) vet ./...
