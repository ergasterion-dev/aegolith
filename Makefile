GO ?= go
ADAPTERS := adapters/fiberv2
# Packages (relative to the root module) that hold Fuzz targets.
FUZZ_PKGS := . ./internal/normalize
FUZZTIME ?= 10s

.PHONY: build test test-quick vet fmt fmt-check bench fuzz-quick corpus perf ci

build:
	CGO_ENABLED=0 $(GO) build ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) build ./...; fi

# Both runs are needed: -race catches data races, and the plain run executes
# the checks that only make sense at full speed (TestScanTextLinear's growth
# ratio is skipped under -race).
test:
	$(GO) test -race ./...
	$(GO) test ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) test -race ./... && $(GO) test ./...; fi

test-quick:
	$(GO) test ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) test ./...; fi

vet:
	$(GO) vet ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) vet ./...; fi

# Only tracked Go files: "." would also walk scratch directories such as
# .superpowers/.
fmt:
	git ls-files -z '*.go' | xargs -0 gofmt -w

fmt-check:
	@out=$$(git ls-files -z '*.go' | xargs -0 gofmt -l); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) test -run '^$$' -bench . -benchmem ./...; fi

# Runs every Fuzz target in FUZZ_PKGS for FUZZTIME each.
fuzz-quick:
	@for p in $(FUZZ_PKGS); do \
		for t in $$($(GO) test -list '^Fuzz' $$p | grep '^Fuzz'); do \
			echo "== $$p $$t"; \
			$(GO) test -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME) $$p || exit 1; \
		done; \
	done

corpus:
	$(GO) test -run Corpus -v .

# Latency budget (spec: p99 < 50 µs per legit request on one core). Never
# under -race.
perf:
	AEGOLITH_PERF=1 $(GO) test -run LatencyBudget -count=1 -v .

ci: fmt-check vet test corpus
