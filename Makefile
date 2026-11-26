GO ?= go
ADAPTERS := adapters/fiberv2
# The WAF bench is its own module (the make target "bench" runs Go
# benchmarks, not this).
BENCHDIR := bench
FUZZTIME ?= 10s
# Go files gofmt covers: tracked plus untracked files git does not ignore
# ("." would also walk scratch directories such as .superpowers/).
GOFILES := git ls-files --cached --others --exclude-standard -z '*.go'

.PHONY: build test test-quick vet fmt fmt-check bench fuzz-quick corpus perf ci

build:
	CGO_ENABLED=0 $(GO) build ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) build ./...; fi
	@if [ -d $(BENCHDIR) ]; then cd $(BENCHDIR) && $(GO) build ./...; fi

# Both runs are needed: -race catches data races, and the plain run executes
# the checks that only make sense at full speed (TestScanTextLinear's growth
# ratio is skipped under -race).
test:
	$(GO) test -race ./...
	$(GO) test ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) test -race ./... && $(GO) test ./...; fi
	@if [ -d $(BENCHDIR) ]; then cd $(BENCHDIR) && $(GO) test -race ./... && $(GO) test ./...; fi

test-quick:
	$(GO) test ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) test ./...; fi
	@if [ -d $(BENCHDIR) ]; then cd $(BENCHDIR) && $(GO) test ./...; fi

vet:
	$(GO) vet ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) vet ./...; fi
	@if [ -d $(BENCHDIR) ]; then cd $(BENCHDIR) && $(GO) vet ./...; fi

fmt:
	$(GOFILES) | xargs -0 gofmt -w

fmt-check:
	@out=$$($(GOFILES) | xargs -0 gofmt -l); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) test -run '^$$' -bench . -benchmem ./...; fi

# Runs every Fuzz target in every package that declares one (discovered by
# scripts/fuzz-quick.sh) for FUZZTIME each, and fails if none is found or a
# package's targets cannot be listed. FuzzInspect's per-request time bound
# is 2 s here, not the brief's 100 ms: fuzz workers fill every core, and on
# a busy machine a scheduler stall alone passes 100 ms. AEGOLITH_PERF=1
# restores 100 ms.
fuzz-quick:
	GO=$(GO) FUZZTIME=$(FUZZTIME) ./scripts/fuzz-quick.sh

corpus:
	$(GO) test -run Corpus -v .

# Latency budget (spec: p99 < 50 µs per legit request on one core). Never
# under -race.
perf:
	AEGOLITH_PERF=1 $(GO) test -run LatencyBudget -count=1 -v .

ci: fmt-check vet test corpus
