GO ?= go
ADAPTERS := adapters/fiberv2

.PHONY: build test test-quick vet fmt fmt-check bench fuzz-quick corpus ci

build:
	CGO_ENABLED=0 $(GO) build ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) build ./...; fi

test:
	$(GO) test -race ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) test -race ./...; fi

test-quick:
	$(GO) test ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) test ./...; fi

vet:
	$(GO) vet ./...
	@if [ -d $(ADAPTERS) ]; then cd $(ADAPTERS) && $(GO) vet ./...; fi

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./...

fuzz-quick:
	@for t in $$($(GO) test -list 'Fuzz.*' . | grep '^Fuzz'); do \
		$(GO) test -run '^$$' -fuzz "^$$t$$" -fuzztime 10s . || exit 1; \
	done

corpus:
	$(GO) test -run Corpus -v .

ci: fmt-check vet test corpus
