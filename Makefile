.PHONY: build test race vet fmt check manifest clean

# Cross-compile all platform binaries and regenerate the integrity manifest.
build:
	./build.sh

# Run the full test suite.
test:
	go test ./...

# Run tests with the race detector.
race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w *.go cmd internal

# What CI enforces: formatting, vet, the generated-KB freshness check, and the race suite.
check:
	@test -z "$$(gofmt -l *.go cmd internal)" || (echo "gofmt needed:"; gofmt -l *.go cmd internal; exit 1)
	go run ./cmd/kbgen --check
	go vet ./...
	go test -race ./...

# Regenerate rules_gen.go from rules/*.json (run before build after rule edits).
gen:
	go run ./cmd/kbgen

# Regenerate bin/manifest.sha256 from the current binaries.
manifest:
	./bin/peephole-$$(go env GOOS)-$$(go env GOARCH) genmanifest

clean:
	rm -f bin/.peephole-exe
