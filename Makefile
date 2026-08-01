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
	gofmt -w *.go

# What CI enforces: formatting, vet, and the race suite.
check:
	@test -z "$$(gofmt -l *.go)" || (echo "gofmt needed:"; gofmt -l *.go; exit 1)
	go vet ./...
	go test -race ./...

# Regenerate bin/manifest.sha256 from the current binaries.
manifest:
	./bin/peephole-$$(go env GOOS)-$$(go env GOARCH) genmanifest

clean:
	rm -f bin/.peephole-exe
