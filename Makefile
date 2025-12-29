.PHONY: build run test

build:
	go build -o bin/btblocker ./cmd/btblocker

run: build
	./bin/btblocker

test:
	go test ./...
