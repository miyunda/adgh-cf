.PHONY: build test check linux

build:
	bash scripts/build.sh local

test:
	go test -race ./...

check:
	go vet ./...
	test -z "$$(gofmt -l cmd/adgh-cf/*.go)"
	bash -n scripts/*.sh
	bash scripts/check-repo.sh

linux:
	bash scripts/build.sh linux
