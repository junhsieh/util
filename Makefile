SHELL = /bin/bash -o pipefail

APP_NAME = util

# Example: make go-test args="-Debug"
# NOTE: -count 1 to disable go test cache.
# NOTE: -timeout 10h
# NOTE: Put -args at the end.
# NOTE: go help testflag
# NOTE: https://golang.org/cmd/go/#hdr-Testing_flags
go-test:
	cd $(CURDIR) && go mod vendor -v
	cd $(CURDIR) && go test -v -count 1 -timeout 1h -mod vendor -race . -args $(args)

go-bench:
	cd $(CURDIR) && go test -v -mod vendor -run=^$$ -bench "NumOfDigits|AbsWith"

go-testNotYet:
	@cd $(CURDIR) && go mod vendor -v
	@cd $(CURDIR) && go test -v -count 1 -mod vendor -race -run "NotYet"

go-tidy:
	@cd $(CURDIR) && go mod tidy -v

go-clean:
	@cd $(CURDIR) && go clean -i -x -modcache
