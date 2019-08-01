SHELL = /bin/bash -o pipefail

APP_NAME = util

# NOTE: -count 1 to disable go test cache.
# NOTE: -timeout 10h
# NOTE: go help testflag
# NOTE: https://golang.org/cmd/go/#hdr-Testing_flags
go-test:
	cd $(CURDIR) && go mod vendor -v
	cd $(CURDIR) && go test -v -count 1 -timeout 1h -mod vendor -race

go-bench:
	cd $(CURDIR) && go test -v -mod vendor -run=^$$ -bench "NumOfDigits|AbsWith"

go-testNotYet:
	@cd $(CURDIR) && go mod vendor -v
	@cd $(CURDIR) && go test -v -count 1 -mod vendor -race -run "NotYet"

go-tidy:
	cd $(ROOT_DIR) && go mod tidy -v
