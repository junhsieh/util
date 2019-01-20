SHELL = /bin/bash -o pipefail

APP_NAME = util

ROOT_DIR = $(CURDIR)

# NOTE: -count 1 to disable go test cache.
# NOTE: -timeout 10h
go-test:
	cd $(ROOT_DIR) && go mod vendor -v
	cd $(ROOT_DIR) && go test -v -count 1 -mod vendor -race 

go-bench:
	cd $(ROOT_DIR) && go test -v -mod vendor -run=^$$ -bench "NumOfDigits|AbsWith"

go-testNotYet:
	@cd $(ROOT_DIR) && go mod vendor -v
	@cd $(ROOT_DIR) && go test -v -count 1 -mod vendor -race -run "NotYet"
