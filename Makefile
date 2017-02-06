# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

PACKAGE = github.com/bryanjeal/go-nonce

.PHONY: vendor check fmt lint test test-race vet test-cover-html help
.DEFAULT_GOAL := help

vendor: ## Install govendor and sync nonce's vendored dependencies
	go get github.com/kardianos/govendor
	govendor sync ${PACKAGE}

check: test-race fmt vet ## Run tests and linters

test386: ## Run tests in 32-bit mode
	GOARCH=386 govendor test +local

test: ## Run tests
	govendor test +local

test-race: ## Run tests with race detector
	govendor test -race +local

fmt: ## Run gofmt linter
	@for d in `govendor list -no-status +local | sed 's/github.com.bryanjeal.go-nonce/./'` ; do \
		if [ "`gofmt -s -l $$d/*.go | tee /dev/stderr`" ]; then \
			echo "^ improperly formatted go files" && echo && exit 1; \
		fi \
	done

lint: ## Run golint linter
	@for d in `govendor list -no-status +local | sed 's/github.com.bryanjeal.go-nonce/./'` ; do \
		if [ "`golint $$d | tee /dev/stderr`" ]; then \
			echo "^ golint errors!" && echo && exit 1; \
		fi \
	done

vet: ## Run go vet linter
	@if [ "`govendor vet +local | tee /dev/stderr`" ]; then \
		echo "^ go vet errors!" && echo && exit 1; \
	fi

test-cover-html: PACKAGES = $(shell govendor list -no-status +local | sed 's/github.com.bryanjeal.go-nonce/./')
test-cover-html: ## Generate test coverage report
	echo "mode: count" > coverage-all.out
	$(foreach pkg,$(PACKAGES),\
		govendor test -coverprofile=coverage.out -covermode=count $(pkg);\
		tail -n +2 coverage.out >> coverage-all.out;)
	go tool cover -html=coverage-all.out

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
