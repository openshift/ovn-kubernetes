EXCLUDE_DIRS ?= test/
TEST_PKGS := $$(go list ./... | grep -v $(EXCLUDE_DIRS))

.PHONY: test
test:
	go test -v $(TEST_PKGS)
