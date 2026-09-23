EXCLUDE_DIRS ?= test/annotate test/deploymentconfig test/generated
TEST_PKGS := $$(go list ./... $(foreach dir,$(EXCLUDE_DIRS),| grep -v $(dir)))

.PHONY: test
test:
	go test -v $(TEST_PKGS)

.PHONY: lint
lint:
	../go-controller/hack/lint.sh run-natively
