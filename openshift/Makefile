# SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
# SPDX-License-Identifier: Apache-2.0

EXCLUDE_DIRS ?= test/annotate test/deploymentconfig test/generated
TEST_PKGS := $$(go list ./... $(foreach dir,$(EXCLUDE_DIRS),| grep -v $(dir)))

LICENSE_EYE := $(shell which license-eye 2>/dev/null || echo "$(shell go env GOPATH)/bin/license-eye")
LICENSE_EYE_VERSION ?= v0.8.0

.PHONY: test
test:
	go test -v $(TEST_PKGS)

.PHONY: lint
lint:
	$(MAKE) -f ../go-controller/Makefile lint

.PHONY: gofmt
gofmt:
	@PKGS=. ../go-controller/hack/verify-gofmt.sh

$(LICENSE_EYE):
	go install github.com/apache/skywalking-eyes/cmd/license-eye@$(LICENSE_EYE_VERSION)

.PHONY: license-check
license-check: $(LICENSE_EYE)
	$(LICENSE_EYE) header check

.PHONY: license-fix
license-fix: $(LICENSE_EYE)
	$(LICENSE_EYE) header fix
