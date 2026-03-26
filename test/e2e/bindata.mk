TESTDATA_PATH := extension/testdata
GOPATH ?= $(shell go env GOPATH)
GO_BINDATA := $(GOPATH)/bin/go-bindata

$(GO_BINDATA):
	@echo "Installing go-bindata..."
	@GOFLAGS= go install github.com/go-bindata/go-bindata/v3/go-bindata@latest

.PHONY: update-bindata
update-bindata: $(GO_BINDATA)
	@echo "Generating bindata for testdata files..."
	$(GO_BINDATA) \
		-nocompress \
		-nometadata \
		-prefix "extension/testdata" \
		-pkg testdata \
		-o extension/testdata/bindata.go \
		extension/testdata/...
	@gofmt -s -w extension/testdata/bindata.go
	@echo "Bindata generated successfully"

.PHONY: verify-bindata
verify-bindata: update-bindata
	@echo "Verifying bindata is up to date..."
	git diff --exit-code $(TESTDATA_PATH)/bindata.go || (echo "Bindata is out of date" && exit 1)
	@echo "Bindata is up to date"

.PHONY: bindata
bindata: clean-bindata update-bindata

.PHONY: clean-bindata
clean-bindata:
	@echo "Cleaning bindata..."
	@rm -f $(TESTDATA_PATH)/bindata.go
