package pool_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNetworkPool(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Network Pool Suite")
}
