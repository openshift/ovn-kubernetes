package networkControllerManager

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestNodeSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ovnkube controller suite")
}
