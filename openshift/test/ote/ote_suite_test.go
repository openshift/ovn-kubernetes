package ote

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestOTE(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OTE Suite")
}
