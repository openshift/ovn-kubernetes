package otp

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestOTP(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OTP Networking Tools Suite")
}
