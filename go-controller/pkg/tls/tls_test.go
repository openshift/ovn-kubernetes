// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package tls_test

import (
	"crypto/tls"

	ovntls "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/tls"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewApplyConfigOptions", func() {
	assertApplySuccess := func(minVersion string, ciperSuites []string) *tls.Config {
		applyOpts, err := ovntls.NewApplyConfigOptions(minVersion, ciperSuites)
		Expect(err).ToNot(HaveOccurred())
		Expect(applyOpts).ToNot(BeNil())

		cfg := &tls.Config{}
		applyOpts(cfg)

		return cfg
	}

	Context("with valid inputs", func() {
		It("should correctly apply the settings", func() {
			cfg := assertApplySuccess("VersionTLS12", []string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
			})
			Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(cfg.CipherSuites).To(ConsistOf(tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384))
		})
	})

	Context("with empty cipher suites list", func() {
		It("should apply an empty cipher suites list", func() {
			cfg := assertApplySuccess("VersionTLS13", []string{})
			Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			Expect(cfg.CipherSuites).To(BeEmpty())
		})
	})

	Context("with nil cipher suites list", func() {
		It("should apply an empty cipher suites list", func() {
			cfg := assertApplySuccess("VersionTLS11", nil)
			Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS11)))
			Expect(cfg.CipherSuites).To(BeEmpty())
		})
	})

	Context("with empty min version", func() {
		It("should apply the default min version", func() {
			cfg := assertApplySuccess("", []string{})
			Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
		})
	})

	DescribeTableSubtree("with invalid",
		func(minVersion string, ciperSuites []string) {
			It("should return an error", func() {
				applyOpts, err := ovntls.NewApplyConfigOptions(minVersion, ciperSuites)
				Expect(err).To(HaveOccurred())
				Expect(applyOpts).To(BeNil())
			})
		},
		Entry("TLS version string", "InvalidTLSVersion", []string{}),
		Entry("cipher suite name", "VersionTLS12", []string{
			"TLS_AES_128_GCM_SHA256",
			"InvalidCipherSuite",
			"TLS_AES_256_GCM_SHA384"}),
	)
})
