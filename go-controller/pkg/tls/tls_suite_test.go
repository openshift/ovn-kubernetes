// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package tls_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTLS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS Suite")
}
