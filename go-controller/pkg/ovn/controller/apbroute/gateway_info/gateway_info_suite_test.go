// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package gateway_info

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGatewayInfo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "GatewayInfo Suite")
}
