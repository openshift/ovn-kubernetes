// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package networkconnect

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNetworkConnectController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OVNKube NetworkConnect Controller Suite")
}
