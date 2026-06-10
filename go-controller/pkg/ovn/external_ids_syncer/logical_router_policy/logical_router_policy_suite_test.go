// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package logical_router_policy

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPortGroup(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "LRP Suite")
}
