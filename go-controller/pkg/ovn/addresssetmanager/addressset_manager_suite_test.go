// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package addresssetmanager

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAddressSet(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Address Set Manager Operations Suite")
}
