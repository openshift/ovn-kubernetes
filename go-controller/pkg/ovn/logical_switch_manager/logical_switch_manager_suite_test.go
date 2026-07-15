// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package logicalswitchmanager

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLogicalSwitchManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Logical Switch Manager Operations Suite")
}
