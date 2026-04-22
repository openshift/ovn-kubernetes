// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package netlinkdevicemanager

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNetlinkDeviceManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Netlink Device Manager Suite")
}
