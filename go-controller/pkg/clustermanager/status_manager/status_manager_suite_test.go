// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package status_manager

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestStatusManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cluster Manager Status Manager Suite")
}
