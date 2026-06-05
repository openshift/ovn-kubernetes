// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHybridOverlayControllerSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Hybrid Overlay Controller Suite")
}
