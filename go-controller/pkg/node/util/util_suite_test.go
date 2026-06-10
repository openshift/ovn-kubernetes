// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNodeSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Node util Suite")
}
