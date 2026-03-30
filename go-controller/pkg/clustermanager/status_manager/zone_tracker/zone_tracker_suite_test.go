// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package zone_tracker

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestZoneTracker(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cluster Manager Zone Tracker Suite")
}
