// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package networkconnect

import (
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMain(m *testing.M) {
	// Disable WatchListClient feature gate for tests.
	// Fake clientsets from third-party libraries don't yet support WatchList semantics
	// introduced in K8s 1.35, causing informers to hang waiting for bookmark events.
	// See: https://github.com/kubernetes/kubernetes/issues/135895
	os.Setenv("KUBE_FEATURE_WatchListClient", "false")
	os.Exit(m.Run())
}

func TestNetworkConnectController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OVNKube NetworkConnect Controller Suite")
}
