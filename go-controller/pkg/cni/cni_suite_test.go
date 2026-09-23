// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package cni

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	// Disable WatchListClient feature gate for tests.
	// Fake clientsets from third-party libraries don't yet support WatchList semantics
	// introduced in K8s 1.35, causing informers to hang waiting for bookmark events.
	// See: https://github.com/kubernetes/kubernetes/issues/135895
	os.Setenv("KUBE_FEATURE_WatchListClient", "false")
}

// TestMain keeps the pod port journal inside the test's own scratch space, so
// no test writes to the node's /var/run.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ovnk-cni-test")
	if err != nil {
		panic(err)
	}
	portJournalDir = filepath.Join(dir, "ports")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestCNISuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CNI Suite")
}
