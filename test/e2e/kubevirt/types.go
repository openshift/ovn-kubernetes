// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import "os"

const (
	FedoraCoreOSContainerDiskImage = "quay.io/kubevirtci/fedora-coreos-kubevirt:v20230905-be4fa50"
	FedoraContainerDiskImage       = "quay.io/containerdisks/fedora:39"
)

var (
	FedoraWithTestToolingContainerDiskImage = "quay.io/kubevirtci/fedora-with-test-tooling:v20250416-e37573e"
)

func init() {
	if override := os.Getenv("FEDORA_WITH_TEST_TOOLING_IMAGE"); override != "" {
		FedoraWithTestToolingContainerDiskImage = override
	}
}
