// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import (
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
)

const (
	// OvnZoneExternalIDKey stores the OVN zone that owns a KubeVirt OVN resource.
	OvnZoneExternalIDKey = types.OvnK8sPrefix + "/zone"
	// OvnRemoteZone marks OVN resources owned by a remote zone.
	OvnRemoteZone = "remote"
	// OvnLocalZone marks OVN resources owned by the local zone.
	OvnLocalZone = "local"

	// NamespaceExternalIDsKey stores the VM namespace in OVN external IDs.
	NamespaceExternalIDsKey = "k8s.ovn.org/namespace"
	// VirtualMachineExternalIDsKey stores the VM name in OVN external IDs.
	VirtualMachineExternalIDsKey = "k8s.ovn.org/vm"
)
