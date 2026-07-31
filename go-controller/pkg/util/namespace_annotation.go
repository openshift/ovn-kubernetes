// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"fmt"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/kube"
)

const (
	// Annotation used to enable/disable multicast in the namespace
	NsMulticastAnnotation = "k8s.ovn.org/multicast-enabled"
	// ExternalGatewayPodIPsAnnotation is an internal annotation used to signal
	// ovnkube-node to flush conntrack for external gateway pod IPs.
	ExternalGatewayPodIPsAnnotation = "k8s.ovn.org/external-gw-pod-ips"
	// Annotation for enabling ACL logging to controller's log file
	AclLoggingAnnotation = "k8s.ovn.org/acl-logging"
)

func UpdateExternalGatewayPodIPsAnnotation(k kube.Interface, namespace string, exgwIPs []string) error {
	exgwPodAnnotation := strings.Join(exgwIPs, ",")
	err := k.SetAnnotationsOnNamespace(namespace, map[string]interface{}{ExternalGatewayPodIPsAnnotation: exgwPodAnnotation})
	if err != nil {
		return fmt.Errorf("failed to add annotation %s/%v for namespace %s: %v", ExternalGatewayPodIPsAnnotation, exgwPodAnnotation, namespace, err)
	}
	return nil
}
