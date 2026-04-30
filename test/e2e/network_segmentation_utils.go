// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/net"
)

// podIPsForUserDefinedPrimaryNetwork returns the v4 or v6 IPs for a pod on the UDN
func getPodAnnotationIPsForPrimaryNetworkByIPFamily(k8sClient kubernetes.Interface, podNamespace string, podName string, networkName string, family net.IPFamily) (string, error) {
	if networkName != "default" {
		networkName = namespacedName(podNamespace, networkName)
	}
	ipnets, err := getPodAnnotationIPsForAttachment(k8sClient, podNamespace, podName, networkName)
	if err != nil {
		return "", err
	}
	ipnet := getFirstCIDROfFamily(family, ipnets)
	if ipnet == nil {
		return "", nil
	}
	return ipnet.IP.String(), nil
}

// GetPodAnnotationIPsForPrimaryNetworkByIPFamily returns the v4 or v6 IP for a pod
// on a primary user-defined network, extracted from the pod's network annotations.
func GetPodAnnotationIPsForPrimaryNetworkByIPFamily(k8sClient kubernetes.Interface, podNamespace, podName, networkName string, family net.IPFamily) (string, error) {
	return getPodAnnotationIPsForPrimaryNetworkByIPFamily(k8sClient, podNamespace, podName, networkName, family)
}
