// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors

// Package cnooverrides reads the CNO config overrides that OpenShift renders
// into OVN-Kubernetes components. It exists so that deploymentconfig and
// infraprovider can consume the same lookups without an API dependency
// between them: both packages import this one, neither imports the other.
//
// Keep the constants here in sync with the ovn-conf-disable-udn-arp-ndp-flood
// steps in openshift/release, which gate on the same ConfigMap.
package cnooverrides

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// OvnConfigOverridesNamespace is the namespace of the CNO ConfigMap that
	// carries the OVN-Kubernetes config overrides.
	OvnConfigOverridesNamespace = "openshift-network-operator"
	// OvnConfigOverridesConfigMap is the CNO ConfigMap that carries the
	// OVN-Kubernetes config overrides.
	OvnConfigOverridesConfigMap = "ovn-kubernetes-config-overrides"
	// CNO renders --disable-udn-arp-ndp-flood into ovnkube-node when this
	// override key is true.
	disableUDNARPNDPFloodOverride = "disable-udn-arp-ndp-flood"
	configOverridesRequestTimeout = 30 * time.Second
)

// IsUDNARPNDPFloodDisabled reports whether the CNO config override that
// disables UDN ARP/NDP flooding is set. On OpenShift the setting is a CNO
// config override rather than a feature gate, so the overrides ConfigMap is
// its only declarative source. It answers "configured", not "converged": it
// does not observe that the ovnkube-node rollout picked the override up.
// That is verified by the openshift/release step that enables it
// (ovn-conf-disable-udn-arp-ndp-flood) before the tests start.
//
// A missing ConfigMap or key leaves the feature off and is not an error;
// only a failure to read the ConfigMap is. Callers decide how to react to
// the error.
func IsUDNARPNDPFloodDisabled(client kubernetes.Interface) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), configOverridesRequestTimeout)
	defer cancel()
	overrides, err := client.CoreV1().ConfigMaps(OvnConfigOverridesNamespace).Get(ctx, OvnConfigOverridesConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read configmap %s/%s: %w", OvnConfigOverridesNamespace, OvnConfigOverridesConfigMap, err)
	}
	// As CNO does (validateConfigOverrideBool): the trimmed value must parse
	// as a boolean true; a missing, blank or invalid value leaves the feature
	// off (ParseBool returns false with its error).
	disabled, _ := strconv.ParseBool(strings.TrimSpace(overrides.Data[disableUDNARPNDPFloodOverride]))
	return disabled, nil
}
