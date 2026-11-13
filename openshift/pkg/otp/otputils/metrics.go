package otputils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"
)

// GetPolicyMetrics queries Prometheus for OVN-K metrics.
// Uses the in-pod HTTP listener (127.0.0.1:9090) to avoid TLS/kube-rbac-proxy
// issues with https://…:9091 from inside the prometheus container.
func GetPolicyMetrics(metricName string, expectedValue string, labels ...string) {
	query := metricName
	if len(labels) > 0 {
		var labelSelectors []string
		if metricName == "ovnkube_controller_baseline_admin_network_policies_rules" ||
			metricName == "ovnkube_controller_admin_network_policies_rules" {
			labelSelectors = append(labelSelectors, fmt.Sprintf("direction=\"%s\"", labels[0]))
			labelSelectors = append(labelSelectors, fmt.Sprintf("action=\"%s\"", labels[1]))
		}
		query = fmt.Sprintf("%s{%s}", metricName, strings.Join(labelSelectors, ","))
	}

	var lastOut string
	err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 2*time.Minute, true, func(context.Context) (bool, error) {
		encodedQuery := url.QueryEscape(query)
		// Local prometheus HTTP port needs no bearer token / CA.
		promURL := "http://127.0.0.1:9090/api/v1/query?query=" + encodedQuery
		output, err := exec.Command("oc", "exec", "-n", "openshift-monitoring", "prometheus-k8s-0", "-c", "prometheus", "--",
			"curl", "-s", promURL).CombinedOutput()
		lastOut = string(output)
		if err != nil {
			return false, nil
		}

		var resp struct {
			Data struct {
				Result []struct {
					Value []interface{} `json:"value"`
				} `json:"result"`
			} `json:"data"`
		}
		if err := json.Unmarshal(output, &resp); err != nil || len(resp.Data.Result) == 0 {
			return false, nil
		}
		// Each ovnkube-node scrapes the same cluster-scoped gauge; accept if any
		// series matches the expected value.
		for _, r := range resp.Data.Result {
			if len(r.Value) < 2 {
				continue
			}
			value, _ := r.Value[1].(string)
			if value == expectedValue {
				return true, nil
			}
		}
		return false, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Metric %s did not reach expected value %s; last response: %s", query, expectedValue, lastOut))
}

// CheckIPStackType returns "dualstack", "ipv4" or "ipv6"
func CheckIPStackType() string {
	output, err := exec.Command("oc", "get", "network.config.openshift.io", "cluster", "-o", "jsonpath={.status.clusterNetwork[*].cidr}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	
	cidrs := strings.Fields(string(output))
	hasIPv4 := false
	hasIPv6 := false
	for _, cidr := range cidrs {
		if strings.Contains(cidr, ":") {
			hasIPv6 = true
		} else {
			hasIPv4 = true
		}
	}
	if hasIPv4 && hasIPv6 {
		return "dualstack"
	}
	if hasIPv6 {
		return "ipv6"
	}
	return "ipv4"
}
