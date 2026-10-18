package otputils

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	"github.com/tidwall/gjson"
	"k8s.io/apimachinery/pkg/util/wait"
)

// GetSAToken returns the token for the prometheus-k8s service account
func GetSAToken() (string, error) {
	args := []string{"get", "secret", "-n", "openshift-monitoring", "-o", "jsonpath={.items[?(@.metadata.annotations.kubernetes\\.io/service-account\\.name==\"prometheus-k8s\")].name}"}
	secretName, err := exec.Command("oc", args...).Output()
	if err != nil {
		return "", err
	}
	args = []string{"get", "secret", strings.TrimSpace(string(secretName)), "-n", "openshift-monitoring", "-o", "jsonpath={.data.token}"}
	tokenBase64, err := exec.Command("oc", args...).Output()
	if err != nil {
		return "", err
	}
	tokenCmd := exec.Command("base64", "-d")
	tokenCmd.Stdin = strings.NewReader(string(tokenBase64))
	token, err := tokenCmd.Output()
	if err != nil {
		return "", err
	}
	return string(token), nil
}

// GetPolicyMetrics queries Prometheus for OVN-K metrics
func GetPolicyMetrics(metricName string, expectedValue string, labels ...string) {
	token, err := GetSAToken()
	o.Expect(err).NotTo(o.HaveOccurred())

	query := metricName
	if len(labels) > 0 {
		var labelSelectors []string
		if metricName == "ovnkube_controller_baseline_admin_network_policies_db_objects" || 
		   metricName == "ovnkube_controller_admin_network_policies_db_objects" {
			labelSelectors = append(labelSelectors, fmt.Sprintf("db_object=\"%s\"", labels[0]))
		} else if metricName == "ovnkube_controller_baseline_admin_network_policies_rules" ||
		          metricName == "ovnkube_controller_admin_network_policies_rules" {
			labelSelectors = append(labelSelectors, fmt.Sprintf("direction=\"%s\"", labels[0]))
			labelSelectors = append(labelSelectors, fmt.Sprintf("action=\"%s\"", labels[1]))
		}
		query = fmt.Sprintf("%s{%s}", metricName, strings.Join(labelSelectors, ","))
	}

	err = wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		promURL := "https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query?query=" + query
		curlCmd := fmt.Sprintf("curl -k -s -H \"Authorization: Bearer %s\" \"%s\"", token, promURL)
		output, err := exec.Command("oc", "exec", "-n", "openshift-monitoring", "prometheus-k8s-0", "-c", "prometheus", "--", "bash", "-c", curlCmd).Output()
		if err != nil {
			return false, nil
		}

		value := gjson.Get(string(output), "data.result.0.value.1").String()
		if value == expectedValue {
			return true, nil
		}
		return false, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Metric %s did not reach expected value %s", query, expectedValue))
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
