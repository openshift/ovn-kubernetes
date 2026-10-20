package otputils

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"
)

// GetSAToken returns the token for the prometheus-k8s service account
func GetSAToken() (string, error) {
	args := []string{"create", "token", "prometheus-k8s", "-n", "openshift-monitoring"}
	token, err := exec.Command("oc", args...).Output()
	if err == nil && len(token) > 0 {
		return strings.TrimSpace(string(token)), nil
	}
	args = []string{"get", "secrets", "-n", "openshift-monitoring", "-o", "jsonpath={.items[?(@.type==\"kubernetes.io/service-account-token\")].name}"}
	secretNames, err := exec.Command("oc", args...).Output()
	if err != nil {
		return "", fmt.Errorf("failed to get service account secrets: %w", err)
	}
	
	secretList := strings.Fields(string(secretNames))
	if len(secretList) == 0 {
		return "", fmt.Errorf("no service account token secret found")
	}
	
	secretName := secretList[0]
	args = []string{"get", "secret", secretName, "-n", "openshift-monitoring", "-o", "jsonpath={.data.token}"}
	tokenBase64, err := exec.Command("oc", args...).Output()
	if err != nil {
		return "", fmt.Errorf("failed to get service account token secret: %w", err)
	}
	
	tokenCmd := exec.Command("base64", "-d")
	tokenCmd.Stdin = strings.NewReader(string(tokenBase64))
	token, err = tokenCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to decode token from base64: %w", err)
	}
	return strings.TrimSpace(string(token)), nil
}

// GetPolicyMetrics queries Prometheus for OVN-K metrics
func GetPolicyMetrics(metricName string, expectedValue string, labels ...string) {
	token, err := GetSAToken()
	o.Expect(err).NotTo(o.HaveOccurred())

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

	err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 2*time.Minute, true, func(context.Context) (bool, error) {
		encodedQuery := url.QueryEscape(query)
		promURL := "https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query?query=" + encodedQuery
		curlCmd := fmt.Sprintf("TOKEN='%s'\ncurl -s --cacert /run/secrets/kubernetes.io/serviceaccount/ca.crt -H \"Authorization: Bearer ${TOKEN}\" \"%s\"", token, promURL)
		output, err := exec.Command("oc", "exec", "-n", "openshift-monitoring", "prometheus-k8s-0", "-c", "prometheus", "--", "bash", "-c", curlCmd).CombinedOutput()
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
		if err := json.Unmarshal(output, &resp); err != nil || len(resp.Data.Result) == 0 || len(resp.Data.Result[0].Value) < 2 {
			return false, nil
		}
		value, _ := resp.Data.Result[0].Value[1].(string)
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
