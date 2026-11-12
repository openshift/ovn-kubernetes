package otputils

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	o "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

// FixturePath returns the absolute path to a fixture file in the OTE extension
func FixturePath(parts ...string) string {
	cwd, _ := os.Getwd()
	return filepath.Join(append([]string{cwd, "pkg", "otp", "testdata", "fixtures"}, parts...)...)
}

// ApplyResourceFromTemplate processes an OpenShift template and applies it
func ApplyResourceFromTemplate(namespace string, templatePath string, parameters ...string) error {
	args := append([]string{"process", "-f", templatePath, "--ignore-unknown-parameters=true"}, parameters...)
	processCmd := exec.Command("oc", args...)
	var processed bytes.Buffer
	var errOut bytes.Buffer
	processCmd.Stdout = &processed
	processCmd.Stderr = &errOut
	if err := processCmd.Run(); err != nil {
		return fmt.Errorf("failed to process template %s: %v, stderr: %s", templatePath, err, errOut.String())
	}

	applyArgs := []string{"apply", "-f", "-"}
	if namespace != "" {
		applyArgs = append(applyArgs, "-n", namespace)
	}
	applyCmd := exec.Command("oc", applyArgs...)
	applyCmd.Stdin = &processed
	applyCmd.Stdout = os.Stdout
	applyCmd.Stderr = os.Stderr
	if err := applyCmd.Run(); err != nil {
		return fmt.Errorf("failed to apply processed template: %v", err)
	}

	return nil
}

// RemoveResource removes a resource by type and name
func RemoveResource(resourceType, name string, extraArgs ...string) error {
	args := append([]string{"delete", resourceType, name, "--ignore-not-found=true"}, extraArgs...)
	cmd := exec.Command("oc", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete %s %s: %w", resourceType, name, err)
	}
	return nil
}

// WaitForPodWithLabelReady waits for pods with the given label to be ready
func WaitForPodWithLabelReady(namespace, label string) error {
	return wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 2*time.Minute, true, func(context.Context) (bool, error) {
		args := []string{"get", "pods", "-n", namespace, "-l", label, "-o", "jsonpath={.items[*].status.conditions[?(@.type==\"Ready\")].status}"}
		output, err := exec.Command("oc", args...).Output()
		if err != nil {
			return false, nil
		}
		statuses := strings.Split(string(output), " ")
		if len(statuses) == 0 || string(output) == "" {
			return false, nil
		}
		for _, s := range statuses {
			if s != "True" {
				return false, nil
			}
		}
		return true, nil
	})
}

// GetPodNodeName returns the node name where the pod is scheduled
func GetPodNodeName(namespace, podName string) (string, error) {
	args := []string{"get", "pod", podName, "-n", namespace, "-o", "jsonpath={.spec.nodeName}"}
	output, err := exec.Command("oc", args...).Output()
	if err != nil {
		return "", fmt.Errorf("failed to get node name for pod %s in namespace %s: %w", podName, namespace, err)
	}
	return strings.TrimSpace(string(output)), nil
}

// GetPodName returns a pod name matching the label on a specific node
func GetPodName(namespace, label, nodeName string) (string, error) {
	args := []string{"get", "pods", "-n", namespace, "-l", label, "--field-selector", "spec.nodeName=" + nodeName, "-o", "jsonpath={.items[0].metadata.name}"}
	output, err := exec.Command("oc", args...).Output()
	if err != nil {
		return "", fmt.Errorf("failed to get pod with label %s on node %s in namespace %s: %w", label, nodeName, namespace, err)
	}
	return strings.TrimSpace(string(output)), nil
}

// CurlPod2PodPass ensures connectivity from pod to pod
func CurlPod2PodPass(namespaceSrc, podNameSrc, namespaceDst, podNameDst string) {
	podIPs, err := getPodIPs(namespaceDst, podNameDst)
	o.Expect(err).NotTo(o.HaveOccurred())
	for _, ip := range podIPs {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 --max-time 10 -s "+net.JoinHostPort(ip, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlPod2PodFail ensures no connectivity from pod to pod.
// kubectl/oc exec failures are not treated as blocked connectivity: the remote
// shell always echoes curl's exit code so exec can succeed while curl fails.
func CurlPod2PodFail(namespaceSrc, podNameSrc, namespaceDst, podNameDst string) {
	podIPs, err := getPodIPs(namespaceDst, podNameDst)
	o.Expect(err).NotTo(o.HaveOccurred())
	for _, ip := range podIPs {
		addr := net.JoinHostPort(ip, "8080")
		stdout, stderr, err := e2eoutput.RunHostCmdWithFullOutput(
			namespaceSrc,
			podNameSrc,
			fmt.Sprintf("curl --connect-timeout 5 --max-time 10 -s %s; echo CURL_RC:$?", addr),
		)
		o.Expect(err).NotTo(o.HaveOccurred(),
			"pod exec failed before curl could run toward %s\nstdout=%s\nstderr=%s", addr, stdout, stderr)
		combined := stdout + stderr
		o.Expect(combined).To(o.ContainSubstring("CURL_RC:"),
			"curl did not report an exit code for %s\nstdout=%s\nstderr=%s", addr, stdout, stderr)
		rc := parseCurlRC(combined)
		o.Expect(rc).NotTo(o.Equal(0), "expected curl toward %s to fail (blocked), got CURL_RC=%d", addr, rc)
	}
}

func parseCurlRC(output string) int {
	const marker = "CURL_RC:"
	idx := strings.LastIndex(output, marker)
	if idx < 0 {
		return -1
	}
	var rc int
	if _, err := fmt.Sscanf(output[idx+len(marker):], "%d", &rc); err != nil {
		return -1
	}
	return rc
}

func getPodIPs(namespace, podName string) ([]string, error) {
	args := []string{"get", "pod", podName, "-n", namespace, "-o", "jsonpath={.status.podIPs[*].ip}"}
	output, err := exec.Command("oc", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get pod IPs for pod %s in namespace %s: %w", podName, namespace, err)
	}
	ips := strings.Fields(string(output))
	if len(ips) == 0 {
		return nil, fmt.Errorf("no pod IPs found for pod %s in namespace %s", podName, namespace)
	}
	return ips, nil
}

// flowFieldValue returns the value of a comma-delimited OVS flow field (e.g. nw_dst=).
func flowFieldValue(line, field string) string {
	key := field + "="
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	val := line[idx+len(key):]
	if end := strings.IndexByte(val, ','); end >= 0 {
		val = val[:end]
	}
	return strings.TrimSpace(val)
}

// flowContainsDestIP reports whether an ACL audit log line's flow addresses
// include the destination IP that curl probed (IPv4 nw_dst / IPv6 ipv6_dst).
func flowContainsDestIP(line, ip string) bool {
	want := net.ParseIP(ip)
	if want == nil {
		return false
	}
	for _, field := range []string{"nw_dst", "ipv6_dst"} {
		raw := flowFieldValue(line, field)
		if raw == "" {
			continue
		}
		got := net.ParseIP(raw)
		if got != nil && got.Equal(want) {
			return true
		}
	}
	return false
}

func aclRecordMatchesDestIP(line, aclLogSearchString, destIP string) bool {
	return strings.Contains(line, aclLogSearchString) && flowContainsDestIP(line, destIP)
}

// CheckACLLogs monitors OVN-K node logs for specific ACL audit strings.
// For each destination IP curl probes (dual-stack aware), it requires a matching
// audit record when resultPass is true, and none when false.
func CheckACLLogs(serverPodNs, serverPodName, clientPodNs, clientPodName, curlCmd, aclLogSearchString, ovnKNodePodName string, resultPass bool) {
	// tail -n 0 -F: start at end of file, follow with file rotation support
	tailACLLog := "tail -n 0 -F /var/log/ovn/acl-audit-log.log"

	cmd := exec.Command("oc", "exec", "-n", "openshift-ovn-kubernetes", ovnKNodePodName, "-c", "ovn-controller", "--", "/bin/bash", "-c", tailACLLog)
	var logOutput bytes.Buffer
	cmd.Stdout = &logOutput
	if err := cmd.Start(); err != nil {
		framework.Failf("Failed to start log tailing: %v", err)
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	stopped := false
	var waitErr error
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		select {
		case waitErr = <-waitCh:
			// tail already exited; preserve its result
		default:
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			waitErr = <-waitCh
		}
	}
	defer stop()

	// Give tail time to start capturing
	time.Sleep(1 * time.Second)

	tailAliveBeforeProbe := false
	select {
	case waitErr = <-waitCh:
		stopped = true
		framework.Failf("audit log tail exited before probe (err=%v); cannot validate ACL logs", waitErr)
	default:
		tailAliveBeforeProbe = true
	}

	dstIPs, err := getPodIPs(clientPodNs, clientPodName)
	o.Expect(err).NotTo(o.HaveOccurred())

	if curlCmd == "pass" {
		CurlPod2PodPass(serverPodNs, serverPodName, clientPodNs, clientPodName)
	} else {
		CurlPod2PodFail(serverPodNs, serverPodName, clientPodNs, clientPodName)
	}

	// Allow log entries to be written, then stop process before reading
	time.Sleep(2 * time.Second)

	tailAliveAfterProbe := false
	select {
	case waitErr = <-waitCh:
		stopped = true
	default:
		tailAliveAfterProbe = true
		stop()
	}

	logs := logOutput.String()
	if !resultPass {
		// Empty logs are only valid when the stream stayed alive through the probe.
		o.Expect(tailAliveBeforeProbe && tailAliveAfterProbe).To(o.BeTrue(),
			"audit log stream was not active during probe (waitErr=%v); refusing to treat missing logs as a pass\nLogs:\n%s",
			waitErr, logs)
	} else if waitErr != nil && !tailAliveAfterProbe && logs == "" {
		framework.Failf("audit log tail failed with no output (err=%v)", waitErr)
	}

	for _, ip := range dstIPs {
		found := false
		for _, line := range strings.Split(logs, "\n") {
			if aclRecordMatchesDestIP(line, aclLogSearchString, ip) {
				found = true
				break
			}
		}
		if resultPass {
			o.Expect(found).To(o.BeTrue(),
				"expected ACL audit for dest IP %s matching %q\nLogs:\n%s", ip, aclLogSearchString, logs)
		} else {
			o.Expect(found).To(o.BeFalse(),
				"unexpected ACL audit for dest IP %s matching %q\nLogs:\n%s", ip, aclLogSearchString, logs)
		}
	}
}
