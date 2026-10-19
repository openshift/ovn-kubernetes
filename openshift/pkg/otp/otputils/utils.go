package otputils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"net"

	o "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

// FixturePath returns the absolute path to a fixture file in the OTE extension
func FixturePath(parts ...string) string {
	cwd, _ := os.Getwd()
	// If already in openshift dir, don't add it again
	base := filepath.Join(cwd, "pkg", "otp", "testdata", "fixtures")
	if _, err := os.Stat(base); os.IsNotExist(err) {
		// Try with openshift prefix if not found
		base = filepath.Join(cwd, "openshift", "pkg", "otp", "testdata", "fixtures")
	}
	return filepath.Join(append([]string{base}, parts...)...)
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
	return cmd.Run()
}

// WaitForPodWithLabelReady waits for pods with the given label to be ready
func WaitForPodWithLabelReady(namespace, label string) error {
	return wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
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
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// GetPodName returns a pod name matching the label on a specific node
func GetPodName(namespace, label, nodeName string) (string, error) {
	args := []string{"get", "pods", "-n", namespace, "-l", label, "--field-selector", "spec.nodeName="+nodeName, "-o", "jsonpath={.items[0].metadata.name}"}
	output, err := exec.Command("oc", args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// CurlPod2PodPass ensures connectivity from pod to pod
func CurlPod2PodPass(namespaceSrc, podNameSrc, namespaceDst, podNameDst string) {
	podIPs, err := getPodIPs(namespaceDst, podNameDst)
	o.Expect(err).NotTo(o.HaveOccurred())
	for _, ip := range podIPs {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(ip, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlPod2PodFail ensures no connectivity from pod to pod
func CurlPod2PodFail(namespaceSrc, podNameSrc, namespaceDst, podNameDst string) {
	podIPs, err := getPodIPs(namespaceDst, podNameDst)
	o.Expect(err).NotTo(o.HaveOccurred())
	for _, ip := range podIPs {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(ip, "8080"))
		o.Expect(err).To(o.HaveOccurred())
	}
}

func getPodIPs(namespace, podName string) ([]string, error) {
	args := []string{"get", "pod", podName, "-n", namespace, "-o", "jsonpath={.status.podIPs[*].ip}"}
	output, err := exec.Command("oc", args...).Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(output)), nil
}

// CheckACLLogs monitors OVN-K node logs for specific ACL audit strings
func CheckACLLogs(serverPodNs, serverPodName, clientPodNs, clientPodName, curlCmd, aclLogSearchString, ovnKNodePodName string, resultPass bool) {
	tailACLLog := "tail -f /var/log/ovn/acl-audit-log.log"
	
	cmd := exec.Command("oc", "exec", "-n", "openshift-ovn-kubernetes", ovnKNodePodName, "-c", "ovn-controller", "--", "/bin/bash", "-c", tailACLLog)
	var logOutput bytes.Buffer
	cmd.Stdout = &logOutput
	if err := cmd.Start(); err != nil {
		framework.Failf("Failed to start log tailing: %v", err)
	}
	defer cmd.Process.Kill()

	time.Sleep(2 * time.Second)

	if curlCmd == "pass" {
		CurlPod2PodPass(serverPodNs, serverPodName, clientPodNs, clientPodName)
	} else {
		CurlPod2PodFail(serverPodNs, serverPodName, clientPodNs, clientPodName)
	}

	time.Sleep(5 * time.Second)
	
	found := strings.Contains(logOutput.String(), aclLogSearchString)
	if resultPass {
		o.Expect(found).To(o.BeTrue(), fmt.Sprintf("Expected log string not found: %s\nLogs:\n%s", aclLogSearchString, logOutput.String()))
	} else {
		o.Expect(found).To(o.BeFalse(), fmt.Sprintf("Unexpected log string found: %s\nLogs:\n%s", aclLogSearchString, logOutput.String()))
	}
}
