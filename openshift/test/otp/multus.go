package otp

import (
	"fmt"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[sig-networking] OTP Multus", func() {
	var oc = exutil.NewCLI("otp-multus")

	// High-57589: Whereabouts CNI Timeout with Large Exclude Range
	g.It("[OTP][blocking][case_id:57589] should handle large IPv6 exclude ranges without timeout", func() {
		g.By("Creating NetworkAttachmentDefinition with large exclude range")
		nadYAML := `
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  name: nad-w-excludes
spec:
  config: '{
    "cniVersion": "0.3.1",
    "name": "bridge-net",
    "type": "bridge",
    "bridge": "test-br0",
    "isGateway": false,
    "ipMasq": false,
    "ipam": {
      "type": "whereabouts",
      "range": "fd43:01f1:3daa:0baa::/64",
      "exclude": [ "fd43:01f1:3daa:0baa::/100" ],
      "log_file": "/tmp/whereabouts.log",
      "log_level": "debug"
    }
  }'
`
		err := oc.Run("create").Args("-f", "-").InputString(nadYAML).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating pod with secondary network")
		podYAML := `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  annotations:
    k8s.v1.cni.cncf.io/networks: nad-w-excludes
spec:
  containers:
  - name: test
    image: registry.access.redhat.com/ubi8/ubi-minimal:latest
    command: ["sleep", "3600"]
`
		err = oc.Run("create").Args("-f", "-").InputString(podYAML).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for pod to reach Running state (max 60s)")
		// Pod should be Running within 60 seconds (test validates no timeout)
		err = wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
			output, err := oc.Run("get").Args("pod", "test-pod", "-o", "jsonpath={.status.phase}").Output()
			if err != nil {
				return false, nil
			}
			return output == "Running", nil
		})
		o.Expect(err).NotTo(o.HaveOccurred(), "Pod did not reach Running state within 60s - Whereabouts may have timed out")

		g.By("Verifying secondary network attachment")
		networkStatus, err := oc.Run("get").Args("pod", "test-pod", "-o", "jsonpath={.metadata.annotations.k8s\\.v1\\.cni\\.cncf\\.io/network-status}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(networkStatus).NotTo(o.BeEmpty(), "Pod missing network-status annotation")

		// Verify at least 2 networks (primary + secondary)
		networkCount := strings.Count(networkStatus, `"name"`)
		o.Expect(networkCount).To(o.BeNumerically(">=", 2),
			"Expected at least 2 networks, got %d", networkCount)
	})

	// Medium-76652: Dummy CNI Support
	g.It("[OTP][blocking][case_id:76652] should support Dummy CNI plugin with Multus", func() {
		g.By("Creating NetworkAttachmentDefinition with dummy CNI and static IPAM")
		nadYAML := `
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  name: dummy-net
spec:
  config: '{
    "cniVersion": "0.3.1",
    "name": "dummy-net",
    "type": "dummy",
    "ipam": {
      "type": "static",
      "addresses": [
        {
          "address": "10.10.10.2/24"
        }
      ]
    }
  }'
`
		err := oc.Run("create").Args("-f", "-").InputString(nadYAML).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating pod with dummy network attached")
		podYAML := `
apiVersion: v1
kind: Pod
metadata:
  name: test-dummy-pod
  annotations:
    k8s.v1.cni.cncf.io/networks: dummy-net
spec:
  containers:
  - name: test
    image: registry.access.redhat.com/ubi8/ubi-minimal:latest
    command: ["sleep", "3600"]
`
		err = oc.Run("create").Args("-f", "-").InputString(podYAML).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for pod to reach Running state")
		err = wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
			output, err := oc.Run("get").Args("pod", "test-dummy-pod", "-o", "jsonpath={.status.phase}").Output()
			if err != nil {
				return false, nil
			}
			return output == "Running", nil
		})
		o.Expect(err).NotTo(o.HaveOccurred(), "Pod did not reach Running state within 60s")

		g.By("Verifying dummy network interface is created")
		networkStatus, err := oc.Run("get").Args("pod", "test-dummy-pod", "-o", "jsonpath={.metadata.annotations.k8s\\.v1\\.cni\\.cncf\\.io/network-status}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(networkStatus).NotTo(o.BeEmpty(), "Pod missing network-status annotation")

		g.By("Validating dummy interface has correct IP and configuration")
		// Network status should contain 2 interfaces: ovn-kubernetes (primary) + dummy-net (secondary)
		o.Expect(networkStatus).To(o.ContainSubstring("ovn-kubernetes"), "Should have primary OVN network")
		o.Expect(networkStatus).To(o.ContainSubstring("dummy-net"), "Should have dummy network")
		o.Expect(networkStatus).To(o.ContainSubstring("10.10.10.2"), "Should have assigned dummy IP")

		// Verify we have at least 2 network interfaces
		networkCount := strings.Count(networkStatus, `"name"`)
		o.Expect(networkCount).To(o.BeNumerically(">=", 2),
			"Expected at least 2 networks (primary + dummy), got %d", networkCount)

		e2e.Logf("Successfully validated dummy CNI with IP 10.10.10.2")
	})
})
