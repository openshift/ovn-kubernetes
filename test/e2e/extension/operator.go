package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	e2e "k8s.io/kubernetes/test/e2e/framework"

	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
)

var _ = g.Describe("[OTP][sig-networking] SDN CNO", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-operator", compat_otp.KubeConfigPath())

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-Longduration-NonPreRelease-Medium-44954-Newline is added between user CAs and system CAs [Disruptive]", func() {
		var (
			dirname  = "/tmp/OCP-44954"
			name     = dirname + "OCP-44954-custom"
			validity = 3650
			caSubj   = dirname + "/OU=openshift/CN=admin-kubeconfig-signer-custom"
		)

		if compat_otp.IsHypershiftHostedCluster(oc) {
			g.Skip("This test is not suitable to run on hosted cluster, skip on hosted cluster.")
		}

		// Generation of a new self-signed CA
		g.By("1.  Generation of a new self-signed CA")
		err := os.MkdirAll(dirname, 0777)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.RemoveAll(dirname)
		e2e.Logf("Generate the CA private key")
		opensslCmd := fmt.Sprintf(`openssl genrsa -out %s-ca.key 4096`, name)
		err = exec.Command("bash", "-c", opensslCmd).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		e2e.Logf("Create the CA certificate")
		opensslCmd = fmt.Sprintf(`openssl req -x509 -new -nodes -key %s-ca.key -sha256 -days %d -out %s-ca.crt -subj %s`, name, validity, name, caSubj)
		err = exec.Command("bash", "-c", opensslCmd).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("2. Create a configmap from the CA")
		configmapName := "custom-ca"
		customCA := "--from-file=ca-bundle.crt=" + name + "-ca.crt"
		e2e.Logf("\n customCA is  %v", customCA)
		_, error := oc.AsAdmin().WithoutNamespace().Run("create").Args("configmap", configmapName, customCA, "-n", "openshift-config").Output()
		o.Expect(error).NotTo(o.HaveOccurred())
		defer func() {
			_, err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("configmap", configmapName, "-n", "openshift-config").Output()
			o.Expect(error).NotTo(o.HaveOccurred())
		}()

		g.By("3. Check if configmap is successfully configured in openshift-config namesapce")
		err = checkConfigMap(oc, "openshift-config", configmapName)
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("cm %v not found", configmapName))

		g.By("4. Patch the configmap created above to proxy/cluster")
		defer checkClusterStatus(oc, "Ready")
		defer patchResourceAsAdmin(oc, "proxy/cluster", "{\"spec\":{\"trustedCA\":{\"name\":\"\"}}}")
		patchResourceAsAdmin(oc, "proxy/cluster", "{\"spec\":{\"trustedCA\":{\"name\":\"custom-ca\"}}}")

		g.By("5. Verify that a newline is added between custom user CAs and system CAs")
		ns := "openshift-config-managed"
		// get system CAs
		outputFile, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("cm", "-n", ns, "trusted-ca-bundle", "-o", "yaml").OutputToFile("trusted-ca")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.RemoveAll(outputFile)

		// get the custom user CA in byte array
		certArray, err := exec.Command("bash", "-c", "cat "+name+"-ca.crt").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		// get the ending portion the custom user CA in byte array
		certArrayPart := certArray[len(certArray)-35 : len(certArray)-30]

		// grep in the trusted-ca-bundle by the ending portion of the custom user CAs, get 4 lines after
		output, err := exec.Command("bash", "-c", "cat "+outputFile+" | grep "+string(certArrayPart)+" -A 4").Output()
		e2e.Logf("\nouput string is  --->%s<----", string(output))
		stringToMatch := string(certArrayPart) + ".+\n.*-----END CERTIFICATE-----\n\n.+\n.+-----BEGIN CERTIFICATE-----"
		o.Expect(output).To(o.MatchRegexp(stringToMatch))
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("Author:qiowang-Medium-73156-Verify pod netns iptables usage will be detected and warned [Serial]", func() {
		var (
			namespace           = "openshift-network-operator"
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodYaml         = filepath.Join(buildPruningBaseDir, "testpod-with-privilege.yaml")
			testPodName         = "hello-pod"
		)

		compat_otp.By("Create netns privileged pod")
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("-n", ns, "pod", testPodName).Execute()
		oc.AsAdmin().WithoutNamespace().Run("create").Args("-n", ns, "-f", testPodYaml).Execute()
		waitPodReady(oc, ns, testPodName)

		compat_otp.By("create iptables in the pod")
		cmdErr := oc.AsAdmin().WithoutNamespace().Run("exec").Args(testPodName, "-n", ns, "--", "iptables-nft", "-A", "INPUT", "-p", "tcp", "--dport", "9999", "-j", "DROP").Execute()
		o.Expect(cmdErr).NotTo(o.HaveOccurred())

		compat_otp.By("restart iptables-alerter pod which lands on the same node with the test pod, trigger iptables-alerter script")
		nodeName, getNodeErr := compat_otp.GetPodNodeName(oc, ns, testPodName)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		alerterPodName1, getPodNameErr1 := compat_otp.GetPodName(oc, namespace, "app=iptables-alerter", nodeName)
		o.Expect(getPodNameErr1).NotTo(o.HaveOccurred())
		o.Expect(alerterPodName1).NotTo(o.BeEmpty())
		delPodErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", alerterPodName1, "-n", namespace, "--ignore-not-found=true").Execute()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())

		compat_otp.By("check logs of iptables-alerter pod")
		alerterPodName2, getPodNameErr2 := compat_otp.GetPodName(oc, namespace, "app=iptables-alerter", nodeName)
		o.Expect(getPodNameErr2).NotTo(o.HaveOccurred())
		o.Expect(alerterPodName2).NotTo(o.BeEmpty())
		waitPodReady(oc, namespace, alerterPodName2)
		podLogs, getLogErr := compat_otp.WaitAndGetSpecificPodLogs(oc, namespace, "iptables-alerter", alerterPodName2, ns+"/"+testPodName)
		o.Expect(getLogErr).NotTo(o.HaveOccurred())
		e2e.Logf("The log is : %s", podLogs)
		o.Expect(strings.Contains(podLogs, "Logging event for "+ns+"/"+testPodName+" which has iptables rules")).Should(o.BeTrue())

		compat_otp.By("check event for the test namespace")
		waitErr := wait.Poll(5*time.Second, 30*time.Second, func() (bool, error) {
			events, getEventsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("events", "-n", ns).Output()
			o.Expect(getEventsErr).NotTo(o.HaveOccurred())
			if !strings.Contains(events, "IPTablesUsageObserved") {
				e2e.Logf("Continue to next round")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(waitErr, "Check events failed")
	})

})
