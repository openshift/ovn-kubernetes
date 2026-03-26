package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[OTP][sig-networking] SDN OVN hypershift", func() {
	defer g.GinkgoRecover()

	var (
		oc                                                          = compat_otp.NewCLIForKubeOpenShift("networking-ovnkubernetes-" + getRandomString())
		hostedClusterName, hostedClusterKubeconfig, hostedclusterNS string
	)

	g.BeforeEach(func() {
		// Check the network plugin type
		networkType := compat_otp.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip case on cluster that has non-OVN network plugin!!")
		}
		hostedClusterName, hostedClusterKubeconfig, hostedclusterNS = compat_otp.ValidHypershiftAndGetGuestKubeConf(oc)
		oc.SetGuestKubeconf(hostedClusterKubeconfig)

	})

	g.It("HyperShiftMGMT-NonPreRelease-Longduration-ConnectedOnly-Author:jechen-High-67347-VMI on BM Kubevirt hypershift cluster can be lively migrated from one host to another host. [Disruptive]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		migrationTemplate := filepath.Join(buildPruningBaseDir, "kubevirt-live-migration-job-template.yaml")

		hyperShiftMgmtNS := hostedclusterNS + "-" + hostedClusterName
		e2e.Logf("hyperShiftMgmtNS: %v\n", hyperShiftMgmtNS)

		mgmtClusterPlatform := compat_otp.CheckPlatform(oc)
		e2e.Logf("mgmt cluster platform: %v\n", mgmtClusterPlatform)

		nestedClusterPlatform := compat_otp.CheckPlatform(oc.AsAdmin().AsGuestKubeconf())
		e2e.Logf("hosted cluster platform: %v\n", nestedClusterPlatform)

		if !strings.Contains(mgmtClusterPlatform, "baremetal") || !strings.Contains(nestedClusterPlatform, "kubevirt") {
			g.Skip("Live migration can only be performed on Baremetal Kubevirt Hypershift, skip all other platforms")
		}

		compat_otp.By("1. Get the first VMI on mgmt cluster to perform live migration \n")
		vmi, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmi", "-n", hyperShiftMgmtNS, "-o=jsonpath={.items[0].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		nodeList, err := compat_otp.GetSchedulableLinuxWorkerNodes(oc.AsAdmin().AsGuestKubeconf())
		o.Expect(err).NotTo(o.HaveOccurred())
		origScheduleableWorkerNodeCount := len(nodeList)

		compat_otp.By("2. Get IP address,  hosted nodename, status of the VMI before live migration \n")
		originalIP, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmi", vmi, "-n", hyperShiftMgmtNS, "-o=jsonpath={.status.interfaces[0].ipAddress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("originalIP: %v\n", originalIP)

		OriginalNodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmi", vmi, "-n", hyperShiftMgmtNS, "-o=jsonpath={.metadata.labels.kubevirt\\.io\\/nodeName}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("OriginalNodeName: %v\n", OriginalNodeName)

		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmi", vmi, "-n", hyperShiftMgmtNS, "-o=jsonpath={.status.conditions[*].type}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("status: %v\n", status)
		o.Expect(strings.Contains(status, "Ready")).To(o.BeTrue())
		o.Expect(strings.Contains(status, "LiveMigratable")).To(o.BeTrue())

		compat_otp.By("3. Perform live migration on the VMI \n")
		migrationjob := migrationDetails{
			name:                   "migration-job-67347",
			template:               migrationTemplate,
			namespace:              hyperShiftMgmtNS,
			virtualmachinesintance: vmi,
		}
		defer migrationjob.deleteMigrationJob(oc)
		migrationjob.createMigrationJob(oc)

		compat_otp.By("4. Check live migration status \n")
		o.Eventually(func() bool {
			migrationStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmim", migrationjob.name, "-n", hyperShiftMgmtNS, "-o=jsonpath={.status.phase}").Output()
			return err == nil && migrationStatus == "Succeeded"
		}, "300s", "10s").Should(o.BeTrue(), "Live migration did not succeed!!")

		compat_otp.By("5. Get IP address,  hosted nodename, status of the VMI again after live migration, IP address should remind same while VM is migrated onto a new nodename, and in Ready state \n")
		currentIP, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmi", vmi, "-n", hyperShiftMgmtNS, "-o=jsonpath={.status.interfaces[0].ipAddress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("currentIP: %v\n", currentIP)
		o.Expect(currentIP).To(o.Equal(originalIP))

		currentNodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmi", vmi, "-n", hyperShiftMgmtNS, "-o=jsonpath={.metadata.labels.kubevirt\\.io\\/nodeName}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("currentNodeName: %v\n", currentNodeName)
		o.Expect(strings.Contains(currentNodeName, OriginalNodeName)).To(o.BeFalse())

		newStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmi", vmi, "-n", hyperShiftMgmtNS, "-o=jsonpath={.status.conditions[*].type}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("newStatus: %v\n", newStatus)
		o.Expect(strings.Contains(newStatus, "Ready")).To(o.BeTrue())

		compat_otp.By("6. All hosted cluster nodes should remain in Ready state 2 minutes after migration, same number of hosted cluster nodes remain in Ready state \n")
		o.Consistently(func() int {
			nodeList, err = compat_otp.GetSchedulableLinuxWorkerNodes(oc.AsAdmin().AsGuestKubeconf())
			return (len(nodeList))
		}, 120*time.Second, 10*time.Second).Should(o.Equal(origScheduleableWorkerNodeCount))

		compat_otp.By("7. Check operators state on management cluster and hosted cluster, they should all be in healthy state \n")
		checkAllClusterOperatorsState(oc, 10, 1)
		checkAllClusterOperatorsState(oc.AsGuestKubeconf(), 10, 1)

		compat_otp.By("8. Check health of OVNK on management cluster \n")
		checkOVNKState(oc)
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("OVNkube didn't trigger or rolled out successfully post oc patch"))

		compat_otp.By("9. Delete the migration job \n")
		migrationjob.deleteMigrationJob(oc)
	})

	g.It("HyperShiftMGMT-NonPreRelease-ConnectedOnly-Author:jechen-High-68417-On hosted cluster with Proxy and readinessEndpoint configured, traffic to readinessEndpoint should be sent out through hosted cluster node not mgmt cluster node, and CA bundles can be created on hosted cluster. [Disruptive]", func() {

		// This is for bug https://issues.redhat.com/browse/OCPBUGS-14819

		var (
			dirname  = "/tmp/OCP-68417"
			name     = dirname + "/OCP-68417-custom"
			validity = 3650
			caSubj   = dirname + "/OU=openshift/CN=admin-kubeconfig-signer-custom"
		)

		if !checkProxy(oc.AsGuestKubeconf()) {
			g.Skip("There is no proxy on hosted cluster, skip the test.")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		url := "www.google.com"
		ns := "68417-test-ns"

		compat_otp.By("1. Patch hosted cluster to add readiness endpoints to its proxy\n")
		origReadinessEndPoints, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedcluster", hostedClusterName, "-n", hostedclusterNS, "-o=jsonpath={.spec.configuration.proxy.readinessEndpoints}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("origReadinessEndPoints: %v\n", origReadinessEndPoints)
		patchResource := "hostedcluster/" + hostedClusterName
		patchAdd := "{\"spec\":{\"configuration\":{\"proxy\":{\"readinessEndpoints\":[\"http://" + url + "\", \"https://" + url + "\"]}}}}"

		var patchRemove string
		if origReadinessEndPoints == "" {
			origReadinessEndPoints = "[]" // when original readinessEndpoints is empty string, [] needs to be added around the empty string
		}
		patchRemove = "{\"spec\":{\"configuration\":{\"proxy\":{\"readinessEndpoints\":" + origReadinessEndPoints + "}}}}"

		defer patchResourceAsAdminNS(oc, hostedclusterNS, patchResource, patchRemove)
		patchResourceAsAdminNS(oc, hostedclusterNS, patchResource, patchAdd)

		readinessEndPoints, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedcluster", hostedClusterName, "-n", hostedclusterNS, "-o=jsonpath={.spec.configuration.proxy.readinessEndpoints}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("readinessEndPoints: %v\n", readinessEndPoints)
		o.Expect(readinessEndPoints).Should(o.And(
			o.ContainSubstring("http://"+url),
			o.ContainSubstring("https://"+url)))

		proxyIP, proxyPort := getProxyIPandPortOnHostedCluster(oc, hostedClusterName, hostedclusterNS)
		o.Expect(proxyIP).ShouldNot(o.Equal(""))
		o.Expect(proxyPort).ShouldNot(o.Equal(""))

		scheduleableNodes, err := getReadySchedulableNodesOnHostedCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2. Start tcpdump on on hosted cluster host, verify proxyIP.port string can be captured in tcpdump of all hosted cluster nodes")
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nneep -i any dst %s or src %s and port %s", proxyIP, proxyIP, proxyPort)
		for _, hostedClusterNode := range scheduleableNodes {
			tcpdumpOutput, err := oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("debug").Args("node/"+hostedClusterNode, "--", "bash", "-c", tcpdumpCmd).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(tcpdumpOutput).Should(o.ContainSubstring(proxyIP + "." + proxyPort))
		}

		compat_otp.By("3. Start tcpdump on CNO's host, verify proxyIP.port string should not be captured in tcpdump on CNO node")
		// get CNO pod on management cluster
		CNOPod := getPodName(oc, "openshift-network-operator", "name=network-operator")
		o.Expect(len(CNOPod)).ShouldNot(o.Equal(0))
		o.Expect(CNOPod[0]).ShouldNot(o.Equal(""))

		// get the node that hosts the CNO pod on mgmt cluster
		CNOHost, err := compat_otp.GetPodNodeName(oc, "openshift-network-operator", CNOPod[0])
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(CNOHost).ShouldNot(o.Equal(""))

		tcpdumpOutput, err := oc.AsAdmin().WithoutNamespace().Run("debug").Args("node/"+CNOHost, "--", "bash", "-c", tcpdumpCmd).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(tcpdumpOutput).ShouldNot(o.ContainSubstring(proxyIP + "." + proxyPort))

		compat_otp.By("4. Create test project and test pod on hosted cluster\n")
		defer oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("delete").Args("project", ns, "--ignore-not-found=true").Execute()
		oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("create").Args("namespace", ns).Execute()
		compat_otp.SetNamespacePrivileged(oc.AsGuestKubeconf(), ns)

		testPod := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		defer oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("delete").Args("pod", testPod.name, "-n", testPod.namespace, "--ignore-not-found=true").Execute()
		testPod.createPingPod(oc.AsGuestKubeconf())
		waitPodReady(oc.AsGuestKubeconf(), testPod.namespace, testPod.name)

		// find the node that hosts the test pod on hosted cluster
		testPodNode, err := compat_otp.GetPodNodeName(oc.AsGuestKubeconf(), ns, testPod.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(testPodNode).ShouldNot(o.Equal(""))

		compat_otp.By("5. Enable tcpdump on hosted cluster node where test pod resides and CNO host on management cluster\n")
		tcpdumpCmd = fmt.Sprintf("timeout 180s tcpdump -c 4 -nneep -i any host %s and port 443", url)

		// enable tcpdump on hosted cluster node
		tcpdumpOnHosted, tcpdumpOutputOnHosted, _, err := oc.AsGuestKubeconf().AsAdmin().Run("debug").Args("node/"+testPodNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer tcpdumpOnHosted.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		// enable tcpdump on CNO host on management cluster
		tcpdumpOnMgmt, tcpdumpOutputOnMgmt, _, err := oc.AsAdmin().WithoutNamespace().Run("debug").Args("-n", "default", "node/"+CNOHost, "--", "bash", "-c", tcpdumpCmd).Background()
		defer tcpdumpOnMgmt.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("6. curl https://www.google.com from test pod on hosted cluster node")
		pingCurlCmds := fmt.Sprintf("ping -c 1 %s ; curl  -I -k https://%s --connect-timeout 5", url, url)
		output, err := oc.AsGuestKubeconf().AsAdmin().Run("exec").Args("-n", testPod.namespace, testPod.name, "--", "/bin/sh", "-c", pingCurlCmds).Output()
		o.Expect(err).To(o.HaveOccurred()) // error is expected when trying to ping or curl the url due to proxy

		// match out the IP address for the readinessEndpoint from output of ping command
		re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
		urlIPv4 := re.FindAllString(output, -1)[0]
		e2e.Logf("urlIPv4: %v\n", urlIPv4)

		compat_otp.By("7. Verify traffic to readinessEndpoint goes through node on hosted cluster not through node on management cluster")
		cmdErr1 := tcpdumpOnHosted.Wait()
		o.Expect(cmdErr1).NotTo(o.HaveOccurred())
		o.Expect(tcpdumpOutputOnHosted.String()).To(o.ContainSubstring(urlIPv4))

		cmdErr2 := tcpdumpOnMgmt.Wait()
		o.Expect(cmdErr2).NotTo(o.HaveOccurred())
		o.Expect(tcpdumpOutputOnMgmt.String()).NotTo(o.ContainSubstring(urlIPv4))

		// Generation of a new self-signed CA
		compat_otp.By("8.  Generation of a new self-signed CA")
		defer os.RemoveAll(dirname)
		err = os.MkdirAll(dirname, 0777)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Generate the CA private key")
		opensslCmd := fmt.Sprintf(`openssl genrsa -out %s-ca.key 4096`, name)
		err = exec.Command("bash", "-c", opensslCmd).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("9. Create the CA certificate")
		opensslCmd = fmt.Sprintf(`openssl req -x509 -new -nodes -key %s-ca.key -sha256 -days %d -out %s-ca.crt -subj %s`, name, validity, name, caSubj)
		err = exec.Command("bash", "-c", opensslCmd).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("10. Create a configmap from the CA onto hosted cluster")
		configmapName := "custom-ca"
		customCA := "--from-file=ca-bundle.crt=" + name + "-ca.crt"
		e2e.Logf("\n customCA is  %v", customCA)
		defer func() {
			_, delErr := oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("delete").Args("configmap", configmapName, "-n", "openshift-config", "--ignore-not-found=true").Output()
			o.Expect(delErr).NotTo(o.HaveOccurred())
		}()
		_, createErr := oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("create").Args("configmap", configmapName, customCA, "-n", "openshift-config").Output()
		o.Expect(createErr).NotTo(o.HaveOccurred())

		g.By("11. Check if configmap is successfully configured in openshift-config namesapce on hosted cluster")
		err = checkConfigMap(oc.AsGuestKubeconf(), "openshift-config", configmapName)
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("cm %v not found on hosted cluster", configmapName))

		g.By("12. Patch the configmap created above to hosted cluster, verify trustedCA can be created")
		defer func() {
			innerPollingInterval := 10 * time.Second
			innerPollingIterationCount := 3
			outerPollingInterval := 15 * time.Second
			outerPollingTimeout := 5 * time.Minute

			// Returns true only if all Nodes stay ready for a while
			nodesStayHealthyForAWhile := func() bool {
				for count := 0; count < innerPollingIterationCount; count++ {

					// Wait a little before checking all nodes on hosted cluster all together
					time.Sleep(innerPollingInterval)
					for _, hostedClusterNode := range scheduleableNodes {
						statusOutput, err := oc.AsGuestKubeconf().Run("get").Args("nodes", hostedClusterNode, "-ojsonpath={.status.conditions[-1].status}").Output()
						o.Expect(err).NotTo(o.HaveOccurred())
						e2e.Logf("\n status for node %v is: %v", hostedClusterNode, statusOutput)
						if statusOutput != "True" { // when node is in Ready state, status output returned from line 295 is "True"
							return false
						}
					}
				}
				return true
			}

			o.Eventually(nodesStayHealthyForAWhile).WithTimeout(outerPollingTimeout).WithPolling(outerPollingInterval).Should(o.BeTrue())
		}()

		origTrustedCA, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedcluster", hostedClusterName, "-n", hostedclusterNS, "-o=jsonpath={.spec.configuration.proxy.trustedCA.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("origTrustedCA: %v\n", origTrustedCA)
		patchRemove = "{\"spec\":{\"configuration\":{\"proxy\":{\"trustedCA\":{\"name\":\"" + origTrustedCA + "\"}}}}}"
		patchAdd = "{\"spec\":{\"configuration\":{\"proxy\":{\"trustedCA\":{\"name\":\"custom-ca\"}}}}}"
		defer patchResourceAsAdminNS(oc, hostedclusterNS, patchResource, patchRemove)
		patchResourceAsAdminNS(oc, hostedclusterNS, patchResource, patchAdd)
		trustedCAName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedcluster", hostedClusterName, "-n", hostedclusterNS, "-o=jsonpath={.spec.configuration.proxy.trustedCA.name}").Output()
		e2e.Logf("trustedCAName: %v\n", trustedCAName)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(trustedCAName).Should(o.Equal(configmapName))

		patchResourceAsAdminNS(oc, hostedclusterNS, patchResource, patchRemove)

	})

	g.It("HyperShiftMGMT-NonPreRelease-Longduration-ConnectedOnly-Author:jechen-High-70261-Network Connectivity is not broken even if BM Kubevirt VM migration fails. [Disruptive]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		migrationTemplate := filepath.Join(buildPruningBaseDir, "kubevirt-live-migration-job-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		ns1 := "70261-test-ns1-on-hostedcluster" //namespace for hosted cluster has to be all lowercased, that is why hostedcluster is used here, instead of hostedCluster
		ns2 := "70261-test-ns2-on-hostedcluster"

		hyperShiftMgmtNS := hostedclusterNS + "-" + hostedClusterName
		e2e.Logf("hyperShiftMgmtNS: %v\n", hyperShiftMgmtNS)

		mgmtClusterPlatform := compat_otp.CheckPlatform(oc)
		e2e.Logf("mgmt cluster platform: %v\n", mgmtClusterPlatform)

		nestedClusterPlatform := compat_otp.CheckPlatform(oc.AsAdmin().AsGuestKubeconf())
		e2e.Logf("hosted cluster platform: %v\n", nestedClusterPlatform)

		if !strings.Contains(mgmtClusterPlatform, "baremetal") || !strings.Contains(nestedClusterPlatform, "kubevirt") {
			g.Skip("Live migration can only be performed on Baremetal Kubevirt Hypershift, skip all other platforms")
		}

		compat_otp.By("1. Get node list on hosted cluster\n")
		allNodeListOnHostedCluster, err := compat_otp.GetSchedulableLinuxWorkerNodes(oc.AsAdmin().AsGuestKubeconf())
		o.Expect(err).NotTo(o.HaveOccurred())
		origScheduleableWorkerNodeCount := len(allNodeListOnHostedCluster)

		nodePoolName := compat_otp.GetNodePoolNamesbyHostedClusterName(oc, hostedClusterName, hostedclusterNS)
		o.Expect(len(nodePoolName)).ShouldNot(o.Equal(0))
		nodeNames, err := compat_otp.GetAllNodesByNodePoolNameInHostedCluster(oc, nodePoolName[0])
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeNames)).ShouldNot(o.Equal(0))
		e2e.Logf("The nodes in nodepool %v is:\n%v", nodePoolName[0], nodeNames)

		compat_otp.By("2. Get the first VMI on mgmt cluster for live migration, check it is live migratable \n")
		vmi, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmi", "-n", hyperShiftMgmtNS, "-o=jsonpath={.items[0].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmi", vmi, "-n", hyperShiftMgmtNS, "-o=jsonpath={.status.conditions[*].type}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("status: %v\n", status)
		o.Expect(strings.Contains(status, "Ready")).To(o.BeTrue())
		o.Expect(strings.Contains(status, "LiveMigratable")).To(o.BeTrue())

		compat_otp.By("3. Before perform live migration, create test project and test pod on the node that will involve live migration\n")
		defer oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("delete").Args("project", ns1, "--ignore-not-found=true").Execute()
		oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("create").Args("namespace", ns1).Execute()
		compat_otp.SetNamespacePrivileged(oc.AsGuestKubeconf(), ns1)

		testPod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  vmi,
			template:  pingPodNodeTemplate,
		}

		defer oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("delete").Args("pod", testPod1.name, "-n", testPod1.namespace, "--ignore-not-found=true").Execute()
		testPod1.createPingPodNode(oc.AsGuestKubeconf())
		waitPodReady(oc.AsGuestKubeconf(), testPod1.namespace, testPod1.name)

		compat_otp.By("4. Delibrately set kubevirt.io/func-test-virt-launcher-fail-fast=true on the VMI that will be performed live migration so its migration will fail\n")
		defer oc.AsAdmin().WithoutNamespace().Run("annotate").Args("vmi", vmi, "-n", hyperShiftMgmtNS, "kubevirt.io/func-test-virt-launcher-fail-fast=false", "--overwrite").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("annotate").Args("vmi", vmi, "-n", hyperShiftMgmtNS, "kubevirt.io/func-test-virt-launcher-fail-fast=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("5. Perform live migration on the VMI \n")
		migrationjob := migrationDetails{
			name:                   "migration-job-70261",
			template:               migrationTemplate,
			namespace:              hyperShiftMgmtNS,
			virtualmachinesintance: vmi,
		}

		defer migrationjob.deleteMigrationJob(oc)
		migrationjob.createMigrationJob(oc)

		compat_otp.By("6. Check live migration status, live migration is expected to fail due to annoation from step 4 \n")
		o.Eventually(func() bool {
			migrationStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("vmim", migrationjob.name, "-n", hyperShiftMgmtNS, "-o=jsonpath={.status.phase}").Output()
			return err == nil && migrationStatus == "Failed"
		}, "300s", "10s").Should(o.BeTrue(), "Live migration did not fail as expected!!")

		compat_otp.By("7. All hosted cluster nodes should remain in Ready state 2 minutes after attempted migration, same number of hosted cluster nodes remain in Ready state \n")
		o.Consistently(func() int {
			nodeList, err := compat_otp.GetSchedulableLinuxWorkerNodes(oc.AsAdmin().AsGuestKubeconf())
			o.Expect(err).NotTo(o.HaveOccurred())
			return (len(nodeList))
		}, 120*time.Second, 10*time.Second).Should(o.Equal(origScheduleableWorkerNodeCount))

		compat_otp.By("8. Check operators state on management cluster and hosted cluster, they should all be in healthy state \n")
		checkAllClusterOperatorsState(oc, 10, 1)
		checkAllClusterOperatorsState(oc.AsGuestKubeconf(), 10, 1)

		compat_otp.By("9. Check health of OVNK on management cluster \n")
		checkOVNKState(oc)

		compat_otp.By("10. Create a second test project and test pod on a different node of the hosted cluster after attempted live migration\n")

		// remove the node the involves attempted live migration from node list, get the other nodes from the hosted cluster
		var nodeLeft []string
		for i, v := range nodeNames {
			if v == vmi {
				nodeLeft = append(nodeNames[:i], nodeNames[i+1:]...)
				break
			}
		}
		e2e.Logf("\n Get other nodes from node list of the hosted cluster: %v\n", nodeLeft)

		defer oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("delete").Args("project", ns2, "--ignore-not-found=true").Execute()
		oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("create").Args("namespace", ns2).Execute()
		compat_otp.SetNamespacePrivileged(oc.AsGuestKubeconf(), ns2)

		var testPod2Node string
		if len(nodeLeft) < 1 {
			e2e.Logf("There is no other node on the hosted cluster, create testPod2 on same VMI node")
			testPod2Node = vmi
		} else {
			e2e.Logf("There is some other node on the hosted cluster, create testPod2 on some other node")
			testPod2Node = nodeLeft[0]
		}
		testPod2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns2,
			nodename:  testPod2Node,
			template:  pingPodNodeTemplate,
		}
		defer oc.AsGuestKubeconf().AsAdmin().WithoutNamespace().Run("delete").Args("pod", testPod2.name, "-n", testPod2.namespace, "--ignore-not-found=true").Execute()
		testPod2.createPingPodNode(oc.AsGuestKubeconf())
		waitPodReady(oc.AsGuestKubeconf(), testPod2.namespace, testPod2.name)

		compat_otp.By("11. Pod created before attempted live migration should be able to communicate with pod created after attempted live migration\n")
		testPod1IP1, testPod1IP2 := getPodIP(oc.AsGuestKubeconf(), testPod1.namespace, testPod1.name)
		e2e.Logf("\n Got ip address for testPod1 is: %v, %v\n", testPod1IP1, testPod1IP2)
		testPod2IP1, testPod2IP2 := getPodIP(oc.AsGuestKubeconf(), testPod2.namespace, testPod2.name)
		e2e.Logf("\n Got ip address for testPod2 is: %v, %v\n", testPod2IP1, testPod2IP2)

		// Curl testPod 1 from testPod2
		cmd1 := "curl --connect-timeout 5 -s " + testPod1IP1 + ":8080"
		cmd2 := "curl --connect-timeout 5 -s " + testPod1IP2 + ":8080"
		if testPod1IP2 != "" {
			_, err := execCommandInSpecificPod(oc.AsGuestKubeconf(), testPod2.namespace, testPod2.name, cmd1)
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = execCommandInSpecificPod(oc.AsGuestKubeconf(), testPod2.namespace, testPod2.name, cmd2)
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			_, err := execCommandInSpecificPod(oc.AsGuestKubeconf(), testPod2.namespace, testPod2.name, cmd1)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		// Curl from testPod2 from testPod1
		cmd1 = "curl --connect-timeout 5 -s " + testPod2IP1 + ":8080"
		cmd2 = "curl --connect-timeout 5 -s " + testPod2IP2 + ":8080"
		if testPod2IP2 != "" {
			_, err := execCommandInSpecificPod(oc.AsGuestKubeconf(), testPod1.namespace, testPod1.name, cmd1)
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = execCommandInSpecificPod(oc.AsGuestKubeconf(), testPod1.namespace, testPod1.name, cmd2)
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			_, err := execCommandInSpecificPod(oc.AsGuestKubeconf(), testPod1.namespace, testPod1.name, cmd1)
			o.Expect(err).NotTo(o.HaveOccurred())
		}
	})

	g.It("Author:jechen-HyperShiftMGMT-ConnectedOnly-High-74596-Even with a FQDN proxy configured on hostedCluster, connection can be made to the readinessEndpoint under noProxy that bypass the proxy [Disruptive]", func() {

		// This is for bug https://issues.redhat.com/browse/OCPBUGS-33526

		buildPruningBaseDir := testdata.FixturePath("networking")
		squidProxyDeploymentFile := filepath.Join(buildPruningBaseDir, "proxy_deployment.yaml")
		url := "www.google.com"

		compat_otp.By("1. create new namespace\n")
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-scc-to-user", "anyuid", "-z", "default", "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2. Deploy a squid deployment in the namespace then expose its service\n")
		defer removeResource(oc, true, true, "deployment", "squid-deployment", ns)
		defer removeResource(oc, true, true, "service", "squid-deployment", ns)
		createResourceFromFile(oc, ns, squidProxyDeploymentFile)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment", "-n", ns, "squid-deployment").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "squid-deployment")).To(o.BeTrue())

		err = waitForPodWithLabelReady(oc, ns, "app=squid")
		compat_otp.AssertWaitPollNoErr(err, "Not all squid pods with label app=squid are ready")
		squidPods := getPodName(oc, ns, "app=squid")
		o.Expect(len(squidPods)).Should(o.Equal(1))
		defer removeResource(oc, true, true, "pod", squidPods[0], ns)

		err = oc.AsAdmin().WithoutNamespace().Run("expose").Args("deployment/squid-deployment", "--type=LoadBalancer", "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		LBSVCHostname := getLBSVCHostname(oc, ns, "squid-deployment")
		e2e.Logf("\n\n\n Got hostname for the squid service: %v\n", LBSVCHostname)

		compat_otp.By("3. Patch hosted cluster to add squid proxy as its proxy\n")
		origProxy, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedcluster", hostedClusterName, "-n", hostedclusterNS, "-o=jsonpath={.spec.configuration.proxy}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		patchResource := "hostedcluster/" + hostedClusterName
		patchRestore := fmt.Sprintf(`[{"op": "replace", "path": "/spec/configuration/proxy", "value":%s}]`, origProxy)
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", hostedclusterNS, patchResource, "--type=json", "-p", patchRestore).Execute()
			proxy, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedcluster", hostedClusterName, "-n", hostedclusterNS, "-o=jsonpath={.spec.configuration.proxy}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("proxy is restored to: %s\n", proxy)
			o.Expect(proxy).Should(o.ContainSubstring(origProxy))
		}()

		proxyValue := "http://" + LBSVCHostname + ":3128"
		patchAdd := "{\"spec\":{\"configuration\":{\"proxy\":{\"httpProxy\":\"" + proxyValue + "\", \"httpsProxy\":\"" + proxyValue + "\"}}}}"
		patchResourceAsAdminNS(oc, hostedclusterNS, patchResource, patchAdd)

		proxy, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedcluster", hostedClusterName, "-n", hostedclusterNS, "-o=jsonpath={.spec.configuration.proxy}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("proxy: %s\n", proxy)
		expectedProxy1 := fmt.Sprintf(`"httpProxy":"http://%s:3128"`, LBSVCHostname)
		expectedProxy2 := fmt.Sprintf(`"httpsProxy":"http://%s:3128"`, LBSVCHostname)
		o.Expect(proxy).Should(o.And(o.ContainSubstring(expectedProxy1), o.ContainSubstring(expectedProxy2)))

		compat_otp.By("4. Patch hosted cluster to add squid proxy to noProxy, then set its readinessEndpoint to www.google.com\n")
		patchAdd = "{\"spec\":{\"configuration\":{\"proxy\":{\"noProxy\":\"" + LBSVCHostname + "\"}}}}"
		patchResourceAsAdminNS(oc, hostedclusterNS, patchResource, patchAdd)

		readinessEP := "https://" + url
		patchAdd = "{\"spec\":{\"configuration\":{\"proxy\":{\"readinessEndpoints\":[\"" + readinessEP + "\"]}}}}"
		patchResourceAsAdminNS(oc, hostedclusterNS, patchResource, patchAdd)

		noProxyOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedcluster", hostedClusterName, "-n", hostedclusterNS, "-o=jsonpath={.spec.configuration.proxy.noProxy}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(noProxyOutput, LBSVCHostname)).To(o.BeTrue())
		readinessEPOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedcluster", hostedClusterName, "-n", hostedclusterNS, "-o=jsonpath={.spec.configuration.proxy.readinessEndpoints}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(readinessEPOutput, url)).To(o.BeTrue())

		// give some time for readinessEndpoints under noProxy to take effect
		time.Sleep(30 * time.Second)

		compat_otp.By("5. Check squid pod to confirm connectivity to www.google.com succeed\n")
		expectedString := fmt.Sprintf(`CONNECT %s:443`, url)
		o.Eventually(func() bool {
			podLogs, LogErr := checkLogMessageInPod(oc, ns, "tailer", squidPods[0], "google.com")
			o.Expect(LogErr).NotTo(o.HaveOccurred())
			return strings.Contains(podLogs, expectedString)
		}, "5m", "10s").Should(o.BeTrue(), "Connection to the readinessEndpoint under noProxy did not succeed!!")
	})

})
