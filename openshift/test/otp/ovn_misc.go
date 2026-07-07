package otp

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"

	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/utils"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[sig-network] SDN OVN Misc", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("otp-ovn-misc")

	g.BeforeEach(func() {
		networkType := otputils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs][NETWORKCUSIM] 80439-pod to external traffic doesn't require OVN to create mac-binding entry for Join subnet gateway IP [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)
		var joinSubGWIP string

		ipStackType := otputils.CheckIPStackType(oc)
		if ipStackType != "ipv4single" {
			g.Skip("The is supported on IPv4 cluster only, skip for other IP stack type for now")
		}
		joinSubGWIP = "100.64.0.1"
		workerNode, err := otputils.GetFirstWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Create pod on one worker node")
		ns := oc.Namespace()
		pod := otputils.PingPodResourceNode{
			Name:      "hello-pod",
			Namespace: ns,
			Nodename:  workerNode,
			Template:  pingPodNodeTemplate,
		}
		defer pod.DeletePingPodNode(oc)
		pod.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod.Namespace, pod.Name)

		g.By("Check pod to external traffic to make sure before proceeding")
		otputils.CurlPod2ExternalPass(oc, ns, "hello-pod")

		g.By("Verify no rtoj mac_binding entry for Join subnet gw IP in SBDB")
		ovnKubeNodePod := otputils.OvnkubeNodePod(oc, workerNode)
		macBindingCmd := "ovn-sbctl find mac_binding"
		macBindCmdOutput, err := otputils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, macBindingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(macBindCmdOutput, joinSubGWIP)).ShouldNot(o.BeTrue())
	})

	g.It("[JIRA:Networking][OTP] 64151-check node healthz port is enabled for ovnk in CNO for GCP", func() {
		platform := otputils.CheckPlatform(oc)
		if !strings.Contains(platform, "gcp") {
			g.Skip("Skip for un-expected platform, not GCP!")
		}

		g.By("Expect healtz-bind-address to be present in ovnkube-config config map")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("cm", "-n", "openshift-ovn-kubernetes", "ovnkube-config", "-ojson").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "0.0.0.0:10256")).To(o.BeTrue())

		g.By("Make sure healtz-bind-address is reachable via nodes")
		workerNode, err := otputils.GetFirstLinuxWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		output, err = otputils.DebugNode(oc, workerNode, "bash", "-c", "curl -v http://0.0.0.0:10256/healthz")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("HTTP/1.1 200 OK"))
	})

	g.It("[JIRA:Networking][OTP][NETWORKCUSIM] 74589-Pod-to-external TCP connectivity using port in range of snat port", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		testPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		url := "www.example.com"

		ipStackType := otputils.CheckIPStackType(oc)
		if otputils.CheckDisconnect(oc) || ipStackType == "ipv6single" {
			g.Skip("Skip the test on disconnected cluster or singlev6 cluster.")
		}

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough node available, need at least two nodes for the test, skip the case!!")
		}

		g.By("1. create a namespace, create nodeport service on one node")
		ns := oc.Namespace()
		otputils.SetNamespacePrivileged(oc, ns)

		g.By("2. Create a hello pod in ns")
		pod1 := otputils.PingPodResourceNode{
			Name:      "hello-pod",
			Namespace: ns,
			Nodename:  nodeList.Items[0].Name,
			Template:  testPodNodeTemplate,
		}
		pod1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("3. Create a nodePort type service fronting the above pod")
		svc := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "NodePort",
			IpFamilyPolicy:        "",
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "",
			Template:              genericServiceTemplate,
		}
		if ipStackType == "dualstack" {
			svc.IpFamilyPolicy = "PreferDualStack"
		} else {
			svc.IpFamilyPolicy = "SingleStack"
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				otputils.RemoveResource(oc, true, true, "service", svc.Servicename, "-n", svc.Namespace)
			}
		}()
		svc.CreateServiceFromParams(oc)

		g.By("4. Get NodePort at which service listens.")
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.Servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. From external, curl NodePort service with its port to make sure NodePort service works")
		otputils.CurlNodePortPass(oc, nodeList.Items[1].Name, nodeList.Items[0].Name, nodePort)

		g.By("6. Create another test pod on another node, from the test pod to curl local port of external url, verify the connection can succeed")
		pod2 := otputils.PingPodResourceNode{
			Name:      "testpod",
			Namespace: ns,
			Nodename:  nodeList.Items[1].Name,
			Template:  testPodNodeTemplate,
		}
		pod2.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, ns, pod2.Name)

		cmd := fmt.Sprintf("curl --local-port 32012 -v -I -L http://%s", url)
		expectedString := fmt.Sprintf(`^* Connected to %s \(([\d\.]+)\) port 80 `, url)
		re := regexp.MustCompile(expectedString)
		connectErr := wait.Poll(3*time.Second, 15*time.Second, func() (bool, error) {
			_, execCmdOutput, err := e2eoutput.RunHostCmdWithFullOutput(ns, pod2.Name, cmd)
			if err != nil {
				e2e.Logf("Getting err :%v, trying again...", err)
				return false, nil
			}
			if !re.MatchString(execCmdOutput) {
				e2e.Logf("Did not get expected output, trying again...")
				e2e.Logf("\n execCmdOutput is %v\n", execCmdOutput)
				return false, nil
			}
			return true, nil
		})
		otputils.AssertWaitPollNoErr(connectErr, fmt.Sprintf("Connection to %s did not succeed!", url))
	})

	g.It("[JIRA:Networking][OTP][NETWORKCUSIM] 75613-Should be able to access applications when client ephemeral port is 22623 or 22624", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
		)

		g.By("Get new namespace")
		ns1 := oc.Namespace()

		g.By("Create test pods")
		otputils.CreateResourceFromFile(oc, ns1, testPodFile)
		err := otputils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		otputils.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		g.By("Should be able to access applications when client ephemeral port is 22623 or 22624")
		testPodName := otputils.GetPodName(oc, ns1, "name=test-pods")
		pod1Name := testPodName[0]
		localPort := []string{"22623", "22624"}

		ipStackType := otputils.CheckIPStackType(oc)
		if ipStackType == "dualstack" {
			pod2IP1, pod2IP2 := otputils.GetPodIP(oc, ns1, testPodName[1])
			for i := 0; i < 2; i++ {
				curlCmd := fmt.Sprintf("curl --connect-timeout 5 -s %s --local-port %s", net.JoinHostPort(pod2IP1, "8080"), localPort[i])
				_, err := e2eoutput.RunHostCmdWithRetries(ns1, pod1Name, curlCmd, 60*time.Second, 120*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())
				curlCmd = fmt.Sprintf("curl --connect-timeout 5 -s %s --local-port %s", net.JoinHostPort(pod2IP2, "8080"), localPort[i])
				_, err = e2eoutput.RunHostCmdWithRetries(ns1, pod1Name, curlCmd, 60*time.Second, 120*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		} else {
			pod2IP1, _ := otputils.GetPodIP(oc, ns1, testPodName[1])
			for i := 0; i < 2; i++ {
				curlCmd := fmt.Sprintf("curl --connect-timeout 5 -s %s --local-port %s", net.JoinHostPort(pod2IP1, "8080"), localPort[i])
				_, err := e2eoutput.RunHostCmdWithRetries(ns1, pod1Name, curlCmd, 60*time.Second, 120*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}
	})

	g.It("[JIRA:Networking][OTP][NETWORKCUSIM] 75758-Bad certificate should not cause ovn pods crash [Serial]", func() {
		g.By("Get one worker node.")
		node1, err := otputils.GetFirstCoreOsWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(node1) < 1 {
			g.Skip("Skip the test as no enough worker nodes.")
		}

		g.By("Get the ovnkube-node pod on specific node.")
		ovnPod := otputils.OvnkubeNodePod(oc, node1)

		g.By("Create bad ovnkube-node-certs certificate")
		cmd := `cd /var/lib/ovn-ic/etc/ovnkube-node-certs && ls | grep '^ovnkube-client-.*\.pem$' | grep -v 'ovnkube-client-current.pem' | xargs -I {} sh -c 'echo "" > {}'`
		_, err = otputils.DebugNodeWithChroot(oc, node1, "bash", "-c", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Restart ovnkube-node pod on specific node.")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", ovnPod, "-n", "openshift-ovn-kubernetes", "--ignore-not-found=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Wait ovnkube-node pod to be running")
		ovnPod = otputils.OvnkubeNodePod(oc, node1)
		otputils.AssertPodToBeReady(oc, ovnPod, "openshift-ovn-kubernetes")
	})

	g.It("[JIRA:Networking][OTP] 68418-Same name pod can be recreated on new node and still work on OVN cluster [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		kubeletKillerPodTemplate := filepath.Join(buildPruningBaseDir, "kubelet-killer-pod-template.yaml")

		g.By("1. Create a new machineset, get the new node created")
		otputils.SkipIfMachineAPIUnavailable(oc)
		infrastructureName := otputils.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-68418"

		defer otputils.WaitForMachineSetDeleted(oc, machinesetName)
		defer otputils.DeleteMachineSet(oc, machinesetName)
		otputils.CreateMachineSetFromExisting(oc, machinesetName, 1)

		machineName := otputils.GetMachineNamesFromMachineSet(oc, machinesetName)
		o.Expect(len(machineName)).ShouldNot(o.Equal(0))
		nodeName := otputils.GetNodeNameFromMachine(oc, machineName[0])
		e2e.Logf("Get nodeName: %v", nodeName)

		g.By("2. Create kubelet-killer pod on the node")
		kkPod := otputils.KubeletKillerPod{
			Name:      "kubelet-killer-68418",
			Namespace: "openshift-machine-api",
			Nodename:  nodeName,
			Template:  kubeletKillerPodTemplate,
		}
		kkPod.CreateKubeletKillerPodOnNode(oc)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "kubelet-killer-68418", "-n", kkPod.Namespace, "--ignore-not-found=true").Execute()

		podStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", kkPod.Name, "-n", kkPod.Namespace, "-o=jsonpath={.status.phase}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("kkPod status:%v", podStatus)
		o.Expect(regexp.MatchString("Pending", podStatus)).Should(o.BeTrue())

		otputils.CheckNodeStatus(oc, nodeName, "NotReady")

		g.By("3. Delete the node and its machineset, and delete the kubelet-killer pod")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("machines.machine.openshift.io", machineName[0], "-n", "openshift-machine-api").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		otputils.DeleteMachineSet(oc, machinesetName)
		otputils.WaitForMachineSetRunning(oc, 0, machinesetName)
		otputils.WaitForMachineSetDeleted(oc, machinesetName)

		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "kubelet-killer-68418", "-n", kkPod.Namespace, "--ignore-not-found=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Recreate the machineset, get the newer node created")
		otputils.CreateMachineSetFromExisting(oc, machinesetName, 1)

		machineName = otputils.GetMachineNamesFromMachineSet(oc, machinesetName)
		o.Expect(len(machineName)).ShouldNot(o.Equal(0))
		newNodeName := otputils.GetNodeNameFromMachine(oc, machineName[0])

		g.By("5. Recreate kubelet-killer pod with same pod name on the newer node")
		kkPod2 := otputils.KubeletKillerPod{
			Name:      "kubelet-killer-68418",
			Namespace: "openshift-machine-api",
			Nodename:  newNodeName,
			Template:  kubeletKillerPodTemplate,
		}
		kkPod2.CreateKubeletKillerPodOnNode(oc)

		podStatus, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", kkPod2.Name, "-n", kkPod2.Namespace, "-o=jsonpath={.status.phase}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("kkPod2 status:%v", podStatus)
		o.Expect(regexp.MatchString("Pending", podStatus)).Should(o.BeTrue())

		otputils.CheckNodeStatus(oc, newNodeName, "NotReady")

		g.By("6. Verify ErrorAddingLogicalPort or FailedCreateSandBox events are not generated when pod is recreated")
		podDescribe, err := oc.AsAdmin().WithoutNamespace().Run("describe").Args("pod", kkPod2.Name, "-n", kkPod2.Namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(regexp.MatchString("ErrorAddingLogicalPort", podDescribe)).Should(o.BeFalse())
		o.Expect(regexp.MatchString("FailedCreatedPodSandBox", podDescribe)).Should(o.BeFalse())

		g.By("7. Cleanup after test: delete the node and its machineset, then delete the kubelet-killer pod")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("machines.machine.openshift.io", machineName[0], "-n", "openshift-machine-api").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		otputils.DeleteMachineSet(oc, machinesetName)
		time.Sleep(180 * time.Second)
		otputils.WaitForMachineSetRunning(oc, 0, machinesetName)

		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "kubelet-killer-68418", "-n", kkPod.Namespace, "--ignore-not-found=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("[JIRA:Networking][OTP] 34674-Ensure ovnkube-master nbdb and sbdb exit properly [Serial]", func() {
		g.By("1. Enable ovnkube-master pod debug log by ovn-appctl")
		ovnMasterPodName := otputils.GetOVNKMasterOVNkubeNode(oc)
		o.Expect(ovnMasterPodName).NotTo(o.BeEmpty())
		masterNodeName, err := otputils.GetPodNodeName(oc, "openshift-ovn-kubernetes", ovnMasterPodName)
		o.Expect(err).NotTo(o.HaveOccurred())

		ctls := []string{"ovnnb_db.ctl", "ovnsb_db.ctl"}
		for _, ctl := range ctls {
			dbgCmd := fmt.Sprintf("ovn-appctl -t /var/run/ovn/%s vlog/set console:jsonrpc:dbg", ctl)
			_, err := otputils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, dbgCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("2. Check ovnkube-master pod debug log enabled successfully and make hard-link(ln) to preserve log")
		logsPath := "/var/log/pods/openshift-ovn-kubernetes_ovnkube-node-*"
		var wg sync.WaitGroup
		database := []string{"nbdb", "sbdb"}
		for _, db := range database {
			wg.Add(1)
			go func() {
				defer g.GinkgoRecover()
				defer wg.Done()
				logPath := filepath.Join(logsPath, db, "*.log")
				checkErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, false, func(cxt context.Context) (bool, error) {
					resultOutput, err := otputils.DebugNodeWithChroot(oc, masterNodeName, "/bin/bash", "-c", fmt.Sprintf("tail -10 %s", logPath))
					o.Expect(err).NotTo(o.HaveOccurred())
					if strings.Contains(resultOutput, "jsonrpc") {
						e2e.Logf("ovnkube-pod debug log has been successfully enabled!!!")
						_, lnErr := otputils.DebugNodeWithChroot(oc, masterNodeName, "/bin/bash", "-c", fmt.Sprintf("ln -v $(ls -1t %s | head -n 1) /var/log/%s.log", logPath, db))
						o.Expect(lnErr).NotTo(o.HaveOccurred())
						return true, nil
					}
					e2e.Logf("%v, Waiting for ovnkube-master pod debug log enable, try again ...,", err)
					return false, nil
				})
				otputils.AssertWaitPollNoErr(checkErr, "Enable ovnkube-master pod debug log timeout.")
			}()
		}
		wg.Wait()

		g.By("3. delete the ovnkube-master pod and check log process should be exited")
		defer otputils.CheckOVNKState(oc)
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", ovnMasterPodName, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, db := range database {
			wg.Add(1)
			go func() {
				defer g.GinkgoRecover()
				defer wg.Done()
				defer otputils.DebugNodeWithChroot(oc, masterNodeName, "/bin/bash", "-c", fmt.Sprintf("rm -f /var/log/%s.log", db))
				checkErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, false, func(cxt context.Context) (bool, error) {
					output, err := otputils.DebugNodeWithChroot(oc, masterNodeName, "/bin/bash", "-c", fmt.Sprintf("tail -10 /var/log/%s.log", db))
					o.Expect(err).NotTo(o.HaveOccurred())
					if strings.Contains(output, fmt.Sprintf("Exiting ovn%s_db", strings.Split(db, "db")[0])) {
						e2e.Logf("ovnkube-master pod %s exit properly!!!", db)
						return true, nil
					}
					e2e.Logf("%v, Waiting for ovnkube-master pod log sync up, try again ...,", err)
					return false, nil
				})
				otputils.AssertWaitPollNoErr(checkErr, fmt.Sprintf("Check ovnkube-master pod %s debug log timeout.", db))
			}()
		}
		wg.Wait()
	})

	g.It("[JIRA:Networking][OTP] 69875-Check apbexternalroute status when there is zone reported failure [Serial]", func() {
		ipStackType := otputils.CheckIPStackType(oc)
		var externalGWIP1, externalGWIP2 string
		if ipStackType == "dualstack" {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "2011::11"
		} else if ipStackType == "ipv6single" {
			externalGWIP1 = "2011::11"
			externalGWIP2 = "2011::12"
		} else {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "1.1.1.2"
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		apbExternalRouteTemplate := filepath.Join(buildPruningBaseDir, "apbexternalroute-static-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		workerNode, getWorkerErr := otputils.GetFirstLinuxWorkerNode(oc)
		o.Expect(getWorkerErr).NotTo(o.HaveOccurred())

		g.By("1. Create pod on one worker node")
		ns := oc.Namespace()
		pod := otputils.PingPodResourceNode{
			Name:      "hello-pod",
			Namespace: ns,
			Nodename:  workerNode,
			Template:  pingPodNodeTemplate,
		}
		defer pod.DeletePingPodNode(oc)
		pod.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod.Namespace, pod.Name)

		g.By("2. Remove node annotation k8s.ovn.org/l3-gateway-config")
		annotation, getAnnotationErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("node/"+workerNode, "-o", "jsonpath='{.metadata.annotations.k8s\\.ovn\\.org/l3-gateway-config}'").Output()
		o.Expect(getAnnotationErr).NotTo(o.HaveOccurred())
		defer otputils.AddAnnotationsToSpecificResource(oc, "node/"+workerNode, "", "k8s.ovn.org/l3-gateway-config="+strings.Trim(annotation, "'"))
		otputils.RemoveAnnotationFromSpecificResource(oc, "node/"+workerNode, "", "k8s.ovn.org/l3-gateway-config")

		g.By("3. Create Admin Policy Based External route object")
		apbExternalRoute := otputils.ApbStaticExternalRoute{
			Name:       "externalgw-69875",
			Labelkey:   "kubernetes.io/metadata.name",
			Labelvalue: ns,
			Ip1:        externalGWIP1,
			Ip2:        externalGWIP2,
			Bfd:        false,
			Template:   apbExternalRouteTemplate,
		}
		defer apbExternalRoute.DeleteAPBExternalRoute(oc)
		apbExternalRoute.CreateAPBExternalRoute(oc)

		g.By("4. Check status of apbexternalroute object")
		checkErr := otputils.CheckAPBExternalRouteStatus(oc, apbExternalRoute.Name, "Fail")
		otputils.AssertWaitPollNoErr(checkErr, fmt.Sprintf("apbexternalroute %s doesn't show Fail in time", apbExternalRoute.Name))
		messages, messagesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", apbExternalRoute.Name, `-ojsonpath={.status.messages}`).Output()
		o.Expect(messagesErr).NotTo(o.HaveOccurred())
		nodes, getNodeErr := otputils.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			if node == workerNode {
				o.Expect(messages).Should(o.ContainSubstring(node + ": " + node + " failed to apply policy"))
			} else {
				o.Expect(messages).Should(o.ContainSubstring(node + ": configured external gateway IPs: " + apbExternalRoute.Ip1 + "," + apbExternalRoute.Ip2))
			}
		}
	})

	g.It("[JIRA:Networking][OTP] 72348-Configure networkDiagnostics for both network-check-source and network-check-target [Serial]", func() {
		var (
			diagNamespace = "openshift-network-diagnostics"
			restoreCmd    = `[{"op":"replace","path":"/spec/networkDiagnostics","value":{"mode":"","sourcePlacement":{},"targetPlacement":{}}}]`
		)

		workers, err := otputils.GetSchedulableLinuxWorkerNodes(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workers) < 2 {
			g.Skip("No enough workers, skip the tests")
		}

		g.By("Get default networkDiagnostics pods.")
		networkdDiagPods, err := otputils.GetAllPods(oc, diagNamespace)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Add a label to one worker node.")
		defer otputils.DeleteLabelFromNode(oc, workers[0], "net-diag-test-source")
		otputils.AddLabelToNode(oc, workers[0], "net-diag-test-source", "ocp72348")

		g.By("Configure networkDiagnostics to match the label")
		defer func() {
			err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("Network.config.openshift.io/cluster", "--type=json", "-p", restoreCmd).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			err := otputils.CheckNetworkOperatorStatus(oc)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Eventually(func() bool {
				recNetworkdDiagPods, err := otputils.GetAllPods(oc, diagNamespace)
				o.Expect(err).NotTo(o.HaveOccurred())
				return len(recNetworkdDiagPods) == len(networkdDiagPods)
			}, "300s", "10s").Should(o.BeTrue(), "networkDiagnostics pods are not recovered as default.")
		}()

		patchCmd := `{ "spec":{
			"networkDiagnostics": {
			  "mode": "All",
			  "sourcePlacement": {
				"nodeSelector": {
				  "kubernetes.io/os": "linux",
				  "net-diag-test-source": "ocp72348"
				}
			  },
			  "targetPlacement": {
				"nodeSelector": {
				  "kubernetes.io/os": "linux"
				},
				"tolerations": [
				  {
					"operator": "Exists"
				  }
				]
			  }
			}
		  }
		}
		`
		otputils.PatchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchCmd)

		g.By("Verify network-check-source pod deployed to the labeled node.")
		o.Eventually(func() bool {
			var nodeName string
			networkCheckSourcePod, err := otputils.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-source")
			o.Expect(err).NotTo(o.HaveOccurred())
			if len(networkCheckSourcePod) == 0 {
				nodeName = ""
			} else {
				nodeName, _ = otputils.GetPodNodeName(oc, diagNamespace, networkCheckSourcePod[0])
			}
			e2e.Logf("Currently the network-check-source pod's node is %s, expected node is %s", nodeName, workers[0])
			return nodeName == workers[0]
		}, "300s", "10s").Should(o.BeTrue(), "network-check-source pod was not deployed to labeled node.")

		g.By("Verify network-check-target pod deployed to all linux nodes.")
		o.Eventually(func() bool {
			networkCheckTargetPods, err := otputils.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-target")
			o.Expect(err).NotTo(o.HaveOccurred())
			allWorkers, err := otputils.GetAllNodesbyOSType(oc, "linux")
			o.Expect(err).NotTo(o.HaveOccurred())
			return len(networkCheckTargetPods) == len(allWorkers)
		}, "300s", "10s").Should(o.BeTrue(), "network-check-target pods were not deployed to all linux nodes..")

		g.By("Add a label to second worker node")
		defer otputils.DeleteLabelFromNode(oc, workers[1], "net-diag-test-target")
		otputils.AddLabelToNode(oc, workers[1], "net-diag-test-target", "ocp72348")

		g.By("Configure networkDiagnostics to match the label")
		patchCmd = `{ "spec":{
			"networkDiagnostics": {
			  "mode": "All",
			  "sourcePlacement": {
				"nodeSelector": {
				  "kubernetes.io/os": "linux",
				  "net-diag-test-source": "ocp72348"
				}
			  },
			  "targetPlacement": {
				"nodeSelector": {
				  "kubernetes.io/os": "linux",
				  "net-diag-test-target": "ocp72348"
				},
				"tolerations": [
				  {
					"operator": "Exists"
				  }
				]
			  }
			}
		  }
		}
		`
		otputils.PatchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchCmd)

		g.By("Verify only one network-check-target pod is deployed to the labeled node.")
		o.Eventually(func() bool {
			networkCheckTargetPods, err := otputils.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-target")
			o.Expect(err).NotTo(o.HaveOccurred())
			var nodeName string
			if len(networkCheckTargetPods) == 0 {
				nodeName = ""
			} else {
				nodeName, _ = otputils.GetPodNodeName(oc, diagNamespace, networkCheckTargetPods[0])
			}
			e2e.Logf("Currently the network-check-target pod's node is %s, expected node is %s", nodeName, workers[1])
			return len(networkCheckTargetPods) == 1 && nodeName == workers[1]
		}, "300s", "10s").Should(o.BeTrue(), "network-check-target pod was not deployed to the node with correct label.")

		g.By("Verify PodNetworkConnectivityCheck has only one network-check-source-to-network-check-target")
		o.Eventually(func() bool {
			podNetworkConnectivityCheck, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("PodNetworkConnectivityCheck", "-n", diagNamespace).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("%s", podNetworkConnectivityCheck)
			regexStr := "network-check-source.*network-check-target.*"
			r := regexp.MustCompile(regexStr)
			matches := r.FindAllString(podNetworkConnectivityCheck, -1)
			return len(matches) == 1
		}, "300s", "10s").Should(o.BeTrue(), "The number of network-check-source.*network-check-target.* was not 1.")
	})

	g.It("[JIRA:Networking][OTP] 68156-ovnkube-node should be modifying annotations on its own node and pods only [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			caseID              = "68156"
			kubeconfigFilePath  = "/tmp/kubeconfig-" + caseID
			userContext         = "default-context"
		)

		g.By("Get list of nodes")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		workerNodeCount := len(nodeList.Items)
		o.Expect(workerNodeCount == 0).ShouldNot(o.BeTrue())

		g.By("Get namespace")
		ns := oc.Namespace()

		g.By(fmt.Sprintf("Get ovnkube-node pod name for a node %s", nodeList.Items[0].Name))
		ovnKubeNodePodName := otputils.OvnkubeNodePod(oc, nodeList.Items[0].Name)

		defer func() {
			err := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("node", nodeList.Items[0].Name, "k8s.ovn.org/node-mgmt-port-").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			_, cmdErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePodName, "ovnkube-controller", "rm -f /tmp/*.yaml")
			o.Expect(cmdErr).NotTo(o.HaveOccurred())
			_, cmdErr = otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePodName, "ovnkube-controller", fmt.Sprintf("rm -f %s", kubeconfigFilePath))
			o.Expect(cmdErr).NotTo(o.HaveOccurred())
		}()

		g.By(fmt.Sprintf("Create a kubeconfig file on the node %s", nodeList.Items[0].Name))
		o.Expect(otputils.GenerateKubeConfigFileForContext(oc, nodeList.Items[0].Name, ovnKubeNodePodName, kubeconfigFilePath, userContext)).To(o.BeTrue())

		g.By("Verify pod is successfully scheduled on a node")
		podns := otputils.PingPodResourceNode{
			Name:      "hello-pod",
			Namespace: ns,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		podns.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, podns.Namespace, podns.Name)

		g.By("Generate YAML for the pod and save it on node")
		_, podFileErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePodName, "ovnkube-controller", fmt.Sprintf("export KUBECONFIG=%s; oc -n %s get pod %s -o json > /tmp/%s-%s.yaml", kubeconfigFilePath, podns.Namespace, podns.Name, podns.Name, caseID))
		o.Expect(podFileErr).NotTo(o.HaveOccurred())

		for i := 0; i < 2; i++ {
			g.By(fmt.Sprintf("Generate YAML for the node %s and save it on node", nodeList.Items[i].Name))
			_, cmdErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePodName, "ovnkube-controller", fmt.Sprintf("export KUBECONFIG=%s; oc get node %s -o json > /tmp/node-%s-%d.yaml", kubeconfigFilePath, nodeList.Items[i].Name, caseID, i))
			o.Expect(cmdErr).NotTo(o.HaveOccurred())
			if workerNodeCount == 1 {
				break
			}
		}

		g.By("Verify the annotation can be added to the node where ovnkube-node is impersonated")
		patchNodePayload := `[{"op": "add", "path": "/metadata/annotations/k8s.ovn.org~1node-mgmt-port", "value":"{\"PfId\":1, \"FuncId\":1}"}]`
		patchNodeCmd := fmt.Sprintf("export KUBECONFIG=%s; kubectl patch -f /tmp/node-%s-0.yaml --type='json' --subresource=status -p='%s'", kubeconfigFilePath, caseID, patchNodePayload)
		cmdOutput, cmdErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePodName, "ovnkube-controller", fmt.Sprintf("export KUBECONFIG=%s;  %s", kubeconfigFilePath, patchNodeCmd))
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		e2e.Logf("%s", cmdOutput)

		if workerNodeCount > 1 {
			g.By("Verify the annotation cannot be added to the node where ovnkube-node is not impersonated")
			patchNodeCmd = fmt.Sprintf("export KUBECONFIG=%s; kubectl patch -f /tmp/node-%s-1.yaml --type='json' --subresource=status -p='%s'", kubeconfigFilePath, caseID, patchNodePayload)
			_, cmdErr = otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePodName, "ovnkube-controller", fmt.Sprintf("export KUBECONFIG=%s;  %s", kubeconfigFilePath, patchNodeCmd))
			o.Expect(cmdErr).To(o.HaveOccurred())
		}

		g.By("Verify ovnkube-node is not allowed to add the annotation to pod")
		patchPodDisallowedPayload := `[{"op": "add", "path": "/metadata/annotations/description", "value":"{\"hello-pod\"}"}]`
		patchPodCmd := fmt.Sprintf("export KUBECONFIG=%s; kubectl -n %s patch -f /tmp/%s-%s.yaml --type='json' --subresource=status -p='%s'", kubeconfigFilePath, podns.Namespace, podns.Name, caseID, patchPodDisallowedPayload)
		_, cmdErr = otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePodName, "ovnkube-controller", fmt.Sprintf("export KUBECONFIG=%s;  %s", kubeconfigFilePath, patchPodCmd))
		o.Expect(cmdErr).To(o.HaveOccurred())
	})

	g.It("[JIRA:Networking][OTP] 68690-When adding nodes, the overlapped node-subnet should not be allocated [Serial]", func() {
		g.By("1. Create a new machineset, get the new node created")
		otputils.SkipIfMachineAPIUnavailable(oc)
		infrastructureName := otputils.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-68690"

		defer otputils.WaitForMachineSetDeleted(oc, machinesetName)
		defer otputils.DeleteMachineSet(oc, machinesetName)
		otputils.CreateMachineSetFromExisting(oc, machinesetName, 2)

		machineName := otputils.GetMachineNamesFromMachineSet(oc, machinesetName)
		o.Expect(len(machineName)).ShouldNot(o.Equal(0))
		for i := 0; i < 2; i++ {
			nodeName := otputils.GetNodeNameFromMachine(oc, machineName[i])
			e2e.Logf("Node with name %v added to cluster", nodeName)
		}

		g.By("2. Check host subnet is not over lapping for the nodes")
		nodeList, err := otputils.GetClusterNodesBy(oc, "worker")
		o.Expect(err).NotTo(o.HaveOccurred())
		similarSubnetNodesFound, _ := otputils.FindNodesWithSameSubnet(oc, nodeList)
		o.Expect(similarSubnetNodesFound).To(o.BeFalse())
	})
})
