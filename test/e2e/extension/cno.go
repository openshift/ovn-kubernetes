package networking

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

var _ = g.Describe("[OTP][sig-networking] SDN CNO", func() {
	defer g.GinkgoRecover()

	var (
		oc            = compat_otp.NewCLI("networking-cno", compat_otp.KubeConfigPath())
		diagNamespace = "openshift-network-diagnostics"
		restoreCmd    = `[{"op":"replace","path":"/spec/networkDiagnostics","value":{"mode":"","sourcePlacement":{},"targetPlacement":{}}}]`
	)

	g.BeforeEach(func() {
		err := compat_otp.CheckNetworkOperatorStatus(oc)
		if err != nil {
			g.Skip("The Cluster Network Operator is already not in normal status, skip networkDiagnostics test cases!!!")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-Critical-72348-Configure networkDiagnostics for both network-check-source and network-check-target. [Disruptive]", func() {
		workers, err := compat_otp.GetSchedulableLinuxWorkerNodes(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workers) < 2 {
			g.Skip("No enough workers, skip the tests")
		}

		compat_otp.By("Get default networkDiagnostics pods.  ")
		networkdDiagPods, err := compat_otp.GetAllPods(oc, diagNamespace)
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("Add a label to one worker node.")
		defer compat_otp.DeleteLabelFromNode(oc, workers[0].Name, "net-diag-test-source")
		compat_otp.AddLabelToNode(oc, workers[0].Name, "net-diag-test-source", "ocp72348")

		compat_otp.By("Configure networkDiagnostics to match the label")
		defer func() {
			err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("Network.config.openshift.io/cluster", "--type=json", "-p", restoreCmd).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			err := compat_otp.CheckNetworkOperatorStatus(oc)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Eventually(func() bool {
				recNetworkdDiagPods, err := compat_otp.GetAllPods(oc, diagNamespace)
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
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchCmd)

		compat_otp.By("Verify network-check-source pod deployed to the labeled node.")
		o.Eventually(func() bool {
			var nodeName string
			networkCheckSourcePod, err := compat_otp.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-source")
			o.Expect(err).NotTo(o.HaveOccurred())
			if len(networkCheckSourcePod) == 0 {
				// In case when the pod started, it might have a time just pod got terminiated but not started yet.
				nodeName = ""
			} else {
				nodeName, _ = compat_otp.GetPodNodeName(oc, diagNamespace, networkCheckSourcePod[0])

			}
			e2e.Logf("Currently the network-check-source pod's node is %s,expected node is %s", nodeName, workers[0].Name)
			return nodeName == workers[0].Name
		}, "300s", "10s").Should(o.BeTrue(), "network-check-source pod was not deployed to labeled node.")

		compat_otp.By("Verify network-check-target pod deployed to all linux nodes.")
		o.Eventually(func() bool {
			networkCheckTargetPods, err := compat_otp.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-target")
			o.Expect(err).NotTo(o.HaveOccurred())
			workers, err := compat_otp.GetAllNodesbyOSType(oc, "linux")
			o.Expect(err).NotTo(o.HaveOccurred())
			return len(networkCheckTargetPods) == len(workers)
		}, "300s", "10s").Should(o.BeTrue(), "network-check-target pods were not deployed to all linux nodes..")

		compat_otp.By("Add a label to second worker node ")
		defer compat_otp.DeleteLabelFromNode(oc, workers[1].Name, "net-diag-test-target")
		compat_otp.AddLabelToNode(oc, workers[1].Name, "net-diag-test-target", "ocp72348")

		compat_otp.By("Configure networkDiagnostics to match the label")
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
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchCmd)

		compat_otp.By("Verify only one network-check-target pod is deployed to the labeled node.")
		o.Eventually(func() bool {
			networkCheckTargetPods, err := compat_otp.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-target")
			o.Expect(err).NotTo(o.HaveOccurred())
			var nodeName string
			if len(networkCheckTargetPods) == 0 {
				nodeName = ""
			} else {
				nodeName, _ = compat_otp.GetPodNodeName(oc, diagNamespace, networkCheckTargetPods[0])
			}
			e2e.Logf("Currently the network-check-target pod's node is %s,expected node is %s", nodeName, workers[0].Name)
			return len(networkCheckTargetPods) == 1 && nodeName == workers[1].Name
		}, "300s", "10s").Should(o.BeTrue(), "network-check-target pod was not deployed to the node with correct label.")

		compat_otp.By("Verify PodNetworkConnectivityCheck has only one network-check-source-to-network-check-target")
		o.Eventually(func() bool {
			podNetworkConnectivityCheck, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("PodNetworkConnectivityCheck", "-n", diagNamespace).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf(podNetworkConnectivityCheck)
			regexStr := "network-check-source.*network-check-target.*"
			r := regexp.MustCompile(regexStr)
			matches := r.FindAllString(podNetworkConnectivityCheck, -1)
			return len(matches) == 1
		}, "300s", "10s").Should(o.BeTrue(), "The number of network-check-source.*network-check-target.* was not 1.")

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-Medium-72349-No matching node for sourcePlacement or targePlacement. [Disruptive]", func() {
		compat_otp.By("Get default networkDiagnostics pods.  ")
		networkdDiagPods, err := compat_otp.GetAllPods(oc, diagNamespace)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Configure networkDiagnostics sourcePlacement  with label that no node has")
		defer func() {
			err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("Network.config.openshift.io/cluster", "--type=json", "-p", restoreCmd).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			err := compat_otp.CheckNetworkOperatorStatus(oc)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Eventually(func() bool {
				recNetworkdDiagPods, err := compat_otp.GetAllPods(oc, diagNamespace)
				o.Expect(err).NotTo(o.HaveOccurred())
				return len(recNetworkdDiagPods) == len(networkdDiagPods)
			}, "300s", "10s").Should(o.BeTrue(), "networkDiagnostics pods are not recovered as default.")
		}()
		patchCmd := `{ "spec":{
			"networkDiagnostics": {
			  "mode": "All",
			  "sourcePlacement": {
				"nodeSelector": {
				  "net-diag-node-placement-72349": ""
				}
			  }
			}
		  }
		}`
		e2e.Logf("networkDiagnostics config command is: %s\n", patchCmd)
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchCmd)

		compat_otp.By("Verify network-check-source pod is in pending status.")
		o.Eventually(func() bool {
			networkCheckSourcePod, err := compat_otp.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-source")
			o.Expect(err).NotTo(o.HaveOccurred())
			var status string
			if len(networkCheckSourcePod) == 0 {
				status = ""
			} else {
				status, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", diagNamespace, networkCheckSourcePod[0], "-o=jsonpath={.status.phase}").Output()

			}
			e2e.Logf("Current pod status is %s,expected status is %s", status, "Pending")
			return status == "Pending"
		}, "300s", "10s").Should(o.BeTrue(), "network-check-source pod was not in pending status.")

		compat_otp.By("Verify NetworkDiagnosticsAvailable status is false.")
		o.Eventually(func() bool {
			status := getNetworkDiagnosticsAvailable(oc)
			return status == "false"
		}, "300s", "10s").Should(o.BeTrue(), "NetworkDiagnosticsAvailable is not in false status")

		compat_otp.By("Verify CNO is not in degraded status")
		err = compat_otp.CheckNetworkOperatorStatus(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Configure networkDiagnostics targetPlacement  with label that no node has")
		patchCmd = `{ "spec":{
			"networkDiagnostics": {
			  "mode": "All",
			  "sourcePlacement": null,
			  "targetPlacement": {
				"nodeSelector": {
				  "net-diag-node-placement-72349": ""
				}
			  }
			}
		  }
		}`
		e2e.Logf("networkDiagnostics config command is: %s\n", patchCmd)
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchCmd)

		compat_otp.By("Verify all network-check-target pod gone ")
		o.Eventually(func() bool {
			networkCheckTargetPods, _ := compat_otp.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-target")
			return len(networkCheckTargetPods) == 0
		}, "300s", "10s").Should(o.BeTrue(), "network-check-target pods are not terminated.")

		compat_otp.By("Verify NetworkDiagnosticsAvailable status is true.")
		o.Eventually(func() bool {
			status := getNetworkDiagnosticsAvailable(oc)
			return status == "true"
		}, "300s", "10s").Should(o.BeTrue(), "NetworkDiagnosticsAvailable is not in true status")

		compat_otp.By("Verify CNO is not in degraded status")
		err = compat_otp.CheckNetworkOperatorStatus(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-Medium-72351-Low-73365-mode of networkDiagnostics is Disabled,invalid mode will not be accepted. [Disruptive]", func() {
		compat_otp.By("Get default networkDiagnostics pods.  ")
		networkdDiagPods, err := compat_otp.GetAllPods(oc, diagNamespace)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Configure networkDiagnostics sourcePlacement  with label that no node has")
		defer func() {
			err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("Network.config.openshift.io/cluster", "--type=json", "-p", restoreCmd).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			err := compat_otp.CheckNetworkOperatorStatus(oc)
			o.Expect(err).NotTo(o.HaveOccurred())
			var recNetworkdDiagPods []string
			o.Eventually(func() bool {
				recNetworkdDiagPods, err := compat_otp.GetAllPods(oc, diagNamespace)
				o.Expect(err).NotTo(o.HaveOccurred())
				return len(recNetworkdDiagPods) == len(networkdDiagPods)
			}, "300s", "10s").Should(o.BeTrue(), fmt.Sprintf("Original networkDiagnostics pods number is %v, current number is %v,", len(networkdDiagPods), len(recNetworkdDiagPods)))
		}()
		patchCmd := `{ "spec":{
			"networkDiagnostics": {
			  "mode": "Disabled",
			  "sourcePlacement": null,
			  "targetPlacement": null
			}
		  }
		}`
		e2e.Logf("networkDiagnostics config command is: %s\n", patchCmd)
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchCmd)

		compat_otp.By("Verify that neither the network-check-source pod nor the network-check-target pod is placed. ")
		o.Eventually(func() bool {
			networkCheckSourcePod, _ := compat_otp.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-source")
			networkCheckTargetPods, _ := compat_otp.GetAllPodsWithLabel(oc, diagNamespace, "app=network-check-target")
			return len(networkCheckTargetPods) == 0 && len(networkCheckSourcePod) == 0
		}, "300s", "10s").Should(o.BeTrue(), "There is still network-check-source or network-check-target pod placed")

		compat_otp.By("Verify NetworkDiagnosticsAvailable status is false.")
		o.Eventually(func() bool {
			status := getNetworkDiagnosticsAvailable(oc)
			return status == "false"
		}, "300s", "10s").Should(o.BeTrue(), "NetworkDiagnosticsAvailable is not in false status")

		compat_otp.By("Verify CNO is not in degraded status")
		err = compat_otp.CheckNetworkOperatorStatus(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify no PodNetworkConnectivityCheck created ")
		o.Eventually(func() bool {
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("PodNetworkConnectivityCheck", "-n", diagNamespace).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf(output)
			return strings.Contains(output, "No resources found")
		}, "300s", "10s").Should(o.BeTrue(), "PodNetworkConnectivityCheck is still there.")

		compat_otp.By("Verify invalid mode is not accepted")
		patchCmd = `{ "spec":{
			"networkDiagnostics": {
			  "mode": "test-invalid"
			}
		  }
		}`

		output, err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("Network.config.openshift.io/cluster", "-p", patchCmd, "--type=merge").Output()
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(strings.Contains(output, "Unsupported value: \"test-invalid\"")).To(o.BeTrue())
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-Medium-73367-Configure disableNetworkDiagnostics and networkDiagnostics. [Disruptive]", func() {
		compat_otp.By("Get default networkDiagnostics pods.  ")
		networkdDiagPods, err := compat_otp.GetAllPods(oc, diagNamespace)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Configure spec.disableNetworkDiagnostics=true in network.operator")
		defer func() {
			patchResourceAsAdmin(oc, "network.operator/cluster", "{\"spec\":{\"disableNetworkDiagnostics\": false}}")
			err := compat_otp.CheckNetworkOperatorStatus(oc)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Eventually(func() bool {
				recNetworkdDiagPods, err := compat_otp.GetAllPods(oc, diagNamespace)
				o.Expect(err).NotTo(o.HaveOccurred())
				return len(recNetworkdDiagPods) == len(networkdDiagPods)
			}, "300s", "10s").Should(o.BeTrue(), "networkDiagnostics pods are not recovered as default.")
		}()
		patchResourceAsAdmin(oc, "network.operator/cluster", "{\"spec\":{\"disableNetworkDiagnostics\": true}}")

		compat_otp.By("Verify CNO is not in degraded status")
		err = compat_otp.CheckNetworkOperatorStatus(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify NetworkDiagnosticsAvailable status is false.")
		o.Eventually(func() bool {
			status := getNetworkDiagnosticsAvailable(oc)
			return status == "false"
		}, "300s", "10s").Should(o.BeTrue(), "NetworkDiagnosticsAvailable is not in false status")

		compat_otp.By("Configure networkDiagnostics")
		defer func() {
			err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("Network.config.openshift.io/cluster", "--type=json", "-p", restoreCmd).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}()
		patchCmd := `{ "spec":{
			"networkDiagnostics": {
			  "mode": "All",
			  "sourcePlacement": null,
			  "targetPlacement": null
			}
		  }
		}`
		e2e.Logf("networkDiagnostics config command is: %s\n", patchCmd)
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchCmd)

		compat_otp.By("Verify CNO is not in degraded status")
		err = compat_otp.CheckNetworkOperatorStatus(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify NetworkDiagnosticsAvailable status is true.")
		o.Eventually(func() bool {
			status := getNetworkDiagnosticsAvailable(oc)
			return status == "true"
		}, "300s", "10s").Should(o.BeTrue(), "NetworkDiagnosticsAvailable is not in true status")
	})

	// author: meinli@redhat.com
	g.It("Author:meinli-NonPreRelease-Medium-51727-ovsdb-server and northd should not core dump on node restart [Disruptive]", func() {
		// https://bugzilla.redhat.com/show_bug.cgi?id=1944264

		compat_otp.By("1. Get one node to reboot")
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 1 {
			g.Skip("This case requires 1 nodes, but the cluster has none. Skip it!!!")
		}
		worker := workerList.Items[0].Name
		defer checkNodeStatus(oc, worker, "Ready")
		rebootNode(oc, worker)
		checkNodeStatus(oc, worker, "NotReady")
		checkNodeStatus(oc, worker, "Ready")

		compat_otp.By("2. Check the node core dump output")
		mustgatherDir := "/tmp/must-gather-51727"
		defer os.RemoveAll(mustgatherDir)
		_, err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("must-gather", "--dest-dir="+mustgatherDir, "--", "/usr/bin/gather_core_dumps").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		match, err := filepath.Glob(filepath.Join(mustgatherDir, "*", "/node_core_dumps"))
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(match)).Should(o.Equal(1))
		files, err := os.ReadDir(match[0])
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(files).Should(o.BeEmpty())
	})
})
