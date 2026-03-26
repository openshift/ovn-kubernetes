package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"path/filepath"
	"strconv"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN sriov-legacy", func() {
	defer g.GinkgoRecover()
	var (
		oc                  = exutil.NewCLI("sriov-" + getRandomString())
		buildPruningBaseDir = testdata.FixturePath("networking/sriov")
		sriovNeworkTemplate = filepath.Join(buildPruningBaseDir, "sriovnetwork-whereabouts-template.yaml")
		sriovOpNs           = "openshift-sriov-network-operator"
		vfNum               = 2
	)
	testData := []struct {
		Name          string
		DeviceID      string
		Vendor        string
		InterfaceName string
	}{
		{"e810xxv", "159b", "8086", "ens2f0"},
		{"e810c", "1593", "8086", "ens2f2"},
		{"x710", "1572", "8086", "ens5f0"}, //NO-CARRIER
		{"bcm57414", "16d7", "14e4", "ens4f1np1"},
		{"bcm57508", "1750", "14e4", "ens3f0np0"}, //NO-CARRIER
		{"e810back", "1591", "8086", "ens4f2"},
	}
	g.BeforeEach(func() {
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || !(strings.Contains(msg, "sriov.openshift-qe.sdn.com") || strings.Contains(msg, "offload.openshift-qe.sdn.com")) {
			g.Skip("This case will only run on rdu1/rdu2 cluster. , skip for other envrionment!!!")
		}
		compat_otp.By("check the sriov operator is running")
		chkSriovOperatorStatus(oc, sriovOpNs)
	})
	g.AfterEach(func() {
		//after each case finished testing.  remove sriovnodenetworkpolicy CR
		var policys []string
		for _, items := range testData {
			policys = append(policys, items.Name)

		}
		_, err := oc.AsAdmin().WithoutNamespace().Run("delete").Args(append([]string{"SriovNetworkNodePolicy", "-n", sriovOpNs, "--ignore-not-found"}, policys...)...).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("remove sriovnetworknodepolicy %s", strings.Join(policys, " "))
		waitForSriovPolicyReady(oc, sriovOpNs)

	})

	g.It("Author:zzhao-Medium-NonPreRelease-Longduration-25959-Test container with spoofchk is on [Disruptive]", func() {
		var caseID = "25959-"

		for _, data := range testData {
			data := data
			// Create VF on with given device
			result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
			// if the deviceid is not exist on the worker, skip this
			if !result {
				continue
			}
			func() {
				ns1 := "e2e-" + caseID + data.Name
				err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
				compat_otp.SetNamespacePrivileged(oc, ns1)

				compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
				e2e.Logf("device ID is %v", data.DeviceID)
				e2e.Logf("device Name is %v", data.Name)
				sriovnetwork := sriovNetwork{
					name:             data.Name,
					resourceName:     data.Name,
					networkNamespace: ns1,
					template:         sriovNeworkTemplate,
					namespace:        sriovOpNs,
					spoolchk:         "on",
					trust:            "off",
				}
				//defer
				defer func() {
					rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
				}()
				sriovnetwork.createSriovNetwork(oc)

				chkVFStatusWithPassTraffic(oc, sriovnetwork.name, data.InterfaceName, ns1, "spoof checking on")

			}()
		}
	})

	g.It("Author:zzhao-Medium-NonPreRelease-Longduration-70820-Test container with spoofchk is off [Disruptive]", func() {
		var caseID = "70820-"

		for _, data := range testData {
			data := data
			// Create VF on with given device
			result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
			// if the deviceid is not exist on the worker, skip this
			if !result {
				continue
			}
			func() {
				ns1 := "e2e-" + caseID + data.Name
				err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
				compat_otp.SetNamespacePrivileged(oc, ns1)

				compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
				e2e.Logf("device ID is %v", data.DeviceID)
				e2e.Logf("device Name is %v", data.Name)
				sriovnetwork := sriovNetwork{
					name:             data.Name,
					resourceName:     data.Name,
					networkNamespace: ns1,
					template:         sriovNeworkTemplate,
					namespace:        sriovOpNs,
					spoolchk:         "off",
					trust:            "on",
				}
				//defer
				defer func() {
					rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
				}()
				sriovnetwork.createSriovNetwork(oc)

				chkVFStatusWithPassTraffic(oc, sriovnetwork.name, data.InterfaceName, ns1, "spoof checking off")
			}()
		}
	})
	g.It("Author:zzhao-Medium-NonPreRelease-Longduration-25960-Test container with trust is off [Disruptive]", func() {
		var caseID = "25960-"

		for _, data := range testData {
			data := data
			// Create VF on with given device
			result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
			// if the deviceid is not exist on the worker, skip this
			if !result {
				continue
			}
			func() {
				ns1 := "e2e-" + caseID + data.Name
				err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
				compat_otp.SetNamespacePrivileged(oc, ns1)

				compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
				e2e.Logf("device ID is %v", data.DeviceID)
				e2e.Logf("device Name is %v", data.Name)
				sriovnetwork := sriovNetwork{
					name:             data.Name,
					resourceName:     data.Name,
					networkNamespace: ns1,
					template:         sriovNeworkTemplate,
					namespace:        sriovOpNs,
					spoolchk:         "off",
					trust:            "off",
				}
				//defer
				defer func() {
					rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
				}()
				sriovnetwork.createSriovNetwork(oc)

				chkVFStatusWithPassTraffic(oc, sriovnetwork.name, data.InterfaceName, ns1, "trust off")

			}()
		}
	})
	g.It("Author:zzhao-Medium-NonPreRelease-Longduration-70821-Test container with trust is on [Disruptive]", func() {
		var caseID = "70821-"

		for _, data := range testData {
			data := data
			// Create VF on with given device
			result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
			// if the deviceid is not exist on the worker, skip this
			if !result {
				continue
			}
			func() {
				ns1 := "e2e-" + caseID + data.Name
				err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
				compat_otp.SetNamespacePrivileged(oc, ns1)

				compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
				e2e.Logf("device ID is %v", data.DeviceID)
				e2e.Logf("device Name is %v", data.Name)
				sriovnetwork := sriovNetwork{
					name:             data.Name,
					resourceName:     data.Name,
					networkNamespace: ns1,
					template:         sriovNeworkTemplate,
					namespace:        sriovOpNs,
					spoolchk:         "on",
					trust:            "on",
				}
				//defer
				defer func() {
					rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
				}()
				sriovnetwork.createSriovNetwork(oc)

				chkVFStatusWithPassTraffic(oc, sriovnetwork.name, data.InterfaceName, ns1, "trust on")

			}()
		}
	})

	g.It("Author:zzhao-Medium-NonPreRelease-Longduration-25963-Test container with VF and set vlan minTxRate maxTxRate [Disruptive]", func() {
		var caseID = "25963-"

		for _, data := range testData {
			data := data

			//x710 do not support minTxRate for now
			if data.Name == "x710" || data.Name == "bcm57414" || data.Name == "bcm57508" {
				continue
			}
			// Create VF on with given device
			result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
			// if the deviceid is not exist on the worker, skip this
			if !result {
				continue
			}
			func() {
				ns1 := "e2e-" + caseID + data.Name
				err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
				compat_otp.SetNamespacePrivileged(oc, ns1)

				compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
				e2e.Logf("device ID is %v", data.DeviceID)
				e2e.Logf("device Name is %v", data.Name)
				sriovnetwork := sriovNetwork{
					name:             data.Name,
					resourceName:     data.Name,
					networkNamespace: ns1,
					template:         sriovNeworkTemplate,
					namespace:        sriovOpNs,
					vlanId:           100,
					vlanQoS:          2,
					minTxRate:        40,
					maxTxRate:        100,
				}
				//defer
				defer func() {
					rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
				}()
				sriovnetwork.createSriovNetwork(oc)

				chkVFStatusWithPassTraffic(oc, sriovnetwork.name, data.InterfaceName, ns1, "vlan 100, qos 2, tx rate 100 (Mbps), max_tx_rate 100Mbps, min_tx_rate 40Mbps")

			}()
		}
	})

	g.It("Author:zzhao-Medium-NonPreRelease-Longduration-25961-Test container with VF and set linkState is auto [Disruptive]", func() {
		var caseID = "25961-"

		for _, data := range testData {
			data := data
			// Create VF on with given device
			result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
			// if the deviceid is not exist on the worker, skip this
			if !result {
				continue
			}
			func() {
				ns1 := "e2e-" + caseID + data.Name
				err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
				compat_otp.SetNamespacePrivileged(oc, ns1)

				compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
				e2e.Logf("device ID is %v", data.DeviceID)
				e2e.Logf("device Name is %v", data.Name)
				sriovnetwork := sriovNetwork{
					name:             data.Name,
					resourceName:     data.Name,
					networkNamespace: ns1,
					template:         sriovNeworkTemplate,
					namespace:        sriovOpNs,
					linkState:        "auto",
				}
				//defer
				defer func() {
					rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
				}()
				sriovnetwork.createSriovNetwork(oc)

				chkVFStatusWithPassTraffic(oc, sriovnetwork.name, data.InterfaceName, ns1, "link-state auto")

			}()
		}
	})
	g.It("Author:zzhao-Medium-NonPreRelease-Longduration-71006-Test container with VF and set linkState is enable [Disruptive]", func() {
		var caseID = "71006-"

		for _, data := range testData {
			data := data
			// Create VF on with given device
			result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
			// if the deviceid is not exist on the worker, skip this
			if !result {
				continue
			}
			func() {
				ns1 := "e2e-" + caseID + data.Name
				err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
				compat_otp.SetNamespacePrivileged(oc, ns1)

				compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
				e2e.Logf("device ID is %v", data.DeviceID)
				e2e.Logf("device Name is %v", data.Name)
				sriovnetwork := sriovNetwork{
					name:             data.Name,
					resourceName:     data.Name,
					networkNamespace: ns1,
					template:         sriovNeworkTemplate,
					namespace:        sriovOpNs,
					linkState:        "enable",
				}
				//defer
				defer func() {
					rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
				}()
				sriovnetwork.createSriovNetwork(oc)

				chkVFStatusWithPassTraffic(oc, sriovnetwork.name, data.InterfaceName, ns1, "link-state enable")

			}()
		}

	})

	g.It("Author:yingwang-Medium-NonPreRelease-Longduration-69646-mtu testing for sriov policy [Disruptive]", func() {
		var caseID = "69646-"

		for _, data := range testData {
			data := data
			// Create VF on with given device
			result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
			// if the deviceid is not exist on the worker, skip this
			if !result {
				continue
			}
			//configure mtu in sriovnetworknodepolicy
			mtuValue := 1800
			patchYamlToRestore := `[{"op":"add","path":"/spec/mtu","value":1800}]`
			output, err1 := oc.AsAdmin().WithoutNamespace().Run("patch").Args("sriovnetworknodepolicies.sriovnetwork.openshift.io", data.Name, "-n", sriovOpNs,
				"--type=json", "-p", patchYamlToRestore).Output()
			e2e.Logf("patch result is %v", output)

			o.Expect(err1).NotTo(o.HaveOccurred())
			matchStr := data.Name + " patched"
			o.Expect(output).Should(o.ContainSubstring(matchStr))
			waitForSriovPolicyReady(oc, sriovOpNs)

			func() {
				ns1 := "e2e-" + caseID + data.Name
				err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
				compat_otp.SetNamespacePrivileged(oc, ns1)

				compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
				e2e.Logf("device ID is %v", data.DeviceID)
				e2e.Logf("device Name is %v", data.Name)
				sriovnetwork := sriovNetwork{
					name:             data.Name,
					resourceName:     data.Name,
					networkNamespace: ns1,
					template:         sriovNeworkTemplate,
					namespace:        sriovOpNs,
					spoolchk:         "on",
					trust:            "on",
				}
				//defer
				defer func() {
					rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
				}()
				sriovnetwork.createSriovNetwork(oc)

				chkVFStatusWithPassTraffic(oc, sriovnetwork.name, data.InterfaceName, ns1, "mtu "+strconv.Itoa(mtuValue))

			}()
		}
	})

	g.It("Author:yingwang-Medium-NonPreRelease-Longduration-69582-dpdk for sriov vf can be worked well [Disruptive]", func() {
		var caseID = "69582-"

		for _, data := range testData {
			data := data
			// skip bcm nics: OCPBUGS-30909
			if strings.Contains(data.Name, "bcm") {
				continue
			}
			// Create VF on with given device
			policyName := data.Name
			networkName := data.Name + "dpdk" + "net"
			result := initDpdkVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
			// if the deviceid is not exist on the worker, skip this
			if !result {
				continue
			}
			func() {
				ns1 := "e2e-" + caseID + data.Name
				err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
				compat_otp.SetNamespacePrivileged(oc, ns1)

				compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
				e2e.Logf("device ID is %v", data.DeviceID)
				e2e.Logf("device Name is %v", data.Name)
				sriovNeworkTemplate = filepath.Join(buildPruningBaseDir, "sriovnetwork-template.yaml")
				sriovnetwork := sriovNetwork{
					name:             networkName,
					resourceName:     policyName,
					networkNamespace: ns1,
					template:         sriovNeworkTemplate,
					namespace:        sriovOpNs,
				}

				//defer
				defer func() {
					rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
				}()
				sriovnetwork.createSriovNetwork(oc)
				//create pods
				sriovTestPodDpdkTemplate := filepath.Join(buildPruningBaseDir, "sriov-dpdk-template.yaml")
				sriovTestPod := sriovTestPod{
					name:        "sriovdpdk",
					namespace:   ns1,
					networkName: sriovnetwork.name,
					template:    sriovTestPodDpdkTemplate,
				}
				sriovTestPod.createSriovTestPod(oc)
				err1 := waitForPodWithLabelReady(oc, ns1, "name=sriov-dpdk")
				compat_otp.AssertWaitPollNoErr(err1, "this pod with label name=sriov-dpdk not ready")

				g.By("Check testpmd running well")
				pciAddress := getPciAddress(sriovTestPod.namespace, sriovTestPod.name, policyName)
				command := "testpmd -l 2-3 --in-memory -w " + pciAddress + " --socket-mem 1024 -n 4 --proc-type auto --file-prefix pg -- --disable-rss --nb-cores=1 --rxq=1 --txq=1 --auto-start --forward-mode=mac"
				testpmdOutput, err := e2eoutput.RunHostCmd(sriovTestPod.namespace, sriovTestPod.name, command)
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(testpmdOutput).Should(o.MatchRegexp("forwards packets on 1 streams"))

				sriovTestPod.deleteSriovTestPod(oc)

			}()
		}
	})

})
