package e2e

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/util/retry"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"

	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	logSeverityNamespaceAnnotation = "k8s.ovn.org/acl-logging"
	maxPokeRetries                 = 15
	ovnControllerLogPath           = "/var/log/openvswitch/ovn-controller.log"
	pokeInterval                   = 1 * time.Second
)

var _ = Describe("ACL Logging for NetworkPolicy", func() {
	const (
		denyAllPolicyName       = "default-deny-all"
		initialDenyACLSeverity  = "alert"
		initialAllowACLSeverity = "notice"
		denyACLVerdict          = "drop"
		namespacePrefix         = "acl-logging-netpol"
		pokerPodIndex           = 0
		pokedPodIndex           = 1
		egressDefaultDenySuffix = "Egress"
	)

	fr := wrappedTestFramework(namespacePrefix)

	var (
		nsName string
		pods   []v1.Pod
	)

	BeforeEach(func() {
		By("configuring the ACL logging level within the namespace")
		nsName = fr.Namespace.Name
		Expect(setNamespaceACLLogSeverity(fr, nsName, initialDenyACLSeverity, initialAllowACLSeverity, aclRemoveOptionDelete)).To(Succeed())

		By("creating a \"default deny\" network policy")
		_, err := makeDenyAllPolicy(fr, nsName, denyAllPolicyName)
		Expect(err).NotTo(HaveOccurred())

		By("creating pods")
		cmd := []string{"/bin/bash", "-c", "/agnhost netexec --http-port 8000"}
		for i := 0; i < 2; i++ {
			pod := newAgnhostPod(nsName, fmt.Sprintf("pod%d", i+1), cmd...)
			pod = fr.PodClient().CreateSync(pod)
			Expect(waitForACLLoggingPod(fr, nsName, pod.GetName())).To(Succeed())
			pods = append(pods, *pod)
		}

		By("sending traffic between acl-logging test pods we trigger ACL logging")
		clientPod := pods[pokerPodIndex]
		pokedPod := pods[pokedPodIndex]
		framework.Logf(
			"Poke pod %s (on node %s) from pod %s (on node %s)",
			pokedPod.GetName(),
			pokedPod.Spec.NodeName,
			clientPod.GetName(),
			clientPod.Spec.NodeName)
		Expect(
			pokePod(fr, clientPod.GetName(), pokedPod.Status.PodIP)).To(HaveOccurred(),
			"traffic should be blocked since we only use a deny all traffic policy")
	})

	AfterEach(func() {
		pods = nil
	})

	It("the logs have the expected log level", func() {
		clientPodScheduledPodName := pods[pokerPodIndex].Spec.NodeName
		// Retry here in the case where OVN acls have not been programmed yet
		composedPolicyNameRegex := fmt.Sprintf("NP:%s:%s", nsName, egressDefaultDenySuffix)
		Eventually(func() (bool, error) {
			return assertACLLogs(
				clientPodScheduledPodName,
				composedPolicyNameRegex,
				denyACLVerdict,
				initialDenyACLSeverity)
		}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
	})

	When("the namespace's ACL logging annotation is updated", func() {
		const updatedAllowACLLogSeverity = "debug"

		BeforeEach(func() {
			By(fmt.Sprintf("updating the namespace's ACL logging level to %s", updatedAllowACLLogSeverity))
			Expect(setNamespaceACLLogSeverity(fr, nsName, updatedAllowACLLogSeverity, updatedAllowACLLogSeverity, aclRemoveOptionDelete)).To(Succeed())
		})

		BeforeEach(func() {
			By("poking some more...")
			clientPod := pods[pokerPodIndex]
			pokedPod := pods[pokedPodIndex]

			framework.Logf(
				"Poke pod %s (on node %s) from pod %s (on node %s)",
				pokedPod.GetName(),
				pokedPod.Spec.NodeName,
				clientPod.GetName(),
				clientPod.Spec.NodeName)
			Expect(
				pokePod(fr, clientPod.GetName(), pokedPod.Status.PodIP)).To(HaveOccurred(),
				"traffic should be blocked since we only use a deny all traffic policy")
		})

		It("the ACL logs are updated accordingly", func() {
			clientPodScheduledPodName := pods[pokerPodIndex].Spec.NodeName
			composedPolicyNameRegex := fmt.Sprintf("NP:%s:%s", nsName, egressDefaultDenySuffix)
			Eventually(func() (bool, error) {
				return assertACLLogs(
					clientPodScheduledPodName,
					composedPolicyNameRegex,
					denyACLVerdict,
					updatedAllowACLLogSeverity)
			}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
		})
	})

	When("the namespace's ACL logging annotation is removed", func() {
		BeforeEach(func() {
			By("removing the ACL logging annotation")
			Expect(setNamespaceACLLogSeverity(fr, nsName, "", "", aclRemoveOptionDelete)).To(Succeed())
		})

		It("ACL logging is disabled", func() {
			clientPod := pods[pokerPodIndex]
			pokedPod := pods[pokedPodIndex]
			composedPolicyNameRegex := fmt.Sprintf("NP:%s:%s", nsName, egressDefaultDenySuffix)
			Consistently(func() (bool, error) {
				return isCountUpdatedAfterPokePod(fr, &clientPod, &pokedPod, composedPolicyNameRegex, denyACLVerdict, "")
			}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())
		})
	})

	When("the namespace's ACL allow and deny logging annotations are set to invalid values", func() {
		BeforeEach(func() {
			By("setting invalid values for ACL logging annotation")
			Expect(setNamespaceACLLogSeverity(fr, nsName, "invalid", "invalid", aclRemoveOptionDelete)).To(Succeed())
		})

		It("ACL logging is disabled", func() {
			clientPod := pods[pokerPodIndex]
			pokedPod := pods[pokedPodIndex]
			composedPolicyNameRegex := fmt.Sprintf("NP:%s:%s", nsName, egressDefaultDenySuffix)
			Consistently(func() (bool, error) {
				return isCountUpdatedAfterPokePod(fr, &clientPod, &pokedPod, composedPolicyNameRegex, denyACLVerdict, "")
			}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())
		})
	})
})

var _ = Describe("ACL Logging for EgressFirewall", func() {
	const (
		denyAllPolicyName        = "default-deny-all"
		initialDenyACLSeverity   = "alert"
		initialAllowACLSeverity  = "notice"
		updatedDenyACLSeverity   = "debug"
		updatedAllowACLSeverity  = "debug"
		denyACLVerdict           = "drop"
		allowACLVerdict          = "allow"
		namespacePrefix          = "acl-log-egressfw"
		secondaryNamespacePrefix = "acl-log-egressfw-sec"

		// These targets must be off cluster - traffic to the cluster should always be
		// allowed: https://docs.openshift.com/container-platform/4.10/networking/openshift_sdn/configuring-egress-firewall.html
		// "As a cluster administrator, you can create an egress firewall for a project that restricts egress traffic leaving
		// your OpenShift Container Platform cluster."
		// Because the egress firewall feature only affects traffic leaving the cluster, we will not log for on-cluster targets.
		allowedDstIP = "172.18.0.1"
		deniedDstIP  = "172.19.0.10"
		dstPort      = 8080
	)

	fr := newPrivelegedTestFramework(namespacePrefix)

	var (
		nsName           string
		nsNameSecondary  string
		pokePod          *v1.Pod
		pokePodSecondary *v1.Pod
	)

	BeforeEach(func() {
		By("configuring the ACL logging level within the namespace")
		nsName = fr.Namespace.Name
		Expect(setNamespaceACLLogSeverity(fr, nsName, initialDenyACLSeverity, initialAllowACLSeverity, aclRemoveOptionDelete)).To(Succeed())

		By("creating a \"default deny\" Egress Firewall")
		err := makeEgressFirewall(nsName)
		Expect(err).NotTo(HaveOccurred())

		By("creating a pod running agnhost netexec")
		cmd := []string{"/bin/bash", "-c", "/agnhost netexec --http-port 8000"}
		pod := newAgnhostPod(nsName, "pod", cmd...)
		pokePod = fr.PodClient().CreateSync(pod)
		Expect(waitForACLLoggingPod(fr, nsName, pokePod.GetName())).To(Succeed())

		// The secondary Namespace is required to make sure that 2 namespaces with different logging
		// settings can coexist and that updates to a specific namespace only affect that namespace and
		// not other namespaces.
		By("creating a secondary namespace")
		ns2, err := fr.CreateNamespace(secondaryNamespacePrefix, map[string]string{})
		Expect(err).NotTo(HaveOccurred(), "failed to create secondary namespace")

		By("configuring the ACL logging level within the secondary namespace")
		nsNameSecondary = ns2.Name
		Expect(setNamespaceACLLogSeverity(fr, nsNameSecondary, initialDenyACLSeverity, initialAllowACLSeverity, aclRemoveOptionDelete)).To(Succeed())

		By("creating a \"default deny\" Egress Firewall inside the secondary namespace")
		err = makeEgressFirewall(nsNameSecondary)
		Expect(err).NotTo(HaveOccurred())

		By("creating a pod running agnhost netexec inside the secondary namespace")
		cmdSecondary := []string{"/bin/bash", "-c", "/agnhost netexec --http-port 8000"}
		podSecondary := newAgnhostPod(nsNameSecondary, "pod-secondary", cmdSecondary...)
		// There seems to be a bug in CreateSync for secondary pod. Need to do this here instead:
		pps := fr.PodClientNS(nsNameSecondary).Create(podSecondary)
		Eventually(func() (bool, error) {
			time.Sleep(15 * time.Second)
			pokePodSecondary, err = fr.ClientSet.CoreV1().Pods(nsNameSecondary).Get(context.TODO(), pps.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return pokePodSecondary.Status.Phase == v1.PodRunning, nil
		}, 60, 5).Should(BeTrue())
		Expect(waitForACLLoggingPod(fr, nsNameSecondary, pokePodSecondary.GetName())).To(Succeed())
	})

	AfterEach(func() {
		pokePod = nil
	})

	When("the namespace is brought up with the initial ACL log severity", func() {
		When("the denied destination is poked", func() {
			It("the logs should have the expected log level", func() {
				// Retry here in the case where OVN acls have not been programmed yet
				// Make sure that we see an increment in count
				By("testing the primary namespace")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})

		When("the allowed destination is poked", func() {
			It("the logs should have the expected log level", func() {
				// Retry here in the case where OVN acls have not been programmed yet
				// Make sure that we see an increment in count
				By("testing the primary namespace")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})
	})

	When("the namespace's ACL logging annotation is updated", func() {
		BeforeEach(func() {
			By(fmt.Sprintf("updating the namespace's ACL logging level to %s for deny and %s for allow", updatedDenyACLSeverity, updatedAllowACLSeverity))
			Expect(setNamespaceACLLogSeverity(fr, nsName, updatedDenyACLSeverity, updatedAllowACLSeverity, aclRemoveOptionDelete)).To(Succeed())
		})

		When("the denied destination is poked", func() {
			It("the logs should have the expected log level", func() {
				// Retry here in the case where OVN acls have not been programmed yet
				// Make sure that we see an increment in count
				By("testing the primary namespace")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, deniedDstIP, dstPort, denyACLVerdict, updatedDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})

		When("the allowed destination is poked", func() {
			It("the logs should have the expected log level", func() {
				// Retry here in the case where OVN acls have not been programmed yet
				// Make sure that we see an increment in count
				By("testing the primary namespace")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, allowedDstIP, dstPort, allowACLVerdict, updatedAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})
	})

	When("the namespace's ACL logging allow annotation is removed", func() {
		BeforeEach(func() {
			By("removing the namespace's ACL logging allow configuration")
			Expect(setNamespaceACLLogSeverity(fr, nsName, initialDenyACLSeverity, "", aclRemoveOptionDelete)).To(Succeed())
		})

		When("the denied destination is poked", func() {
			It("the logs should have the expected log level", func() {
				// Retry here in the case where OVN acls have not been programmed yet
				// Make sure that we see an increment in count
				By("testing the primary namespace")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})

		When("the allowed destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})
	})

	When("the namespace's entire ACL logging annotation is removed", func() {
		BeforeEach(func() {
			By("removing the namespace's entire ACL logging configuration")
			Expect(setNamespaceACLLogSeverity(fr, nsName, "", "", aclRemoveOptionDelete)).To(Succeed())
		})

		When("the denied destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, deniedDstIP, dstPort, denyACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})

		When("the allowed destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, allowedDstIP, dstPort, allowACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})
	})

	When("the namespace's entire ACL logging annotation is set to {}", func() {
		BeforeEach(func() {
			By("setting the namespace's entire ACL logging configuration to {}")
			Expect(setNamespaceACLLogSeverity(fr, nsName, "", "", aclRemoveOptionEmptyMap)).To(Succeed())
		})

		When("the denied destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, deniedDstIP, dstPort, denyACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})

		When("the allowed destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, allowedDstIP, dstPort, allowACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})
	})

	When("both the namespace's ACL logging deny and allow annotation are set to \"\"", func() {
		BeforeEach(func() {
			By("setting the namespace's deny annotation to \"\" and the allow annotation to \"\"")
			Expect(setNamespaceACLLogSeverity(fr, nsName, "", "", aclRemoveOptionEmptyString)).To(Succeed())
		})

		When("the denied destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, deniedDstIP, dstPort, denyACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})

		When("the allowed destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, allowedDstIP, dstPort, allowACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})
	})

	When("an invalid value is provided to the allow rule", func() {
		BeforeEach(func() {
			By(fmt.Sprintf("setting the namespace's allow annotation to \"%s\" and the allow annotation to \"invalid\"",
				initialDenyACLSeverity))
			Expect(setNamespaceACLLogSeverity(fr, nsName, initialDenyACLSeverity, "invalid", aclRemoveOptionDelete)).To(Succeed())
		})

		When("the denied destination is poked", func() {
			It("the logs should have the expected log level", func() {
				// Retry here in the case where OVN acls have not been programmed yet
				// Make sure that we see an increment in count
				By("testing the primary namespace")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})

		When("the allowed destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})
	})

	When("both the namespace's ACL logging deny and allow annotation are set to \"invalid\"", func() {
		BeforeEach(func() {
			By("setting the namespace's deny annotation to \"invalid\" and the allow annotation to \"invalid\"")
			Expect(setNamespaceACLLogSeverity(fr, nsName, "invalid", "invalid", aclRemoveOptionEmptyString)).To(Succeed())
		})

		When("the denied destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, deniedDstIP, dstPort, denyACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})

		When("the allowed destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, allowedDstIP, dstPort, allowACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})
	})

	When("the namespace's ACL logging annotation cannot be parsed", func() {
		BeforeEach(func() {
			By("setting the namespace's annotation to value \"cannot-be-parsed\"")
			Expect(setNamespaceACLLogSeverity(fr, nsName, "invalid", "invalid", aclRemoveOptionEmptyString)).To(Succeed())
			Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
				namespaceToUpdate, err := fr.ClientSet.CoreV1().Namespaces().Get(context.Background(), nsName, metav1.GetOptions{})
				if err != nil {
					return err
				}

				if namespaceToUpdate.ObjectMeta.Annotations == nil {
					namespaceToUpdate.ObjectMeta.Annotations = map[string]string{}
				}

				namespaceToUpdate.Annotations[logSeverityNamespaceAnnotation] = "cannot-be-parsed"
				_, err = fr.ClientSet.CoreV1().Namespaces().Update(context.TODO(), namespaceToUpdate, metav1.UpdateOptions{})
				return err
			})).To(Succeed())
		})

		When("the denied destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, deniedDstIP, dstPort, denyACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, deniedDstIP, dstPort, denyACLVerdict, initialDenyACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})

		When("the allowed destination is poked", func() {
			It("there should be no trace in the ACL logs", func() {
				// Retry here until timeout is reached
				// Make sure that we see no increment in count
				By("testing the primary namespace")
				Consistently(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePod, nsName, allowedDstIP, dstPort, allowACLVerdict, "")
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeFalse())

				By("making sure that the secondary namespace logs as expected")
				Eventually(func() (bool, error) {
					return isCountUpdatedAfterPokeExternalHost(fr, pokePodSecondary, nsNameSecondary, allowedDstIP, dstPort, allowACLVerdict, initialAllowACLSeverity)
				}, maxPokeRetries*pokeInterval, pokeInterval).Should(BeTrue())
			})
		})
	})
})

func makeDenyAllPolicy(f *framework.Framework, ns string, policyName string) (*knet.NetworkPolicy, error) {
	policy := &knet.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyName,
		},
		Spec: knet.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []knet.PolicyType{knet.PolicyTypeEgress, knet.PolicyTypeIngress},
			Ingress:     []knet.NetworkPolicyIngressRule{},
			Egress:      []knet.NetworkPolicyEgressRule{},
		},
	}
	return f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(context.TODO(), policy, metav1.CreateOptions{})
}

func makeEgressFirewall(ns string) error {
	egressFirewallYaml := "egressfirewall.yaml"
	var egressFirewallConfig = fmt.Sprintf(`apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: default
  namespace: ` + ns + `
spec:
  egress:
  - type: Allow
    to:
      cidrSelector: 172.18.0.1/32
  - type: Deny
    to:
      cidrSelector: 0.0.0.0/0
`)

	if err := ioutil.WriteFile(egressFirewallYaml, []byte(egressFirewallConfig), 0644); err != nil {
		framework.Failf("Unable to write CRD config to disk: %v", err)
	}

	defer func() {
		if err := os.Remove(egressFirewallYaml); err != nil {
			framework.Logf("Unable to remove the CRD config from disk: %v", err)
		}
	}()

	_, err := framework.RunKubectl(ns, "create", "-f", egressFirewallYaml)
	return err
}

func waitForACLLoggingPod(f *framework.Framework, namespace string, podName string) error {
	return e2epod.WaitForPodCondition(f.ClientSet, namespace, podName, "running", 5*time.Second, func(pod *v1.Pod) (bool, error) {
		podIP := pod.Status.PodIP
		return podIP != "" && pod.Status.Phase != v1.PodPending, nil
	})
}

func isCountUpdatedAfterPokeExternalHost(fr *framework.Framework, pokePod *v1.Pod, nsName, dstIP string, dstPort int, aclVerdict, aclSeverity string) (bool, error) {
	startCount, err := countACLLogs(
		pokePod.Spec.NodeName,
		generateEgressFwRegex(pokePod.Namespace),
		aclVerdict,
		aclSeverity)
	if err != nil {
		return false, err
	}
	pokeExternalHost(fr, pokePod, dstIP, dstPort)
	endCount, _ := countACLLogs(
		pokePod.Spec.NodeName,
		generateEgressFwRegex(pokePod.Namespace),
		aclVerdict,
		aclSeverity)
	if err != nil {
		return false, err
	}
	return startCount < endCount, nil
}

func isCountUpdatedAfterPokePod(fr *framework.Framework, clientPod, pokedPod *v1.Pod, regex, aclVerdict, aclSeverity string) (bool, error) {
	startCount, err := countACLLogs(
		clientPod.Spec.NodeName,
		regex,
		aclVerdict,
		aclSeverity)
	if err != nil {
		return false, err
	}
	pokePod(fr, clientPod.GetName(), pokedPod.Status.PodIP)
	endCount, _ := countACLLogs(
		clientPod.Spec.NodeName,
		regex,
		aclVerdict,
		aclSeverity)
	if err != nil {
		return false, err
	}
	return startCount < endCount, nil
}

func generateEgressFwRegex(nsName string) string {
	return fmt.Sprintf("EF:%s:.*", nsName)
}

func pokeExternalHost(fr *framework.Framework, pokePod *v1.Pod, dstIP string, dstPort int) {
	framework.Logf("sending traffic outside to test triggering ACL logging")
	framework.Logf(
		"Poke destination %s:%d from pod %s/%s (on node %s)",
		dstIP,
		dstPort,
		pokePod.Namespace,
		pokePod.GetName(),
		pokePod.Spec.NodeName,
	)
	pokeExternalHostFromPod(fr, pokePod.Namespace, pokePod.GetName(), dstIP, dstPort)
}

const (
	aclRemoveOptionEmptyMap    = "empty-map"    // Set the annotation to "{}" if both allow and deny are "".
	aclRemoveOptionEmptyString = "empty-string" // Set the field's value to "".
	aclRemoveOptionDelete      = ""             // Delete the field entry if it's value is "".
)

// setNamespaceACLLogSeverity updates namespaceToUpdate with the deny and allow annotations, e.g. k8s.ovn.org/acl-logging={ "deny": "%s", "allow": "%s" }.
func setNamespaceACLLogSeverity(fr *framework.Framework, nsName string, desiredDenyLogLevel string, desiredAllowLogLevel string, removeOption string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		namespaceToUpdate, err := fr.ClientSet.CoreV1().Namespaces().Get(context.Background(), nsName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if namespaceToUpdate.ObjectMeta.Annotations == nil {
			namespaceToUpdate.ObjectMeta.Annotations = map[string]string{}
		}

		aclLogSeverity := ""
		if removeOption == aclRemoveOptionEmptyString || desiredDenyLogLevel != "" && desiredAllowLogLevel != "" {
			aclLogSeverity = fmt.Sprintf(`{ "deny": "%s", "allow": "%s" }`, desiredDenyLogLevel, desiredAllowLogLevel)
			By(fmt.Sprintf("updating the namespace's ACL logging severity to %s", aclLogSeverity))
			namespaceToUpdate.Annotations[logSeverityNamespaceAnnotation] = aclLogSeverity
		} else if removeOption == aclRemoveOptionEmptyMap && desiredDenyLogLevel == "" && desiredAllowLogLevel == "" {
			aclLogSeverity = "{}"
			By(fmt.Sprintf("updating the namespace's ACL logging severity to %s", aclLogSeverity))
			namespaceToUpdate.Annotations[logSeverityNamespaceAnnotation] = aclLogSeverity
		} else {
			if desiredDenyLogLevel != "" {
				aclLogSeverity = fmt.Sprintf(`{ "deny": "%s" }`, desiredDenyLogLevel)
				By(fmt.Sprintf("updating the namespace's ACL logging severity to %s", aclLogSeverity))
				namespaceToUpdate.Annotations[logSeverityNamespaceAnnotation] = aclLogSeverity
			} else if desiredAllowLogLevel != "" {
				aclLogSeverity = fmt.Sprintf(`{ "allow": "%s" }`, desiredAllowLogLevel)
				By(fmt.Sprintf("updating the namespace's ACL logging severity to %s", aclLogSeverity))
				namespaceToUpdate.Annotations[logSeverityNamespaceAnnotation] = aclLogSeverity
			} else {
				By("removing the namespace's ACL logging severity annotation if it exists")
				delete(namespaceToUpdate.Annotations, logSeverityNamespaceAnnotation)
			}
		}

		_, err = fr.ClientSet.CoreV1().Namespaces().Update(context.TODO(), namespaceToUpdate, metav1.UpdateOptions{})
		return err
	})
}
