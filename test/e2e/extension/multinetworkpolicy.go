package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN multinetworkpolicy", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-multinetworkpolicy", compat_otp.KubeConfigPath())

	g.BeforeEach(func() {
		if checkProxy(oc) {
			g.Skip("This is proxy cluster, skip the test.")
		}

		if !isRDUPlatformSuitable(oc) {
			return
		}

	})

	// author: weliang@redhat.com
	g.It("[Level0] Author:weliang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-41168-MultiNetworkPolicy ingress allow same podSelector with same namespaceSelector. [Disruptive]", func() {
		compat_otp.SkipBaselineCaps(oc, "None")
		buildPruningBaseDir := testdata.FixturePath("networking/multinetworkpolicy")
		policyFile := filepath.Join(buildPruningBaseDir, "ingress-allow-same-podSelector-with-same-namespaceSelector.yaml")
		patchSResource := "networks.operator.openshift.io/cluster"
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")

		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
			o.Expect(useContxtErr).NotTo(o.HaveOccurred())
		}()

		ns1 := "project41168a"
		defer oc.AsAdmin().Run("delete").Args("project", ns1, "--ignore-not-found").Execute()
		nserr1 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns1).Execute()
		o.Expect(nserr1).NotTo(o.HaveOccurred())
		_, proerr1 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "user="+ns1).Output()
		o.Expect(proerr1).NotTo(o.HaveOccurred())

		ns2 := "project41168b"
		defer oc.AsAdmin().Run("delete").Args("project", ns2, "--ignore-not-found").Execute()
		nserr2 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns2).Execute()
		o.Expect(nserr2).NotTo(o.HaveOccurred())
		_, proerr2 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "user="+ns2).Output()
		o.Expect(proerr2).NotTo(o.HaveOccurred())

		compat_otp.By("1. Prepare multus multinetwork including 2 ns,5 pods and 2 NADs")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
			waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")
		}()
		prepareMultinetworkTest(oc, ns1, ns2, patchInfoTrue)

		compat_otp.By("2. Get IPs of the pod1ns1's secondary interface in first namespace.")
		pod1ns1IPv4, pod1ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-1")

		compat_otp.By("3. Get IPs of the pod2ns1's secondary interface in first namespace.")
		pod2ns1IPv4, pod2ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-2")

		compat_otp.By("4. Get IPs of the pod3ns1's secondary interface in first namespace.")
		pod3ns1IPv4, pod3ns1IPv6 := getPodMultiNetwork(ns1, "red-pod-1")

		compat_otp.By("5. Get IPs of the pod1ns2's secondary interface in second namespace.")
		pod1ns2IPv4, pod1ns2IPv6 := getPodMultiNetwork(ns2, "blue-pod-3")

		compat_otp.By("6. Get IPs of the pod2ns2's secondary interface in second namespace.")
		pod2ns2IPv4, pod2ns2IPv6 := getPodMultiNetwork(ns2, "red-pod-2")

		compat_otp.By("7. All curl should pass before applying policy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)

		compat_otp.By("8. Create Ingress-allow-same-podSelector-with-same-namespaceSelector policy in ns1")
		oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", policyFile, "-n", ns1).Execute()
		output, err := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("ingress-allow-same-podselector-with-same-namespaceselector"))

		compat_otp.By("9. Same curl testing, one curl pass and three curls will fail after applying policy")
		curlPod2PodMultiNetworkFail(ns1, "red-pod-1", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-3", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkFail(ns1, "red-pod-2", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-2", pod1ns1IPv4, pod1ns1IPv6)

		compat_otp.By("10. Delete ingress-allow-same-podselector-with-same-namespaceselector policy in ns1")
		removeResource(oc, true, true, "multi-networkpolicy", "ingress-allow-same-podselector-with-same-namespaceselector", "-n", ns1)

		compat_otp.By("11. All curl should pass again after deleting policy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-41169-MultiNetworkPolicy ingress allow diff podSelector with same namespaceSelector. [Disruptive]", func() {
		compat_otp.SkipBaselineCaps(oc, "None")
		buildPruningBaseDir := testdata.FixturePath("networking/multinetworkpolicy")
		policyFile := filepath.Join(buildPruningBaseDir, "ingress-allow-diff-podSelector-with-same-namespaceSelector.yaml")
		patchSResource := "networks.operator.openshift.io/cluster"
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")

		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
			o.Expect(useContxtErr).NotTo(o.HaveOccurred())
		}()

		ns1 := "project41169a"
		defer oc.AsAdmin().Run("delete").Args("project", ns1, "--ignore-not-found").Execute()
		nserr1 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns1).Execute()
		o.Expect(nserr1).NotTo(o.HaveOccurred())
		_, proerr1 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "user="+ns1).Output()
		o.Expect(proerr1).NotTo(o.HaveOccurred())

		ns2 := "project41169b"
		defer oc.AsAdmin().Run("delete").Args("project", ns2, "--ignore-not-found").Execute()
		nserr2 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns2).Execute()
		o.Expect(nserr2).NotTo(o.HaveOccurred())
		_, proerr2 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "user="+ns2).Output()
		o.Expect(proerr2).NotTo(o.HaveOccurred())

		compat_otp.By("1. Prepare multus multinetwork including 2 ns,5 pods and 2 NADs")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
			waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")
		}()
		prepareMultinetworkTest(oc, ns1, ns2, patchInfoTrue)

		compat_otp.By("2. Get IPs of the pod1ns1's secondary interface in first namespace.")
		pod1ns1IPv4, pod1ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-1")

		compat_otp.By("3. Get IPs of the pod2ns1's secondary interface in first namespace.")
		pod2ns1IPv4, pod2ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-2")

		compat_otp.By("4. Get IPs of the pod3ns1's secondary interface in first namespace.")
		pod3ns1IPv4, pod3ns1IPv6 := getPodMultiNetwork(ns1, "red-pod-1")

		compat_otp.By("5. Get IPs of the pod1ns2's secondary interface in second namespace.")
		pod1ns2IPv4, pod1ns2IPv6 := getPodMultiNetwork(ns2, "blue-pod-3")

		compat_otp.By("6. Get IPs of the pod2ns2's secondary interface in second namespace.")
		pod2ns2IPv4, pod2ns2IPv6 := getPodMultiNetwork(ns2, "red-pod-2")

		compat_otp.By("7. All curl should pass before applying policy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)

		compat_otp.By("8. Create Ingress-allow-same-podSelector-with-same-namespaceSelector policy in ns1")
		oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", policyFile, "-n", ns1).Execute()
		output, err := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("ingress-allow-diff-podselector-with-same-namespaceselector"))

		compat_otp.By("9. Same curl testing, one curl fail and three curls will pass after applying policy")
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-2", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "red-pod-1", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-3", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkFail(ns1, "red-pod-2", pod1ns1IPv4, pod1ns1IPv6)

		compat_otp.By("10. Delete ingress-allow-diff-podselector-with-same-namespaceselector policy in ns1")
		removeResource(oc, true, true, "multi-networkpolicy", "ingress-allow-diff-podselector-with-same-namespaceselector", "-n", ns1)

		compat_otp.By("11. All curl should pass again after deleting policy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-41171-MultiNetworkPolicy egress allow same podSelector with same namespaceSelector. [Disruptive]", func() {
		compat_otp.SkipBaselineCaps(oc, "None")
		buildPruningBaseDir := testdata.FixturePath("networking/multinetworkpolicy")
		policyFile := filepath.Join(buildPruningBaseDir, "egress-allow-same-podSelector-with-same-namespaceSelector.yaml")
		patchSResource := "networks.operator.openshift.io/cluster"
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")

		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
			o.Expect(useContxtErr).NotTo(o.HaveOccurred())
		}()

		ns1 := "project41171a"
		defer oc.AsAdmin().Run("delete").Args("project", ns1, "--ignore-not-found").Execute()
		nserr1 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns1).Execute()
		o.Expect(nserr1).NotTo(o.HaveOccurred())
		_, proerr1 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "user="+ns1).Output()
		o.Expect(proerr1).NotTo(o.HaveOccurred())

		ns2 := "project41171b"
		defer oc.AsAdmin().Run("delete").Args("project", ns2, "--ignore-not-found").Execute()
		nserr2 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns2).Execute()
		o.Expect(nserr2).NotTo(o.HaveOccurred())
		_, proerr2 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "user="+ns2).Output()
		o.Expect(proerr2).NotTo(o.HaveOccurred())

		compat_otp.By("1. Prepare multus multinetwork including 2 ns,5 pods and 2 NADs")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
			waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")
		}()
		prepareMultinetworkTest(oc, ns1, ns2, patchInfoTrue)

		compat_otp.By("2. Get IPs of the pod2ns1's secondary interface in first namespace.")
		pod2ns1IPv4, pod2ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-2")

		compat_otp.By("3. Get IPs of the pod3ns1's secondary interface in first namespace.")
		pod3ns1IPv4, pod3ns1IPv6 := getPodMultiNetwork(ns1, "red-pod-1")

		compat_otp.By("4. Get IPs of the pod1ns2's secondary interface in second namespace.")
		pod1ns2IPv4, pod1ns2IPv6 := getPodMultiNetwork(ns2, "blue-pod-3")

		compat_otp.By("5. Get IPs of the pod2ns2's secondary interface in second namespace.")
		pod2ns2IPv4, pod2ns2IPv6 := getPodMultiNetwork(ns2, "red-pod-2")

		compat_otp.By("6. All curl should pass before applying policy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)

		compat_otp.By("7. Create egress-allow-same-podSelector-with-same-namespaceSelector policy in ns1")
		oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", policyFile, "-n", ns1).Execute()
		output, err := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("egress-allow-same-podselector-with-same-namespaceselector"))

		compat_otp.By("8. Same curl testing, one curl pass and three curls will fail after applying policy")
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)

		compat_otp.By("9. Delete egress-allow-same-podselector-with-same-namespaceselector policy in ns1")
		removeResource(oc, true, true, "multi-networkpolicy", "egress-allow-same-podselector-with-same-namespaceselector", "-n", ns1)

		compat_otp.By("10. All curl should pass again after deleting policy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-41172-MultiNetworkPolicy egress allow diff podSelector with same namespaceSelector. [Disruptive]", func() {
		compat_otp.SkipBaselineCaps(oc, "None")
		buildPruningBaseDir := testdata.FixturePath("networking/multinetworkpolicy")
		policyFile := filepath.Join(buildPruningBaseDir, "egress-allow-diff-podSelector-with-same-namespaceSelector.yaml")
		patchSResource := "networks.operator.openshift.io/cluster"
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")

		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
			o.Expect(useContxtErr).NotTo(o.HaveOccurred())
		}()

		ns1 := "project41172a"
		defer oc.AsAdmin().Run("delete").Args("project", ns1, "--ignore-not-found").Execute()
		nserr1 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns1).Execute()
		o.Expect(nserr1).NotTo(o.HaveOccurred())
		_, proerr1 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "user="+ns1).Output()
		o.Expect(proerr1).NotTo(o.HaveOccurred())

		ns2 := "project41172b"
		defer oc.AsAdmin().Run("delete").Args("project", ns2, "--ignore-not-found").Execute()
		nserr2 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns2).Execute()
		o.Expect(nserr2).NotTo(o.HaveOccurred())
		_, proerr2 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "user="+ns2).Output()
		o.Expect(proerr2).NotTo(o.HaveOccurred())

		compat_otp.By("1. Prepare multus multinetwork including 2 ns,5 pods and 2 NADs")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
			waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")
		}()
		prepareMultinetworkTest(oc, ns1, ns2, patchInfoTrue)

		compat_otp.By("2. Get IPs of the pod2ns1's secondary interface in first namespace.")
		pod2ns1IPv4, pod2ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-2")

		compat_otp.By("3. Get IPs of the pod3ns1's secondary interface in first namespace.")
		pod3ns1IPv4, pod3ns1IPv6 := getPodMultiNetwork(ns1, "red-pod-1")

		compat_otp.By("4. Get IPs of the pod1ns2's secondary interface in second namespace.")
		pod1ns2IPv4, pod1ns2IPv6 := getPodMultiNetwork(ns2, "blue-pod-3")

		compat_otp.By("5. Get IPs of the pod2ns2's secondary interface in second namespace.")
		pod2ns2IPv4, pod2ns2IPv6 := getPodMultiNetwork(ns2, "red-pod-2")

		compat_otp.By("6. All curl should pass before applying policy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)

		compat_otp.By("7. Create egress-allow-diff-podSelector-with-same-namespaceSelector policy in ns1")
		oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", policyFile, "-n", ns1).Execute()
		output, err := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("egress-allow-diff-podselector-with-same-namespaceselector"))

		compat_otp.By("8. Same curl testing, one curl pass and three curls will fail after applying policy")
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)

		compat_otp.By("9. Delete egress-allow-diff-podselector-with-same-namespaceselector policy in ns1")
		removeResource(oc, true, true, "multi-networkpolicy", "egress-allow-diff-podselector-with-same-namespaceselector", "-n", ns1)

		compat_otp.By("10. All curl should pass again after deleting policy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-41170-MultiNetworkPolicy ingress ipblock. [Disruptive]", func() {
		compat_otp.SkipBaselineCaps(oc, "None")
		buildPruningBaseDir := testdata.FixturePath("networking/multinetworkpolicy")
		patchSResource := "networks.operator.openshift.io/cluster"
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "MultiNetworkPolicy-pod-template.yaml")
		netAttachDefFile := filepath.Join(buildPruningBaseDir, "ipblock-NAD.yaml")
		policyFile := filepath.Join(buildPruningBaseDir, "ingress-ipBlock.yaml")
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")

		compat_otp.By("Getting the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready node for the testing")
		}

		compat_otp.By("1. Enable MacvlanNetworkpolicy in the cluster")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
			waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")
		}()
		patchResourceAsAdmin(oc, patchSResource, patchInfoTrue)
		waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
		waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")

		compat_otp.By("2. Create a namespace")
		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
			o.Expect(useContxtErr).NotTo(o.HaveOccurred())
		}()

		ns1 := "project41170a"
		defer oc.AsAdmin().Run("delete").Args("project", ns1, "--ignore-not-found").Execute()
		nserr1 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns1).Execute()
		o.Expect(nserr1).NotTo(o.HaveOccurred())

		compat_otp.By("3. Create MultiNetworkPolicy-NAD in ns1")
		err1 := oc.AsAdmin().Run("create").Args("-f", netAttachDefFile, "-n", ns1).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())
		output, err2 := oc.AsAdmin().Run("get").Args("net-attach-def", "-n", ns1).Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("ipblock-net"))

		compat_otp.By("4. Create six pods for ip range policy testing")
		pod1ns1 := testPodMultinetwork{
			name:      "blue-pod-1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod1ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		pod2ns1 := testPodMultinetwork{
			name:      "blue-pod-2",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod2ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod2ns1.namespace, pod2ns1.name)

		pod3ns1 := testPodMultinetwork{
			name:      "blue-pod-3",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod3ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod3ns1.namespace, pod3ns1.name)

		pod4ns1 := testPodMultinetwork{
			name:      "blue-pod-4",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod4ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod4ns1.namespace, pod4ns1.name)

		pod5ns1 := testPodMultinetwork{
			name:      "blue-pod-5",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod5ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod5ns1.namespace, pod5ns1.name)

		pod6ns1 := testPodMultinetwork{
			name:      "blue-pod-6",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod6ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod6ns1.namespace, pod6ns1.name)

		g.By("5. Get IPs from all six pod's secondary interfaces")
		pod1ns1IPv4, pod1ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-1")
		pod2ns1IPv4, pod2ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-2")
		pod3ns1IPv4, pod3ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-3")
		pod4ns1IPv4, pod4ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-4")
		pod5ns1IPv4, pod5ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-5")
		pod6ns1IPv4, pod6ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-6")

		compat_otp.By("6. All curl should pass before applying policy")
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod6ns1IPv4, pod6ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod6ns1IPv4, pod6ns1IPv6)

		compat_otp.By("7. Create ingress-ipBlock policy in ns1")
		oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", policyFile, "-n", ns1).Execute()
		output, err3 := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(err3).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("ingress-ipblock"))

		compat_otp.By("8. Curl should fail after applying policy")
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-6", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-6", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-6", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-6", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-6", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-4", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-5", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-6", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-2", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-3", pod1ns1IPv4, pod1ns1IPv6)

		compat_otp.By("9. Delete ingress-ipBlock policy in ns1")
		removeResource(oc, true, true, "multi-networkpolicy", "ingress-ipblock", "-n", ns1)

		compat_otp.By("10. All curl should pass again after deleting policy")
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod6ns1IPv4, pod6ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod6ns1IPv4, pod6ns1IPv6)

	})

	// author: weliang@redhat.com
	g.It("Author:weliang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-41173-MultiNetworkPolicy egress ipblock. [Disruptive]", func() {
		compat_otp.SkipBaselineCaps(oc, "None")
		buildPruningBaseDir := testdata.FixturePath("networking/multinetworkpolicy")
		patchSResource := "networks.operator.openshift.io/cluster"
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "MultiNetworkPolicy-pod-template.yaml")
		netAttachDefFile := filepath.Join(buildPruningBaseDir, "ipblock-NAD.yaml")
		policyFile := filepath.Join(buildPruningBaseDir, "egress-ipBlock.yaml")
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")

		compat_otp.By("Getting the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready node for the testing")
		}

		compat_otp.By("1. Enable MacvlanNetworkpolicy in the cluster")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
			waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")
		}()
		patchResourceAsAdmin(oc, patchSResource, patchInfoTrue)
		waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
		waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")
		compat_otp.By("2. Create a namespace")
		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
			o.Expect(useContxtErr).NotTo(o.HaveOccurred())
		}()

		ns1 := "project41173a"
		defer oc.AsAdmin().Run("delete").Args("project", ns1, "--ignore-not-found").Execute()
		nserr1 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns1).Execute()
		o.Expect(nserr1).NotTo(o.HaveOccurred())

		compat_otp.By("3. Create MultiNetworkPolicy-NAD in ns1")
		policyErr := oc.AsAdmin().Run("create").Args("-f", netAttachDefFile, "-n", ns1).Execute()
		o.Expect(policyErr).NotTo(o.HaveOccurred())
		nadOutput, nadErr := oc.AsAdmin().Run("get").Args("net-attach-def", "-n", ns1).Output()
		o.Expect(nadErr).NotTo(o.HaveOccurred())
		o.Expect(nadOutput).To(o.ContainSubstring("ipblock-net"))

		compat_otp.By("4. Create six pods for egress ip range policy testing")
		pod1ns1 := testPodMultinetwork{
			name:      "blue-pod-1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod1ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		pod2ns1 := testPodMultinetwork{
			name:      "blue-pod-2",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod2ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod2ns1.namespace, pod2ns1.name)

		pod3ns1 := testPodMultinetwork{
			name:      "blue-pod-3",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod3ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod3ns1.namespace, pod3ns1.name)

		pod4ns1 := testPodMultinetwork{
			name:      "blue-pod-4",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod4ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod4ns1.namespace, pod4ns1.name)

		pod5ns1 := testPodMultinetwork{
			name:      "blue-pod-5",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod5ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod5ns1.namespace, pod5ns1.name)

		pod6ns1 := testPodMultinetwork{
			name:      "blue-pod-6",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			nadname:   "ipblock-net",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod6ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod6ns1.namespace, pod6ns1.name)

		compat_otp.By("5. Get IPs from all six pod's secondary interfaces")
		pod1ns1IPv4, pod1ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-1")
		pod2ns1IPv4, pod2ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-2")
		pod3ns1IPv4, pod3ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-3")
		pod4ns1IPv4, pod4ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-4")
		pod5ns1IPv4, pod5ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-5")
		pod6ns1IPv4, pod6ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-6")

		compat_otp.By("6. All curl should pass before applying policy")
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod6ns1IPv4, pod6ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod6ns1IPv4, pod6ns1IPv6)

		compat_otp.By("7. Create egress-ipBlock policy in ns1")
		policyCreateErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", policyFile, "-n", ns1).Execute()
		o.Expect(policyCreateErr).NotTo(o.HaveOccurred())
		policyCreOutput, policyCreErr := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(policyCreErr).NotTo(o.HaveOccurred())
		o.Expect(policyCreOutput).To(o.ContainSubstring("egress-ipblock"))

		compat_otp.By("8. curl should fail for ip range 192.168.0.4-192.168.0.6 after applying policy")
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-1", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-1", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-1", pod6ns1IPv4, pod6ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-2", pod6ns1IPv4, pod6ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-2", pod6ns1IPv4, pod6ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-3", pod6ns1IPv4, pod6ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-4", pod6ns1IPv4, pod6ns1IPv6)
		curlPod2PodMultiNetworkIPBlockFail(ns1, "blue-pod-5", pod6ns1IPv4, pod6ns1IPv6)

		compat_otp.By("9. Delete egress-ipBlock policy in ns1")
		removeResource(oc, true, true, "multi-networkpolicy", "egress-ipblock", "-n", ns1)

		compat_otp.By("10. All curl should pass again after deleting policy")
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-1", pod6ns1IPv4, pod6ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod1ns1IPv4, pod1ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod4ns1IPv4, pod4ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod5ns1IPv4, pod5ns1IPv6)
		curlPod2PodMultiNetworkIPBlockPass(ns1, "blue-pod-6", pod6ns1IPv4, pod6ns1IPv6)
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-41607-Multinetworkpolicy filter-with-tcpport [Disruptive]", func() {
		compat_otp.SkipBaselineCaps(oc, "None")
		buildPruningBaseDir := testdata.FixturePath("networking/multinetworkpolicy")
		patchSResource := "networks.operator.openshift.io/cluster"
		tcpportPod := filepath.Join(buildPruningBaseDir, "tcpport-pod.yaml")
		netAttachDefFile := filepath.Join(buildPruningBaseDir, "MultiNetworkPolicy-NAD1.yaml")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "MultiNetworkPolicy-pod-template.yaml")
		policyFile := filepath.Join(buildPruningBaseDir, "policy-tcpport.yaml")
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")

		compat_otp.By("Getting the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready node for the testing")
		}

		compat_otp.By("1. Enable MacvlanNetworkpolicy in the cluster")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
			waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")
		}()
		patchResourceAsAdmin(oc, patchSResource, patchInfoTrue)
		waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
		waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")

		compat_otp.By("2. Create a namespace")
		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
			o.Expect(useContxtErr).NotTo(o.HaveOccurred())
		}()

		ns := "project41607"
		defer oc.AsAdmin().Run("delete").Args("project", ns, "--ignore-not-found").Execute()
		nserr1 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns).Execute()
		o.Expect(nserr1).NotTo(o.HaveOccurred())

		compat_otp.By("3. Create MultiNetworkPolicy-NAD in ns")
		policyErr := oc.AsAdmin().Run("create").Args("-f", netAttachDefFile, "-n", ns).Execute()
		o.Expect(policyErr).NotTo(o.HaveOccurred())
		nadOutput, nadErr := oc.AsAdmin().Run("get").Args("net-attach-def", "-n", ns).Output()
		o.Expect(nadErr).NotTo(o.HaveOccurred())
		o.Expect(nadOutput).To(o.ContainSubstring("macvlan-nad1"))

		compat_otp.By("4. Create a tcpport pods for ingress tcp port testing")
		createResourceFromFile(oc, ns, tcpportPod)
		podErr := waitForPodWithLabelReady(oc, ns, "name=tcp-port-pod")
		compat_otp.AssertWaitPollNoErr(podErr, "tcpportPod is not running")
		podIPv4, _ := getPodMultiNetwork(ns, "tcp-port-pod")

		compat_otp.By("5. Create a test pods for ingress tcp port testing")
		pod1ns1 := testPodMultinetwork{
			name:      "blue-pod-1",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			nadname:   "macvlan-nad1",
			labelname: "blue-openshift",
			template:  pingPodTemplate,
		}
		pod1ns1.createTestPodMultinetwork(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		compat_otp.By("6. curl should pass before applying policy")
		_, curl1Err := e2eoutput.RunHostCmd(ns, "blue-pod-1", "curl --connect-timeout 5 -s "+net.JoinHostPort(podIPv4, "8888"))
		o.Expect(curl1Err).NotTo(o.HaveOccurred())

		compat_otp.By("7. Create tcpport policy in ns")
		policyCreateErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", policyFile, "-n", ns).Execute()
		o.Expect(policyCreateErr).NotTo(o.HaveOccurred())
		policyCreOutput, policyCreErr := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns).Output()
		o.Expect(policyCreErr).NotTo(o.HaveOccurred())
		o.Expect(policyCreOutput).To(o.ContainSubstring("tcp-port"))

		compat_otp.By("8. One curl should fail before applying policy")
		_, curl2Err := e2eoutput.RunHostCmd(ns, "blue-pod-1", "curl --connect-timeout 5 -s "+net.JoinHostPort(podIPv4, "8888"))
		o.Expect(curl2Err).To(o.HaveOccurred())

		compat_otp.By("9. Delete tcp-port policy in ns")
		removeResource(oc, true, true, "multi-networkpolicy", "tcp-port", "-n", ns)

		compat_otp.By("10. curl should pass after deleting policy")
		_, curl3Err := e2eoutput.RunHostCmd(ns, "blue-pod-1", "curl --connect-timeout 5 -s "+net.JoinHostPort(podIPv4, "8888"))
		o.Expect(curl3Err).NotTo(o.HaveOccurred())
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-55818-[NETWORKCUSIM] Rules are not removed after disabling multinetworkpolicy. [Disruptive]", func() {
		compat_otp.SkipBaselineCaps(oc, "None")
		//https://issues.redhat.com/browse/OCPBUGS-977: Rules are not removed after disabling multinetworkpolicy
		buildPruningBaseDir := testdata.FixturePath("networking/multinetworkpolicy")
		policyFile := filepath.Join(buildPruningBaseDir, "creat-ten-rules.yaml")
		patchSResource := "networks.operator.openshift.io/cluster"
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")

		compat_otp.By("Getting the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready node for the testing")
		}

		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
				o.Expect(useContxtErr).NotTo(o.HaveOccurred())
			}
		}()
		ns1 := "project41171a"
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().Run("delete").Args("project", ns1, "--ignore-not-found").Execute()
			}
		}()
		nserr1 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns1).Execute()
		o.Expect(nserr1).NotTo(o.HaveOccurred())
		_, proerr1 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "user="+ns1).Output()
		o.Expect(proerr1).NotTo(o.HaveOccurred())

		ns2 := "project41171b"
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().Run("delete").Args("project", ns2, "--ignore-not-found").Execute()
			}
		}()
		nserr2 := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(ns2).Execute()
		o.Expect(nserr2).NotTo(o.HaveOccurred())
		_, proerr2 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "user="+ns2).Output()
		o.Expect(proerr2).NotTo(o.HaveOccurred())

		compat_otp.By("1. Prepare multus multinetwork including 2 ns,5 pods and 2 NADs")
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
				compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
				waitForNetworkOperatorState(oc, 20, 20, "True.*False.*False")
			}
		}()
		prepareMultinetworkTest(oc, ns1, ns2, patchInfoTrue)

		compat_otp.By("2. Get IPs of the pod2ns1's secondary interface in first namespace.")
		pod2ns1IPv4, pod2ns1IPv6 := getPodMultiNetwork(ns1, "blue-pod-2")

		compat_otp.By("3. Get IPs of the pod3ns1's secondary interface in first namespace.")
		pod3ns1IPv4, pod3ns1IPv6 := getPodMultiNetwork(ns1, "red-pod-1")

		compat_otp.By("4. Get IPs of the pod1ns2's secondary interface in second namespace.")
		pod1ns2IPv4, pod1ns2IPv6 := getPodMultiNetwork(ns2, "blue-pod-3")

		compat_otp.By("5. Get IPs of the pod2ns2's secondary interface in second namespace.")
		pod2ns2IPv4, pod2ns2IPv6 := getPodMultiNetwork(ns2, "red-pod-2")

		compat_otp.By("6. All curl should pass before applying policy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)

		compat_otp.By("7. Create egress-allow-same-podSelector-with-same-namespaceSelector policy in ns1")
		o.Expect(oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", policyFile, "-n", ns1).Execute()).NotTo(o.HaveOccurred())
		output, err := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		policyList := []string{
			"egress-allow-same-podselector-with-same-namespaceselector1",
			"egress-allow-same-podselector-with-same-namespaceselector2",
			"egress-allow-same-podselector-with-same-namespaceselector3",
			"egress-allow-same-podselector-with-same-namespaceselector4",
			"egress-allow-same-podselector-with-same-namespaceselector5",
			"egress-allow-same-podselector-with-same-namespaceselector6",
			"egress-allow-same-podselector-with-same-namespaceselector7",
			"egress-allow-same-podselector-with-same-namespaceselector8",
			"egress-allow-same-podselector-with-same-namespaceselector9",
			"egress-allow-same-podselector-with-same-namespaceselector10",
		}
		for _, policyRule := range policyList {
			e2e.Logf("The policy rule is: %s", policyRule)
			o.Expect(output).To(o.ContainSubstring(policyRule))
		}

		compat_otp.By("8. Same curl testing, one curl pass and three curls will fail after applying policy")
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkFail(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)

		compat_otp.By("9. Disable MultiNetworkpolicy in the cluster")
		patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
		compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
		waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
		waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")

		compat_otp.By("10. All curl should pass again after disabling MacvlanNetworkpolicy")
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod3ns1IPv4, pod3ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod1ns2IPv4, pod1ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns2IPv4, pod2ns2IPv6)
		curlPod2PodMultiNetworkPass(ns1, "blue-pod-1", pod2ns1IPv4, pod2ns1IPv6)
	})
})
