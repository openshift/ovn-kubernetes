package e2e

import (
	"context"
	"fmt"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/feature"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/images"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider"

	nadclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	e2edeployment "k8s.io/kubernetes/test/e2e/framework/deployment"
	e2eservice "k8s.io/kubernetes/test/e2e/framework/service"
)

var _ = Describe("Network Segmentation EndpointSlices mirroring", feature.NetworkSegmentation, func() {
	f := wrappedTestFramework("endpointslices-mirror")
	f.SkipNamespaceCreation = true
	Context("a user defined primary network", func() {
		const (
			userDefinedNetworkIPv4Subnet = "10.128.0.0/16"
			userDefinedNetworkIPv6Subnet = "2014:100:200::0/60"
			nadName                      = "gryffindor"
		)

		var (
			cs        clientset.Interface
			nadClient nadclient.K8sCniCncfIoV1Interface
		)

		BeforeEach(func() {
			cs = f.ClientSet
			namespace, err := f.CreateNamespace(context.TODO(), f.BaseName, map[string]string{
				"e2e-framework":           f.BaseName,
				RequiredUDNNamespaceLabel: "",
			})
			f.Namespace = namespace
			Expect(err).NotTo(HaveOccurred())
			nadClient, err = nadclient.NewForConfig(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())
		})

		DescribeTableSubtree("created using",
			func(createNetworkFn func(c networkAttachmentConfigParams) error) {
				DescribeTable(
					"mirrors EndpointSlices managed by the default controller for namespaces with user defined primary networks",
					func(
						netConfig networkAttachmentConfigParams,
						isHostNetwork bool,
					) {
						By("creating the network")
						netConfig.namespace = f.Namespace.Name
						netConfig.cidr = filterCIDRsAndJoin(f.ClientSet, netConfig.cidr)
						Expect(createNetworkFn(netConfig)).To(Succeed())

						replicas := int32(3)
						By("creating the deployment")
						var port uint16 = 80
						if isHostNetwork {
							port = infraprovider.Get().GetK8HostPort()
						}
						deployment := e2edeployment.NewDeployment("test-deployment", replicas, map[string]string{"app": "test"}, "agnhost", images.AgnHost(), appsv1.RollingUpdateDeploymentStrategyType)
						deployment.Namespace = f.Namespace.Name
						deployment.Spec.Template.Spec.HostNetwork = isHostNetwork
						deployment.Spec.Template.Spec.Containers[0].Command = getAgnHostHTTPPortBindFullCMD(port)

						_, err := cs.AppsV1().Deployments(f.Namespace.Name).Create(context.Background(), deployment, metav1.CreateOptions{})
						framework.ExpectNoError(err, "Failed creating the deployment %v", err)
						err = e2edeployment.WaitForDeploymentComplete(cs, deployment)
						framework.ExpectNoError(err, "Failed starting the deployment %v", err)

						By("creating the service")
						svc := e2eservice.CreateServiceSpec("test-service", "", false, map[string]string{"app": "test"})
						familyPolicy := v1.IPFamilyPolicyPreferDualStack
						svc.Spec.IPFamilyPolicy = &familyPolicy
						_, err = cs.CoreV1().Services(f.Namespace.Name).Create(context.Background(), svc, metav1.CreateOptions{})
						framework.ExpectNoError(err, "Failed creating service %v", err)

						nodes, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
						framework.ExpectNoError(err, "Failed listing nodes %v", err)
						hostSubnets, err := util.ParseNodePrimaryIfAddr(&nodes.Items[0])
						framework.ExpectNoError(err, "Failed parsing nodes host CIDR %v", err)
						isDualStack := isDualStackCluster(nodes)

						By("asserting the mirrored EndpointSlice exists and contains PODs primary IPs")
						Eventually(func() error {
							return validateMirroredEndpointSlices(cs, f.Namespace.Name, svc.Name, userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet, hostSubnets, int(replicas), isDualStack, isHostNetwork)

						}, 2*time.Minute, 6*time.Second).ShouldNot(HaveOccurred())

						By("removing the mirrored EndpointSlice so it gets recreated")
						err = cs.DiscoveryV1().EndpointSlices(f.Namespace.Name).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", "k8s.ovn.org/service-name", svc.Name)})
						framework.ExpectNoError(err, "Failed removing the mirrored EndpointSlice %v", err)
						Eventually(func() error {
							return validateMirroredEndpointSlices(cs, f.Namespace.Name, svc.Name, userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet, hostSubnets, int(replicas), isDualStack, isHostNetwork)
						}, 2*time.Minute, 6*time.Second).ShouldNot(HaveOccurred())

						By("removing the service so both EndpointSlices get removed")
						err = cs.CoreV1().Services(f.Namespace.Name).Delete(context.TODO(), svc.Name, metav1.DeleteOptions{})
						framework.ExpectNoError(err, "Failed removing the service %v", err)
						Eventually(func() error {
							esList, err := cs.DiscoveryV1().EndpointSlices(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", "k8s.ovn.org/service-name", svc.Name)})
							if err != nil {
								return err
							}

							if len(esList.Items) != 0 {
								return fmt.Errorf("expected no mirrored EndpointSlice, got: %d", len(esList.Items))
							}
							return nil
						}, 2*time.Minute, 6*time.Second).ShouldNot(HaveOccurred())

					},
					Entry(
						"L2 primary UDN, cluster-networked pods",
						networkAttachmentConfigParams{
							name:     nadName,
							topology: "layer2",
							cidr:     joinCIDRs(userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet),
							role:     "primary",
						},
						false,
					),
					Entry(
						"L3 primary UDN, cluster-networked pods",
						networkAttachmentConfigParams{
							name:     nadName,
							topology: "layer3",
							cidr:     joinCIDRs(userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet),
							role:     "primary",
						},
						false,
					),
					Entry(
						"L2 primary UDN, host-networked pods",
						networkAttachmentConfigParams{
							name:     nadName,
							topology: "layer2",
							cidr:     joinCIDRs(userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet),
							role:     "primary",
						},
						true,
					),
					Entry(
						"L3 primary UDN, host-networked pods",
						networkAttachmentConfigParams{
							name:     nadName,
							topology: "layer3",
							cidr:     joinCIDRs(userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet),
							role:     "primary",
						},
						true,
					),
				)
			},
			Entry("NetworkAttachmentDefinitions", func(c networkAttachmentConfigParams) error {
				netConfig := newNetworkAttachmentConfig(c)
				nad := generateNAD(netConfig)
				_, err := nadClient.NetworkAttachmentDefinitions(f.Namespace.Name).Create(context.Background(), nad, metav1.CreateOptions{})
				return err
			}),
			Entry("UserDefinedNetwork", func(c networkAttachmentConfigParams) error {
				udnManifest := generateUserDefinedNetworkManifest(&c)
				cleanup, err := createManifest(f.Namespace.Name, udnManifest)
				DeferCleanup(cleanup)
				Eventually(userDefinedNetworkReadyFunc(f.DynamicClient, f.Namespace.Name, c.name), 5*time.Second, time.Second).Should(Succeed())
				return err
			}),
		)

		DescribeTableSubtree("created using",
			func(createNetworkFn func(c networkAttachmentConfigParams) error) {
				DescribeTable(
					"does not mirror EndpointSlices in namespaces not using user defined primary networks",
					func(
						netConfig networkAttachmentConfigParams,
					) {
						By("creating default net namespace")
						defaultNetNamespace := &v1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: f.Namespace.Name + "-default",
							},
						}
						f.AddNamespacesToDelete(defaultNetNamespace)
						_, err := cs.CoreV1().Namespaces().Create(context.Background(), defaultNetNamespace, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())
						By("creating the network")
						netConfig.namespace = defaultNetNamespace.Name
						netConfig.cidr = filterCIDRsAndJoin(f.ClientSet, netConfig.cidr)
						Expect(createNetworkFn(netConfig)).To(Succeed())

						replicas := int32(3)
						By("creating the deployment")
						deployment := e2edeployment.NewDeployment("test-deployment", replicas, map[string]string{"app": "test"}, "agnhost", images.AgnHost(), appsv1.RollingUpdateDeploymentStrategyType)
						deployment.Namespace = defaultNetNamespace.Name
						deployment.Spec.Template.Spec.Containers[0].Command = getAgnHostHTTPPortBindFullCMD(80)

						_, err = cs.AppsV1().Deployments(defaultNetNamespace.Name).Create(context.Background(), deployment, metav1.CreateOptions{})
						framework.ExpectNoError(err, "Failed creating the deployment %v", err)
						err = e2edeployment.WaitForDeploymentComplete(cs, deployment)
						framework.ExpectNoError(err, "Failed starting the deployment %v", err)

						By("creating the service")
						svc := e2eservice.CreateServiceSpec("test-service", "", false, map[string]string{"app": "test"})
						familyPolicy := v1.IPFamilyPolicyPreferDualStack
						svc.Spec.IPFamilyPolicy = &familyPolicy
						_, err = cs.CoreV1().Services(defaultNetNamespace.Name).Create(context.Background(), svc, metav1.CreateOptions{})
						framework.ExpectNoError(err, "Failed creating service %v", err)

						By("asserting the mirrored EndpointSlice does not exist")
						Eventually(func() error {
							esList, err := cs.DiscoveryV1().EndpointSlices(defaultNetNamespace.Name).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", "k8s.ovn.org/service-name", svc.Name)})
							if err != nil {
								return err
							}

							if len(esList.Items) != 0 {
								return fmt.Errorf("expected no mirrored EndpointSlice, got: %d", len(esList.Items))
							}
							return nil
						}, 2*time.Minute, 6*time.Second).ShouldNot(HaveOccurred())
					},
					Entry(
						"L2 secondary UDN",
						networkAttachmentConfigParams{
							name:     nadName,
							topology: "layer2",
							cidr:     joinCIDRs(userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet),
							role:     "secondary",
						},
					),
					Entry(
						"L3 secondary UDN",
						networkAttachmentConfigParams{
							name:     nadName,
							topology: "layer3",
							cidr:     joinCIDRs(userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet),
							role:     "secondary",
						},
					),
				)
			},
			Entry("NetworkAttachmentDefinitions", func(c networkAttachmentConfigParams) error {
				netConfig := newNetworkAttachmentConfig(c)
				nad := generateNAD(netConfig)
				_, err := nadClient.NetworkAttachmentDefinitions(fmt.Sprintf("%s-default", f.Namespace.Name)).Create(context.Background(), nad, metav1.CreateOptions{})
				return err
			}),
			Entry("UserDefinedNetwork", func(c networkAttachmentConfigParams) error {
				udnManifest := generateUserDefinedNetworkManifest(&c)
				cleanup, err := createManifest(fmt.Sprintf("%s-default", f.Namespace.Name), udnManifest)
				DeferCleanup(cleanup)
				Eventually(userDefinedNetworkReadyFunc(f.DynamicClient, fmt.Sprintf("%s-default", f.Namespace.Name), c.name), 5*time.Second, time.Second).Should(Succeed())
				return err
			}),
		)
	})
})

func validateMirroredEndpointSlices(cs clientset.Interface, namespace, svcName, expectedV4Subnet, expectedV6Subnet string, hostSubnet *util.ParsedNodeEgressIPConfiguration, expectedEndpoints int, isDualStack, isHostNetwork bool) error {
	esList, err := cs.DiscoveryV1().EndpointSlices(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", "k8s.ovn.org/service-name", svcName)})
	if err != nil {
		return err
	}

	expectedEndpointSlicesCount := 1
	if isDualStack {
		expectedEndpointSlicesCount = 2
	}
	if len(esList.Items) != expectedEndpointSlicesCount {
		return fmt.Errorf("expected %d mirrored EndpointSlice, got: %d", expectedEndpointSlicesCount, len(esList.Items))
	}

	for _, endpointSlice := range esList.Items {
		if len(endpointSlice.Endpoints) != expectedEndpoints {
			return fmt.Errorf("expected %d endpoints, got: %d", expectedEndpoints, len(esList.Items))
		}

		subnet := expectedV4Subnet
		if isHostNetwork {
			subnet = hostSubnet.V4.Net.String()
		}

		if endpointSlice.AddressType == discoveryv1.AddressTypeIPv6 {
			subnet = expectedV6Subnet
			if isHostNetwork {
				subnet = hostSubnet.V6.Net.String()
			}
		}
		for _, endpoint := range endpointSlice.Endpoints {
			if len(endpoint.Addresses) != 1 {
				return fmt.Errorf("expected 1 endpoint, got: %d", len(endpoint.Addresses))
			}
			if err := inRange(subnet, endpoint.Addresses[0]); err != nil {
				return err
			}
		}
	}
	return nil
}
