package clustermanager

import (
	"context"
	"net"
	"sync"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	egressqosfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressqos/v1/apis/clientset/versioned/fake"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

var _ = ginkgo.Describe("Cluster Manager operations", func() {
	var (
		app      *cli.App
		f        *factory.WatchFactory
		stopChan chan struct{}
		wg       *sync.WaitGroup
	)

	const (
		clusterIPNet             string = "10.1.0.0"
		clusterCIDR              string = clusterIPNet + "/16"
		hybridOverlayClusterCIDR string = "11.1.0.0/16/24"
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		gomega.Expect(config.PrepareTestConfig()).To(gomega.Succeed())

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
		stopChan = make(chan struct{})
		wg = &sync.WaitGroup{}
	})

	ginkgo.AfterEach(func() {
		close(stopChan)
		f.Shutdown()
		wg.Wait()
	})

	ginkgo.It("Cluster Manager Node subnet allocations", func() {

		app.Action = func(ctx *cli.Context) error {
			nodes := []v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node2",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node3",
					},
				}}
			kubeFakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: nodes,
			})
			egressFirewallFakeClient := &egressfirewallfake.Clientset{}
			egressIPFakeClient := &egressipfake.Clientset{}
			egressQoSFakeClient := &egressqosfake.Clientset{}
			fakeClient := &util.OVNClientset{
				KubeClient:           kubeFakeClient,
				EgressIPClient:       egressIPFakeClient,
				EgressFirewallClient: egressFirewallFakeClient,
				EgressQoSClient:      egressQoSFakeClient,
			}

			_, err := config.InitConfig(ctx, nil, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			config.Kubernetes.HostNetworkNamespace = ""

			f, err = factory.NewClusterManagerWatchFactory(fakeClient)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = f.Start()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			clusterManager := NewClusterManager(fakeClient, f, wg,
				record.NewFakeRecorder(0))
			gomega.Expect(clusterManager).NotTo(gomega.BeNil())

			err = clusterManager.Run()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Check that cluster manager has set the subnet annotation for each node.
			for _, n := range nodes {
				gomega.Eventually(func() ([]*net.IPNet, error) {
					updatedNode, err := fakeClient.KubeClient.CoreV1().Nodes().Get(context.TODO(), n.Name, metav1.GetOptions{})
					if err != nil {
						return nil, err
					}

					return util.ParseNodeHostSubnetAnnotation(updatedNode, types.DefaultNetworkName)
				}, 2).Should(gomega.HaveLen(1))
			}

			// Clear the subnet annotation of node 1 and make sure it is re-allocated by cluster manager.
			nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{kubeFakeClient, egressIPFakeClient, egressFirewallFakeClient, nil}, "node1")
			util.DeleteNodeHostSubnetAnnotation(nodeAnnotator)
			err = nodeAnnotator.Run()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Eventually(func() ([]*net.IPNet, error) {
				updatedNode, err := fakeClient.KubeClient.CoreV1().Nodes().Get(context.TODO(), "node1", metav1.GetOptions{})
				if err != nil {
					return nil, err
				}

				return util.ParseNodeHostSubnetAnnotation(updatedNode, types.DefaultNetworkName)
			}, 2).Should(gomega.HaveLen(1))

			clusterManager.Stop()

			// Need to unregister the metrics, otherwise the subsequent tests would fail with the error
			// that the metrics are already registered.
			metrics.UnRegisterClusterManagerFunctional()
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-cluster-subnets=" + clusterCIDR,
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("Cluster Manager Node subnet allocations - hybrid and linux nodes", func() {

		app.Action = func(ctx *cli.Context) error {
			nodes := []v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node2",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node3",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "winnode",
						Labels: map[string]string{v1.LabelOSStable: "windows"},
					},
				}}
			kubeFakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: nodes,
			})
			egressFirewallFakeClient := &egressfirewallfake.Clientset{}
			egressIPFakeClient := &egressipfake.Clientset{}
			egressQoSFakeClient := &egressqosfake.Clientset{}
			fakeClient := &util.OVNClientset{
				KubeClient:           kubeFakeClient,
				EgressIPClient:       egressIPFakeClient,
				EgressFirewallClient: egressFirewallFakeClient,
				EgressQoSClient:      egressQoSFakeClient,
			}

			_, err := config.InitConfig(ctx, nil, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			config.Kubernetes.HostNetworkNamespace = ""

			f, err = factory.NewClusterManagerWatchFactory(fakeClient)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = f.Start()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			clusterManager := NewClusterManager(fakeClient, f, wg,
				record.NewFakeRecorder(0))
			gomega.Expect(clusterManager).NotTo(gomega.BeNil())
			err = clusterManager.Run()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Check that cluster manager has set the subnet annotation for each node.
			for _, n := range nodes {
				if n.Name == "winnode" {
					continue
				}

				gomega.Eventually(func() ([]*net.IPNet, error) {
					updatedNode, err := fakeClient.KubeClient.CoreV1().Nodes().Get(context.TODO(), n.Name, metav1.GetOptions{})
					if err != nil {
						return nil, err
					}

					return util.ParseNodeHostSubnetAnnotation(updatedNode, types.DefaultNetworkName)
				}, 2).Should(gomega.HaveLen(1))
			}

			// Windows node should be allocated a subnet
			gomega.Eventually(func() (map[string]string, error) {
				updatedNode, err := fakeClient.KubeClient.CoreV1().Nodes().Get(context.TODO(), "winnode", metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return updatedNode.Annotations, nil
			}, 2).Should(gomega.HaveKey(hotypes.HybridOverlayNodeSubnet))

			gomega.Eventually(func() error {
				updatedNode, err := fakeClient.KubeClient.CoreV1().Nodes().Get(context.TODO(), "winnode", metav1.GetOptions{})
				if err != nil {
					return err
				}
				_, err = util.ParseNodeHostSubnetAnnotation(updatedNode, types.DefaultNetworkName)
				return err
			}, 2).Should(gomega.MatchError("could not find \"k8s.ovn.org/node-subnets\" annotation"))

			// Need to unregister the metrics, otherwise the subsequent tests would fail with the error
			// that the metrics are already registered.
			metrics.UnRegisterClusterManagerFunctional()
			clusterManager.Stop()
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"--no-hostsubnet-nodes=kubernetes.io/os=windows",
			"-cluster-subnets=" + clusterCIDR,
			"-gateway-mode=shared",
			"-enable-hybrid-overlay",
			"-hybrid-overlay-cluster-subnets=" + hybridOverlayClusterCIDR,
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
})
