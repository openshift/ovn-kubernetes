package userdefinednetwork

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"
	"k8s.io/utils/pointer"

	netv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netv1fakeclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	netv1informerfactory "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions"
	netv1Informer "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions/k8s.cni.cncf.io/v1"

	udnv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	udnfakeclient "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/clientset/versioned/fake"
	udninformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/informers/externalversions"
	udninformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/informers/externalversions/userdefinednetwork/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var _ = Describe("User Defined Network Controller", func() {
	var (
		udnClient   *udnfakeclient.Clientset
		nadClient   *netv1fakeclientset.Clientset
		udnInformer udninformer.UserDefinedNetworkInformer
		nadInformer netv1Informer.NetworkAttachmentDefinitionInformer
	)

	BeforeEach(func() {
		udnClient = udnfakeclient.NewSimpleClientset()
		udnInformer = udninformerfactory.NewSharedInformerFactory(udnClient, 15).K8s().V1().UserDefinedNetworks()
		nadClient = netv1fakeclientset.NewSimpleClientset()
		nadInformer = netv1informerfactory.NewSharedInformerFactory(nadClient, 15).K8sCniCncfIo().V1().NetworkAttachmentDefinitions()
	})

	Context("controller", func() {
		var f *factory.WatchFactory

		BeforeEach(func() {
			// Restore global default values before each testcase
			Expect(config.PrepareTestConfig()).To(Succeed())
			config.OVNKubernetesFeature.EnableMultiNetwork = true
			config.OVNKubernetesFeature.EnableNetworkSegmentation = true

			fakeClient := &util.OVNClusterManagerClientset{
				KubeClient:               fake.NewSimpleClientset(),
				NetworkAttchDefClient:    nadClient,
				UserDefinedNetworkClient: udnClient,
			}
			var err error
			f, err = factory.NewClusterManagerWatchFactory(fakeClient)
			Expect(err).NotTo(HaveOccurred())
			Expect(f.Start()).To(Succeed())
		})

		AfterEach(func() {
			f.Shutdown()
		})

		It("should create NAD successfully", func() {
			udn := testUDN()
			udn, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Create(context.Background(), udn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			expectedNAD := testNAD()
			c := New(nadClient, f.NADInformer(), udnClient, f.UserDefinedNetworkInformer(), renderNadStub(expectedNAD))
			Expect(c.Run()).To(Succeed())

			Eventually(func() []metav1.Condition {
				udn, err = udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				return normalizeConditions(udn.Status.Conditions)
			}).Should(Equal([]metav1.Condition{{
				Type:    "NetworkReady",
				Status:  "True",
				Reason:  "NetworkAttachmentDefinitionReady",
				Message: "NetworkAttachmentDefinition has been created",
			}}))

			nad, err := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			Expect(nad).To(Equal(expectedNAD))
		})

		It("should fail when NAD render fail", func() {
			udn := testUDN()
			udn, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Create(context.Background(), udn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			renderErr := errors.New("render NAD fails")

			c := New(nadClient, f.NADInformer(), udnClient, f.UserDefinedNetworkInformer(), failRenderNadStub(renderErr))
			Expect(c.Run()).To(Succeed())

			Eventually(func() []metav1.Condition {
				udn, err = udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				return normalizeConditions(udn.Status.Conditions)
			}).Should(Equal([]metav1.Condition{{
				Type:    "NetworkReady",
				Status:  "False",
				Reason:  "SyncError",
				Message: "failed to generate NetworkAttachmentDefinition: " + renderErr.Error(),
			}}))

			_, err = nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
			Expect(kerrors.IsNotFound(err)).To(BeTrue())
		})
		It("should fail when NAD create fail", func() {
			udn := testUDN()
			udn, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Create(context.Background(), udn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			expectedError := errors.New("create NAD error")
			nadClient.PrependReactor("create", "network-attachment-definitions", func(action testing.Action) (handled bool, ret runtime.Object, err error) {
				return true, nil, expectedError
			})

			c := New(nadClient, f.NADInformer(), udnClient, f.UserDefinedNetworkInformer(), noopRenderNadStub())
			Expect(c.Run()).To(Succeed())

			Eventually(func() []metav1.Condition {
				udn, err = udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				return udn.Status.Conditions
			}).ShouldNot(BeEmpty())

			Expect(normalizeConditions(udn.Status.Conditions)).To(Equal([]metav1.Condition{{
				Type:    "NetworkReady",
				Status:  "False",
				Reason:  "SyncError",
				Message: "failed to create NetworkAttachmentDefinition: create NAD error",
			}}))

			_, err = nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
			Expect(kerrors.IsNotFound(err)).To(BeTrue())
		})

		It("should fail when foreign NAD exist", func() {
			udn := testUDN()
			udn, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Create(context.Background(), udn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			foreignNad := testNAD()
			foreignNad.ObjectMeta.OwnerReferences = nil
			foreignNad, err = nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Create(context.Background(), foreignNad, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			c := New(nadClient, f.NADInformer(), udnClient, f.UserDefinedNetworkInformer(), noopRenderNadStub())
			Expect(c.Run()).To(Succeed())

			Eventually(func() []metav1.Condition {
				udn, err = udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				return udn.Status.Conditions
			}).ShouldNot(BeEmpty())

			Expect(normalizeConditions(udn.Status.Conditions)).To(Equal([]metav1.Condition{{
				Type:    "NetworkReady",
				Status:  "False",
				Reason:  "SyncError",
				Message: "foreign NetworkAttachmentDefinition with the desired name already exist [test/test]",
			}}))
		})
		It("should reconcile mutated NAD", func() {
			udn := testUDN()
			udn, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Create(context.Background(), udn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			expectedNAD := testNAD()

			c := New(nadClient, f.NADInformer(), udnClient, f.UserDefinedNetworkInformer(), renderNadStub(expectedNAD))
			Expect(c.Run()).To(Succeed())

			Eventually(func() []metav1.Condition {
				udn, err = udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				return udn.Status.Conditions
			}).ShouldNot(BeEmpty())
			Expect(normalizeConditions(udn.Status.Conditions)).To(Equal([]metav1.Condition{{
				Type:    "NetworkReady",
				Status:  "True",
				Reason:  "NetworkAttachmentDefinitionReady",
				Message: "NetworkAttachmentDefinition has been created",
			}}))

			mutatedNAD := expectedNAD.DeepCopy()
			p := []byte(`[{"op":"replace","path":"/spec/config","value":"MUTATED"}]`)
			mutatedNAD, err = nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Patch(context.Background(), mutatedNAD.Name, types.JSONPatchType, p, metav1.PatchOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() *netv1.NetworkAttachmentDefinition {
				updatedNAD, err := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				return updatedNAD
			}).Should(Equal(expectedNAD))
		})
		It("should fail when update mutated NAD fails", func() {
			expectedNAD := testNAD()

			udn := testUDN()
			udn, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Create(context.Background(), udn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			c := New(nadClient, f.NADInformer(), udnClient, f.UserDefinedNetworkInformer(), renderNadStub(expectedNAD))
			Expect(c.Run()).To(Succeed())

			Eventually(func() []metav1.Condition {
				udn, err = udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				return udn.Status.Conditions
			}).ShouldNot(BeEmpty())
			Expect(normalizeConditions(udn.Status.Conditions)).To(Equal([]metav1.Condition{{
				Type:    "NetworkReady",
				Status:  "True",
				Reason:  "NetworkAttachmentDefinitionReady",
				Message: "NetworkAttachmentDefinition has been created",
			}}))

			actualNAD, err := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(actualNAD).To(Equal(expectedNAD))

			expectedErr := errors.New("update error")
			nadClient.PrependReactor("update", "network-attachment-definitions", func(action testing.Action) (bool, runtime.Object, error) {
				return true, nil, expectedErr
			})

			mutatedNAD := expectedNAD.DeepCopy()
			p := []byte(`[{"op":"replace","path":"/spec/config","value":"MUTATED"}]`)
			mutatedNAD, err = nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Patch(context.Background(), mutatedNAD.Name, types.JSONPatchType, p, metav1.PatchOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []metav1.Condition {
				udn, err = udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				return normalizeConditions(udn.Status.Conditions)
			}).Should(Equal([]metav1.Condition{{
				Type:    "NetworkReady",
				Status:  "False",
				Reason:  "SyncError",
				Message: "failed to update NetworkAttachmentDefinition: " + expectedErr.Error(),
			}}))

			Eventually(func() *netv1.NetworkAttachmentDefinition {
				updatedNAD, err := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				return updatedNAD
			}).Should(Equal(mutatedNAD))
		})
	})

	Context("UserDefinedNetwork object sync", func() {
		It("should fail when NAD owner-reference is malformed", func() {
			udn := testUDN()
			udn, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Create(context.Background(), udn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			nad := testNAD()
			c := New(nadClient, nadInformer, udnClient, udnInformer, renderNadStub(nad))

			mutetedNAD := nad.DeepCopy()
			mutetedNAD.ObjectMeta.OwnerReferences = []metav1.OwnerReference{{Kind: "DifferentKind"}}
			mutetedNAD, err = nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(udn.Namespace).Create(context.Background(), mutetedNAD, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = c.syncUserDefinedNetwork(udn, mutetedNAD)
			Expect(err).To(Equal(errors.New("foreign NetworkAttachmentDefinition with the desired name already exist [test/test]")))
		})
	})

	Context("UserDefinedNetwork status update", func() {
		DescribeTable("should update status, when",
			func(nad *netv1.NetworkAttachmentDefinition, syncErr error, expectedStatus *udnv1.UserDefinedNetworkStatus) {
				udn := testUDN()
				udn, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Create(context.Background(), udn, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				c := New(nadClient, nadInformer, udnClient, udnInformer, noopRenderNadStub())

				Expect(c.updateUserDefinedNetworkStatus(udn, nad, syncErr)).To(Succeed(), "should update status successfully")

				assertUserDefinedNetworkStatus(udnClient, udn, expectedStatus)
			},
			Entry("NAD exist",
				testNAD(),
				nil,
				&udnv1.UserDefinedNetworkStatus{
					Conditions: []metav1.Condition{
						{
							Type:    "NetworkReady",
							Status:  "True",
							Reason:  "NetworkAttachmentDefinitionReady",
							Message: "NetworkAttachmentDefinition has been created",
						},
					},
				},
			),
			Entry("NAD is being deleted",
				testNADWithDeletionTimestamp(time.Now()),
				nil,
				&udnv1.UserDefinedNetworkStatus{
					Conditions: []metav1.Condition{
						{
							Type:    "NetworkReady",
							Status:  "False",
							Reason:  "NetworkAttachmentDefinitionDeleted",
							Message: "NetworkAttachmentDefinition is being deleted",
						},
					},
				},
			),
			Entry("sync error occurred",
				testNAD(),
				errors.New("sync error"),
				&udnv1.UserDefinedNetworkStatus{
					Conditions: []metav1.Condition{
						{
							Type:    "NetworkReady",
							Status:  "False",
							Reason:  "SyncError",
							Message: "sync error",
						},
					},
				},
			),
		)

		It("should update status according to sync errors", func() {
			udn := testUDN()
			udn, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Create(context.Background(), udn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			c := New(nadClient, nadInformer, udnClient, udnInformer, noopRenderNadStub())

			nad := testNAD()
			syncErr := errors.New("sync error")
			Expect(c.updateUserDefinedNetworkStatus(udn, nad, syncErr)).To(Succeed(), "should update status successfully")

			expectedStatus := &udnv1.UserDefinedNetworkStatus{
				Conditions: []metav1.Condition{
					{
						Type:    "NetworkReady",
						Status:  "False",
						Reason:  "SyncError",
						Message: syncErr.Error(),
					},
				},
			}
			assertUserDefinedNetworkStatus(udnClient, udn, expectedStatus)

			anotherSyncErr := errors.New("another sync error")
			Expect(c.updateUserDefinedNetworkStatus(udn, nad, anotherSyncErr)).To(Succeed(), "should update status successfully")

			expectedUpdatedStatus := &udnv1.UserDefinedNetworkStatus{
				Conditions: []metav1.Condition{
					{
						Type:    "NetworkReady",
						Status:  "False",
						Reason:  "SyncError",
						Message: anotherSyncErr.Error(),
					},
				},
			}
			assertUserDefinedNetworkStatus(udnClient, udn, expectedUpdatedStatus)
		})

		It("should fail when client update status fails", func() {
			c := New(nadClient, nadInformer, udnClient, udnInformer, noopRenderNadStub())

			expectedError := errors.New("test err")
			udnClient.PrependReactor("patch", "userdefinednetworks/status", func(action testing.Action) (bool, runtime.Object, error) {
				return true, nil, expectedError
			})

			udn := testUDN()
			nad := testNAD()
			Expect(c.updateUserDefinedNetworkStatus(udn, nad, nil)).To(MatchError(expectedError))
		})
	})
})

func assertUserDefinedNetworkStatus(udnClient *udnfakeclient.Clientset, udn *udnv1.UserDefinedNetwork, expectedStatus *udnv1.UserDefinedNetworkStatus) {
	actualUDN, err := udnClient.K8sV1().UserDefinedNetworks(udn.Namespace).Get(context.Background(), udn.Name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	normalizeConditions(actualUDN.Status.Conditions)

	Expect(actualUDN.Status).To(Equal(*expectedStatus))
}

func normalizeConditions(conditions []metav1.Condition) []metav1.Condition {
	for i := range conditions {
		t := metav1.NewTime(time.Time{})
		conditions[i].LastTransitionTime = t
	}
	return conditions
}

func testUDN() *udnv1.UserDefinedNetwork {
	return &udnv1.UserDefinedNetwork{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "test",
			UID:       "1",
		},
	}
}

func testNAD() *netv1.NetworkAttachmentDefinition {
	return &netv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "test",
			Labels:    map[string]string{"k8s.ovn.org/user-defined-network": ""},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         udnv1.SchemeGroupVersion.String(),
					Kind:               "UserDefinedNetwork",
					Name:               "test",
					UID:                "1",
					BlockOwnerDeletion: pointer.Bool(true),
					Controller:         pointer.Bool(true),
				},
			},
		},
		Spec: netv1.NetworkAttachmentDefinitionSpec{},
	}
}

func testNADWithDeletionTimestamp(ts time.Time) *netv1.NetworkAttachmentDefinition {
	nad := testNAD()
	nad.DeletionTimestamp = &metav1.Time{Time: ts}
	return nad
}

func noopRenderNadStub() RenderNetAttachDefManifest {
	return newRenderNadStub(nil, nil)
}

func renderNadStub(nad *netv1.NetworkAttachmentDefinition) RenderNetAttachDefManifest {
	return newRenderNadStub(nad, nil)
}

func failRenderNadStub(err error) RenderNetAttachDefManifest {
	return newRenderNadStub(nil, err)
}

func newRenderNadStub(nad *netv1.NetworkAttachmentDefinition, err error) RenderNetAttachDefManifest {
	return func(udn *udnv1.UserDefinedNetwork) (*netv1.NetworkAttachmentDefinition, error) {
		return nad, err
	}
}
