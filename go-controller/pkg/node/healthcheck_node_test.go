package node

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

var ovnkNodePodName string = "ovnkube-node-test"

func newFakeOvnkNodePod(deletionTimestamp *metav1.Time) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              ovnkNodePodName,
			UID:               types.UID(ovnkNodePodName),
			Namespace:         config.Kubernetes.OVNConfigNamespace,
			DeletionTimestamp: deletionTimestamp,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "ovnkube-node",
					Image: "ovnkube-image",
				},
			},
			NodeName: "node1",
		},
	}
}

func startWithObjects(objects ...runtime.Object) *fake.Clientset {
	v1Objects := []runtime.Object{}
	for _, object := range objects {
		v1Objects = append(v1Objects, object)
	}
	return fake.NewSimpleClientset(v1Objects...)
}

func checkResponse(address string, expectedStatusCode int) {
	// Try a few times to make sure the server is listening,
	// there's a small race between when Start() returns and
	// the ListenAndServe() is actually active
	var err error
	for i := 0; i < 5; i++ {
		resp, err := http.Get(fmt.Sprintf("http://%s/healthz", address))
		if err == nil {
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(expectedStatusCode))
		}
		time.Sleep(50 * time.Millisecond)
	}
	Expect(err).NotTo(HaveOccurred())
}

var _ = Describe("Node healthcheck tests", func() {
	var (
		wg     *sync.WaitGroup
		stopCh chan struct{}
	)

	BeforeEach(func() {
		stopCh = make(chan struct{})
		wg = &sync.WaitGroup{}
		os.Setenv("POD_NAME", ovnkNodePodName)
	})

	AfterEach(func() {
		close(stopCh)
		wg.Wait()
	})

	Context("node proxy healthz server is started", func() {
		It("it reports healthy", func() {
			recorder := record.NewFakeRecorder(10)
			const addr string = "127.0.0.1:10256"

			fakeClient := startWithObjects(
				&v1.PodList{
					Items: []v1.Pod{
						*newFakeOvnkNodePod(nil),
					},
				})

			hzs := newNodeProxyHealthzServer("some-node", addr, recorder, fakeClient)
			hzs.Start(stopCh, wg)

			checkResponse(addr, http.StatusOK)
		})

		It("it reports unhealthy", func() {
			// ovnk node pod is set for deletion: healthz should report unhealthy
			recorder := record.NewFakeRecorder(10)
			const addr string = "127.0.0.1:10256"
			now := metav1.Now()
			fakeClient := startWithObjects(
				&v1.PodList{
					Items: []v1.Pod{
						*newFakeOvnkNodePod(&now),
					},
				})

			hzs := newNodeProxyHealthzServer("some-node", addr, recorder, fakeClient)
			hzs.Start(stopCh, wg)

			checkResponse(addr, http.StatusServiceUnavailable)
		})

	})
})
