package node

import (
	. "github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"

	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
)

var fakeNodeName = "node"

type FakeOVNNode struct {
	node       *OvnNode
	watcher    *factory.WatchFactory
	stopChan   chan struct{}
	recorder   *record.FakeRecorder
	fakeClient *util.OVNClientset
	fakeExec   *ovntest.FakeExec
}

func NewFakeOVNNode(fexec *ovntest.FakeExec) *FakeOVNNode {
	err := util.SetExec(fexec)
	Expect(err).NotTo(HaveOccurred())

	return &FakeOVNNode{
		fakeExec: fexec,
		recorder: record.NewFakeRecorder(1),
	}
}

func (o *FakeOVNNode) start(ctx *cli.Context, objects ...runtime.Object) {
	v1Objects := []runtime.Object{}
	for _, object := range objects {
		v1Objects = append(v1Objects, object)
	}
	_, err := config.InitConfig(ctx, o.fakeExec, nil)
	Expect(err).NotTo(HaveOccurred())

	o.fakeClient = &util.OVNClientset{
		KubeClient:          fake.NewSimpleClientset(v1Objects...),
		EgressIPClient:      egressipfake.NewSimpleClientset(),
		APIExtensionsClient: apiextensionsfake.NewSimpleClientset(),
	}
	o.init()
}

func (o *FakeOVNNode) restart() {
	o.shutdown()
	o.init()
}

func (o *FakeOVNNode) shutdown() {
	close(o.stopChan)
}

func (o *FakeOVNNode) init() {
	var err error

	o.stopChan = make(chan struct{})

	o.watcher, err = factory.NewWatchFactory(o.fakeClient)
	Expect(err).NotTo(HaveOccurred())

	o.node = NewNode(o.fakeClient.KubeClient, o.watcher, fakeNodeName, o.stopChan, o.recorder)
}
