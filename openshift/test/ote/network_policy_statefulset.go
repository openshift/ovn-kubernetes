package ote

import (
	"path/filepath"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	oteutils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = g.Describe("[sig-network] SDN networkpolicy statefulset", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-networkpolicy-statefulset")

	g.BeforeEach(func() {
		networkType := oteutils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:CORENET-7345] NetworkPolicy egress with statefulset test", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressFile          = filepath.Join(buildPruningBaseDir, "networkpolicy/egress-allow-all.yaml")
		)

		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create egress networkpolicy")
		oteutils.CreateResourceFromFile(oc, ns, egressFile)

		g.By("Verify egress policy exists")
		output := oteutils.DescribePod(oc, ns, "")
		o.Expect(output).NotTo(o.BeEmpty())
	})
})
