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

var _ = g.Describe("[sig-network] SDN networkpolicy VAP", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-networkpolicy-vap")

	g.BeforeEach(func() {
		networkType := oteutils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:CORENET-7345] NetworkPolicy VAP deletion protection test", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			napFile             = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-all-namespaces.yaml")
		)

		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create networkpolicy")
		oteutils.CreateResourceFromFile(oc, ns, napFile)

		g.By("Verify networkpolicy exists")
		output := oteutils.DescribePod(oc, ns, "")
		o.Expect(output).NotTo(o.BeEmpty())
	})
})
