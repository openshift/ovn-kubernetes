//go:build linux
// +build linux

package nftables

import (
	"context"
	"fmt"

	"sigs.k8s.io/knftables"
)

// OCP HACK: OpenShift-specific (downstream-only) nftables rules — eg the MCS-blocking
// rules set up by pkg/node/OCP_HACKS.go — live in their own "openshift-ovn-kubernetes"
// table rather than the shared "ovn-kubernetes" table. Keeping them separate means they
// don't show up in the table dumps checked by upstream unit tests, so we don't have to
// carry downstream patches to those tests (which would otherwise cause repeated merge
// conflicts on every downstream merge). See the review discussion on
// https://github.com/openshift/ovn-kubernetes/pull/3383

// OpenShiftNFTablesName is the name of the nftables table used for OpenShift-specific
// (downstream-only) rules.
const OpenShiftNFTablesName = "openshift-ovn-kubernetes"

var (
	ocpNFTHelper     knftables.Interface
	ocpNFTHelperBase knftables.Interface
)

// GetOpenShiftNFTablesHelper returns a knftables.Interface for the OpenShift-specific
// "openshift-ovn-kubernetes" table. In unit tests, when GetNFTablesHelper has been faked,
// this returns a matching fake interface; otherwise it creates a real one.
func GetOpenShiftNFTablesHelper() (knftables.Interface, error) {
	base, err := GetNFTablesHelper()
	if err != nil {
		return nil, err
	}
	if ocpNFTHelper != nil && ocpNFTHelperBase == base {
		return ocpNFTHelper, nil
	}

	var nft knftables.Interface
	if _, ok := base.(*knftables.Fake); ok {
		nft = knftables.NewFake(knftables.InetFamily, OpenShiftNFTablesName)
	} else {
		nft, err = knftables.New(knftables.InetFamily, OpenShiftNFTablesName)
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenShift nftables helper: %w", err)
		}
	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Table{})
	if err := nft.Run(context.TODO(), tx); err != nil {
		return nil, fmt.Errorf("failed to initialize OpenShift nftables table: %w", err)
	}

	ocpNFTHelperBase = base
	ocpNFTHelper = nft
	return ocpNFTHelper, nil
}

// END OCP HACK
