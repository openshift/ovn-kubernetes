//go:build linux
// +build linux

package cni

import (
	"context"
	"fmt"

	"github.com/containernetworking/plugins/pkg/ns"
	configv1 "github.com/openshift/api/config/v1"

	"sigs.k8s.io/knftables"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

func doNFTablesRules(platformType string) error {
	nft, err := knftables.New(knftables.InetFamily, "openshift-block-output")
	if err != nil {
		return err
	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Table{})

	tx.Add(&knftables.Chain{
		Name: "block",
	})

	// Block MCS
	tx.Add(&knftables.Rule{
		Chain: "block",
		Rule: knftables.Concat(
			"tcp dport { 22623, 22624 } tcp flags syn / fin,syn,rst,ack",
			"reject",
		),
	})

	// Block cloud provider metadata IP except DNS
	metadataServiceIP := "169.254.169.254"
	if platformType == string(configv1.AlibabaCloudPlatformType) {
		metadataServiceIP = "100.100.100.200"
	}
	tx.Add(&knftables.Rule{
		Chain: "block",
		Rule: knftables.Concat(
			"ip daddr", metadataServiceIP,
			"udp dport != 53",
			"reject",
		),
	})
	tx.Add(&knftables.Rule{
		Chain: "block",
		Rule: knftables.Concat(
			"ip daddr", metadataServiceIP,
			"tcp dport != 53",
			"reject",
		),
	})

	tx.Add(&knftables.Chain{
		Name:     "output",
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.OutputHook),
		Priority: knftables.PtrTo(knftables.FilterPriority),
	})
	tx.Add(&knftables.Rule{
		Chain: "output",
		Rule:  "goto block",
	})

	tx.Add(&knftables.Chain{
		Name:     "forward",
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.ForwardHook),
		Priority: knftables.PtrTo(knftables.FilterPriority),
	})
	tx.Add(&knftables.Rule{
		Chain: "forward",
		Rule:  "goto block",
	})

	err = nft.Run(context.Background(), tx)
	if err != nil {
		return fmt.Errorf("could not set up pod nftables rules: %v", err)
	}
	return nil
}

// OCP HACK: block access to MCS/metadata; https://github.com/openshift/ovn-kubernetes/pull/19
func setupIPTablesBlocks(netns ns.NetNS) error {
	return netns.Do(func(_ ns.NetNS) error {
		return doNFTablesRules(config.Kubernetes.PlatformType)
	})
}

// END OCP HACK
