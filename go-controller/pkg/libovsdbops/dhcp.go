package libovsdbops

import (
	"context"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

type DHCPOptionsPredicate func(*nbdb.DHCPOptions) bool

type DHCPConfig struct {
	Options   *nbdb.DHCPOptions
	Predicate DHCPOptionsPredicate
}

type DHCPConfigs struct {
	V4 *DHCPConfig
	V6 *DHCPConfig
}

// CreateOrUpdateDhcpOptionsOps will configure logical switch port DHCPv4Options and DHCPv6Options fields with
// options at dhcpv4Options and dhcpv6Options arguments and create/update DHCPOptions objects that matches the
// pv4 and pv6 predicates. The DHCP options not provided will be reset to nil the LSP fields.
func CreateOrUpdateDhcpOptionsOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lsp *nbdb.LogicalSwitchPort, dhcpConfigs *DHCPConfigs) ([]libovsdb.Operation, error) {
	opModels := []operationModel{}
	if dhcpConfigs.V4 != nil {
		opModel := operationModel{
			Model:          dhcpConfigs.V4.Options,
			OnModelUpdates: onModelUpdatesAllNonDefault(),
			DoAfter:        func() { lsp.Dhcpv4Options = &dhcpConfigs.V4.Options.UUID },
			ErrNotFound:    false,
			BulkOp:         false,
		}
		if dhcpConfigs.V4.Predicate != nil {
			opModel.ModelPredicate = dhcpConfigs.V4.Predicate
		}
		opModels = append(opModels, opModel)
	}
	if dhcpConfigs.V6 != nil {
		opModel := operationModel{
			Model:          dhcpConfigs.V6.Options,
			OnModelUpdates: onModelUpdatesAllNonDefault(),
			DoAfter:        func() { lsp.Dhcpv6Options = &dhcpConfigs.V6.Options.UUID },
			ErrNotFound:    false,
			BulkOp:         false,
		}
		if dhcpConfigs.V6.Predicate != nil {
			opModel.ModelPredicate = dhcpConfigs.V6.Predicate
		}
		opModels = append(opModels, opModel)
	}
	opModels = append(opModels, operationModel{
		Model: lsp,
		OnModelUpdates: []interface{}{
			&lsp.Dhcpv4Options,
			&lsp.Dhcpv6Options,
		},
		ErrNotFound: true,
		BulkOp:      false,
	})

	m := newModelClient(nbClient)
	return m.CreateOrUpdateOps(ops, opModels...)
}

func CreateOrUpdateDhcpOptions(nbClient libovsdbclient.Client, lsp *nbdb.LogicalSwitchPort, dhcpConfigs *DHCPConfigs) error {
	ops, err := CreateOrUpdateDhcpOptionsOps(nbClient, nil, lsp, dhcpConfigs)
	if err != nil {
		return err
	}
	_, err = TransactAndCheck(nbClient, ops)
	return err
}

func findDHCPOptionsWithPredicate(nbClient libovsdbclient.Client, p DHCPOptionsPredicate) ([]*nbdb.DHCPOptions, error) {
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()
	dhcpOptions := []*nbdb.DHCPOptions{}
	err := nbClient.WhereCache(p).List(ctx, &dhcpOptions)
	return dhcpOptions, err
}

func DeleteDHCPOptionsWithPredicate(nbClient libovsdbclient.Client, p DHCPOptionsPredicate) error {
	dhcpOptionList, err := findDHCPOptionsWithPredicate(nbClient, p)
	if err != nil {
		return err
	}
	opModels := []operationModel{}
	for _, dhcpOptions := range dhcpOptionList {
		opModel := operationModel{
			Model:       dhcpOptions,
			ErrNotFound: false,
			BulkOp:      false,
		}
		opModels = append(opModels, opModel)
	}
	m := newModelClient(nbClient)
	return m.Delete(opModels...)

}
