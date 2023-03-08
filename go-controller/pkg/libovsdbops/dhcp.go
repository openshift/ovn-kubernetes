package libovsdbops

import (
	"reflect"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

type dhcpOptionsPredicate func(*nbdb.DHCPOptions) bool

func CreateOrUpdateDhcpOptionsOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lsp *nbdb.LogicalSwitchPort, dhcpv4Options, dhcpv6Options *nbdb.DHCPOptions) ([]libovsdb.Operation, error) {
	opModels := []operationModel{}
	if dhcpv4Options != nil {
		opModels = append(opModels, operationModel{
			Model: dhcpv4Options,
			ModelPredicate: func(item *nbdb.DHCPOptions) bool {
				return item.Cidr == dhcpv4Options.Cidr && reflect.DeepEqual(item.ExternalIDs, dhcpv4Options.ExternalIDs)
			},
			OnModelUpdates: onModelUpdatesAllNonDefault(),
			DoAfter:        func() { lsp.Dhcpv4Options = &dhcpv4Options.UUID },
			ErrNotFound:    false,
			BulkOp:         false,
		})
	}
	if dhcpv6Options != nil {
		opModels = append(opModels, operationModel{
			Model: dhcpv6Options,
			ModelPredicate: func(item *nbdb.DHCPOptions) bool {
				return item.Cidr == dhcpv6Options.Cidr && reflect.DeepEqual(item.ExternalIDs, dhcpv6Options.ExternalIDs)
			},
			OnModelUpdates: onModelUpdatesAllNonDefault(),
			DoAfter:        func() { lsp.Dhcpv6Options = &dhcpv6Options.UUID },
			ErrNotFound:    false,
			BulkOp:         false,
		})
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

func CreateOrUpdateDhcpOptions(nbClient libovsdbclient.Client, lsp *nbdb.LogicalSwitchPort, dhcpv4Options, dhcpv6Options *nbdb.DHCPOptions) error {
	ops, err := CreateOrUpdateDhcpOptionsOps(nbClient, nil, lsp, dhcpv4Options, dhcpv6Options)
	if err != nil {
		return err
	}
	_, err = TransactAndCheck(nbClient, ops)
	return err
}

func DeleteDHCPOptionsWithPredicate(nbClient libovsdbclient.Client, p dhcpOptionsPredicate) error {
	opModel := operationModel{
		Model:          &nbdb.DHCPOptions{},
		ModelPredicate: p,
		ErrNotFound:    false,
		BulkOp:         true,
	}

	m := newModelClient(nbClient)
	return m.Delete(opModel)

}
