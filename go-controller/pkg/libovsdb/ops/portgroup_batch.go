package ops

import (
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/nbdb"
)

// AddPortsToPortGroupBatchOps returns operations to add multiple ports to a port group
// in a single mutation operation, reducing OVN database overhead.
func AddPortsToPortGroupBatchOps(nbClient libovsdbclient.Client, ops []ovsdb.Operation,
	pgName string, portUUIDs ...string) ([]ovsdb.Operation, error) {

	if len(portUUIDs) == 0 {
		return ops, nil
	}

	pg := &nbdb.PortGroup{Name: pgName}

	mutateOps, err := nbClient.WhereCache(
		func(item *nbdb.PortGroup) bool {
			return item.Name == pgName
		}).Mutate(pg, nbdb.PortGroupMutation{
		Ports: portUUIDs,
		Op:    ovsdb.MutateOperationInsert,
	})

	if err != nil {
		return nil, err
	}

	return append(ops, mutateOps...), nil
}
