package util

import (
	"fmt"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
)

// DeleteSbdbMacBindingsWithIPs deletes mac bindings from the SBDB on any of the
// provided IPs. This method should only be used to remove legacy entries, as
// static mac bindings should be created in NBDB instead.
func DeleteSbdbMacBindingsWithIPs(sbClient libovsdbclient.Client, ips ...string) error {
	mb := &sbdb.MACBinding{}
	conditions := make([]model.Condition, len(ips))
	for i := range ips {
		conditions = append(conditions,
			model.Condition{
				Field:    &mb.IP,
				Function: ovsdb.ConditionEqual,
				Value:    ips[i],
			},
		)
	}

	// Delete using the client native API instead of model client to avoid
	// having to monitor & cache the SBDB mac binding table.
	// This will encode the conditions as provided and send them to the server
	// if there is no cache. The operation is idempotent and there is no error
	// if there was nothing to delete.
	ops, err := sbClient.WhereAny(mb, conditions...).Delete()
	if err != nil {
		return fmt.Errorf("failed to delete SBDB mac binding while generating ops: %v", err)
	}

	_, err = libovsdbops.TransactAndCheck(sbClient, ops)
	if err != nil {
		return fmt.Errorf("failed to delete SBDB mac binding while transacting ops: %v", err)
	}

	return nil
}
