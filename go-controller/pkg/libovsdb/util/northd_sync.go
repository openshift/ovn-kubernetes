package util

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

// WaitUntilFlowsInstalled ensures that all ovn-controllers have sync'd at least once by increments nb_cfg value in NB DB
// and waiting for northd to write back a value equal or greater to the hv_cfg field.
// See https://www.ovn.org/support/dist-docs/ovn-nb.5.html for more info regarding nb_cfg / hv_cfg fields.
// The expectation is that the data you wish to be sync'd and installed by all ovn-controllers has already been written to NB DB.
// Note: if any ovn-controllers are down, this will block until they come back up, therefore this func should only
// be used in IC mode and one node per zone.
func WaitUntilFlowsInstalled(ctx context.Context, nbClient client.Client) error {
	// 1. Get value of nb_cfg
	// 2. Increment value of nb_cfg
	// 3. Wait until value appears in hv_cfg field thus ensuring all ovn-controllers have processed the changes.
	nbGlobal := &nbdb.NBGlobal{}
	nbGlobal, err := libovsdbops.GetNBGlobal(nbClient, nbGlobal)
	if err != nil {
		return fmt.Errorf("failed to find OVN Northbound NB_Global table"+
			" entry: %w", err)
	}
	// increment nb_cfg value by 1. When northd consumes updates from NB DB, it will copy this value to SB DBs SB_Global
	// table nb_cfg field.
	ops, err := nbClient.Where(nbGlobal).Mutate(nbGlobal, model.Mutation{
		Field:   &nbGlobal.NbCfg,
		Mutator: ovsdb.MutateOperationAdd,
		Value:   1,
	})
	if err != nil {
		return fmt.Errorf("failed to generate ops to mutate nb_cfg: %w", err)
	}
	if _, err = libovsdbops.TransactAndCheck(nbClient, ops); err != nil {
		return fmt.Errorf("failed to transact to increment nb_cfg: %w", err)
	}
	expectedNbCfgValue := nbGlobal.NbCfg + 1
	if expectedNbCfgValue < 0 { // handle overflow
		expectedNbCfgValue = 0
	}
	nbGlobal = &nbdb.NBGlobal{}
	// ovn-northd sets hv_cfg to the smallest sequence number of all the chassis in the system,
	// as reported in the Chassis_Private table in the southbound database. Thus, hv_cfg
	// equals nb_cfg if all chassis are caught up with NB DB.
	// poll until we see the expected value in NB DB every 5 milliseconds until context is cancelled.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*5, true, func(_ context.Context) (done bool, err error) {
		if nbGlobal, err = libovsdbops.GetNBGlobal(nbClient, nbGlobal); err != nil {
			// northd hasn't added an entry yet
			if errors.Is(err, client.ErrNotFound) {
				return false, nil
			}
			return false, fmt.Errorf("failed to get nb_global table entry from NB DB: %w", err)
		}
		return nbGlobal.HvCfg >= expectedNbCfgValue, nil // we only need to ensure it is greater than or equal to the expected value
	})
	if err != nil {
		return fmt.Errorf("failed while waiting for hv_cfg value greater than or equal %d in NB DB nb_global table: %w",
			expectedNbCfgValue, err)
	}
	return nil
}
