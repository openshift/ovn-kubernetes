package libovsdbops

import (
	"context"
	"fmt"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

// ListChassis returns all the logical chassis
func ListChassis(sbClient libovsdbclient.Client) ([]sbdb.Chassis, error) {
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()
	searchedChassis := []sbdb.Chassis{}
	err := sbClient.List(ctx, &searchedChassis)
	if err != nil {
		return nil, fmt.Errorf("failed listing chassis err: %v", err)
	}

	return searchedChassis, nil
}

// ListChassisPrivate looks up all chassis private models from the cache
func ListChassisPrivate(sbClient libovsdbclient.Client) ([]sbdb.ChassisPrivate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()
	found := []sbdb.ChassisPrivate{}
	err := sbClient.List(ctx, &found)
	return found, err
}

// DeleteChassis deletes the provided chassis and associated private chassis
func DeleteChassis(sbClient libovsdbclient.Client, chassis ...*sbdb.Chassis) error {
	opModels := make([]OperationModel, 0, len(chassis))
	for i := range chassis {
		foundChassis := []sbdb.Chassis{}
		chassisPrivate := sbdb.ChassisPrivate{
			Name: chassis[i].Name,
		}
		opModel := []OperationModel{
			{
				Model:          chassis[i],
				ExistingResult: &foundChassis,
				ErrNotFound:    false,
				BulkOp:         false,
				DoAfter: func() {
					if len(foundChassis) > 0 {
						chassisPrivate.Name = foundChassis[0].Name
					}
				},
			},
			{
				Model:       &chassisPrivate,
				ErrNotFound: false,
				BulkOp:      false,
			},
		}
		opModels = append(opModels, opModel...)
	}

	m := NewModelClient(sbClient)
	if err := m.Delete(opModels...); err != nil {
		return err
	}
	return nil
}

type chassisPredicate func(*sbdb.Chassis) bool

// DeleteChassisWithPredicate looks up chassis from the cache based on a given
// predicate and deletes them as well as the associated private chassis
func DeleteChassisWithPredicate(sbClient libovsdbclient.Client, p chassisPredicate) error {
	foundChassis := []sbdb.Chassis{}
	foundChassisNames := sets.NewString()
	opModels := []OperationModel{
		{
			Model:          &sbdb.Chassis{},
			ModelPredicate: p,
			ExistingResult: &foundChassis,
			ErrNotFound:    false,
			BulkOp:         true,
			DoAfter: func() {
				for _, chassis := range foundChassis {
					foundChassisNames.Insert(chassis.Name)
				}
			},
		},
		{
			Model:          &sbdb.ChassisPrivate{},
			ModelPredicate: func(item *sbdb.ChassisPrivate) bool { return foundChassisNames.Has(item.Name) },
			ErrNotFound:    false,
			BulkOp:         true,
		},
	}
	m := NewModelClient(sbClient)
	err := m.Delete(opModels...)
	return err
}
