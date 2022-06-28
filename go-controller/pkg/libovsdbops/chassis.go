package libovsdbops

import (
	"context"
	"fmt"
	"strings"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

// ListChassis looks up all chassis from the cache
func ListChassis(sbClient libovsdbclient.Client) ([]*sbdb.Chassis, error) {
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()
	searchedChassis := []*sbdb.Chassis{}
	err := sbClient.List(ctx, &searchedChassis)
	return searchedChassis, err
}

// ListChassisPrivate looks up all chassis private models from the cache
func ListChassisPrivate(sbClient libovsdbclient.Client) ([]*sbdb.ChassisPrivate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()
	found := []*sbdb.ChassisPrivate{}
	err := sbClient.List(ctx, &found)
	return found, err
}

// GetChassis looks up a chassis from the cache
func GetChassis(sbClient libovsdbclient.Client, chassis *sbdb.Chassis) (*sbdb.Chassis, error) {
	found := []*sbdb.Chassis{}
	opModel := operationModel{
		Model:          chassis,
		ModelPredicate: func(item *sbdb.Chassis) bool { return item.Name == chassis.Name },
		ExistingResult: &found,
		ErrNotFound:    true,
		BulkOp:         false,
	}

	m := newModelClient(sbClient)
	err := m.Lookup(opModel)
	if err != nil {
		return nil, err
	}

	return found[0], nil
}

// DeleteChassis deletes the provided chassis and associated private chassis
func DeleteChassis(sbClient libovsdbclient.Client, chassis ...*sbdb.Chassis) error {
	opModels := make([]operationModel, 0, len(chassis))
	for i := range chassis {
		foundChassis := []*sbdb.Chassis{}
		chassisPrivate := sbdb.ChassisPrivate{
			Name: chassis[i].Name,
		}
		chassisUUID := ""
		opModel := []operationModel{
			{
				Model:          chassis[i],
				ExistingResult: &foundChassis,
				ErrNotFound:    false,
				BulkOp:         false,
				DoAfter: func() {
					if len(foundChassis) > 0 {
						chassisPrivate.Name = foundChassis[0].Name
						chassisUUID = foundChassis[0].UUID
					}
				},
			},
			{
				Model:       &chassisPrivate,
				ErrNotFound: false,
				BulkOp:      false,
			},
			// IGMPGroup has a weak link to chassis, deleting multiple chassis may result in IGMP_Groups
			// with identical values on columns "address", "datapath", and "chassis", when "chassis" goes empty
			{
				Model: &sbdb.IGMPGroup{},
				ModelPredicate: func(group *sbdb.IGMPGroup) bool {
					return group.Chassis != nil && chassisUUID != "" && *group.Chassis == chassisUUID
				},
				ErrNotFound: false,
				BulkOp:      true,
			},
		}
		opModels = append(opModels, opModel...)
	}

	m := newModelClient(sbClient)
	err := m.Delete(opModels...)
	return err
}

type chassisPredicate func(*sbdb.Chassis) bool

// DeleteChassisWithPredicate looks up chassis from the cache based on a given
// predicate and deletes them as well as the associated private chassis
func DeleteChassisWithPredicate(sbClient libovsdbclient.Client, p chassisPredicate) error {
	foundChassis := []*sbdb.Chassis{}
	foundChassisNames := sets.NewString()
	foundChassisUUIDS := sets.NewString()
	opModels := []operationModel{
		{
			Model:          &sbdb.Chassis{},
			ModelPredicate: p,
			ExistingResult: &foundChassis,
			ErrNotFound:    false,
			BulkOp:         true,
			DoAfter: func() {
				for _, chassis := range foundChassis {
					foundChassisNames.Insert(chassis.Name)
					foundChassisUUIDS.Insert(chassis.UUID)
				}
			},
		},
		{
			Model:          &sbdb.ChassisPrivate{},
			ModelPredicate: func(item *sbdb.ChassisPrivate) bool { return foundChassisNames.Has(item.Name) },
			ErrNotFound:    false,
			BulkOp:         true,
		},
		// IGMPGroup has a weak link to chassis, deleting multiple chassis may result in IGMP_Groups
		// with identical values on columns "address", "datapath", and "chassis", when "chassis" goes empty
		{
			Model:          &sbdb.IGMPGroup{},
			ModelPredicate: func(group *sbdb.IGMPGroup) bool { return group.Chassis != nil && foundChassisUUIDS.Has(*group.Chassis) },
			ErrNotFound:    false,
			BulkOp:         true,
		},
	}
	m := newModelClient(sbClient)
	err := m.Delete(opModels...)
	return err
}

func CreateOrUpdateRemoteChassis(sbClient libovsdbclient.Client, hostname, name, ip string) error {
	chassis := &sbdb.Chassis{
		Hostname: hostname,
		Name:     name,
	}

	chassis, err := GetChassis(sbClient, chassis)
	if err == nil {
		if strings.ToLower(chassis.OtherConfig["is-remote"]) == "true" {
			// chassis already exists with is-remote set. Nothing to do.
			return nil
		}
	} else {
		chassis = &sbdb.Chassis{
			Hostname: hostname,
			Name:     name,
		}
	}

	options := map[string]string{
		"is-remote": "true",
	}
	chassis.ExternalIDs = options
	chassis.OtherConfig = options

	encap := &sbdb.Encap{
		Type:        "geneve",
		ChassisName: name,
		IP:          ip,
		Options:     map[string]string{"csum": "true"},
	}
	m := newModelClient(sbClient)
	opModels := []operationModel{
		{
			Model:          encap,
			ModelPredicate: func(item *sbdb.Encap) bool { return item.Type == encap.Type && item.IP == encap.IP },
			OnModelUpdates: []interface{}{
				&encap.Options,
			},
			DoAfter: func() {
				chassis.Encaps = []string{encap.UUID}
			},
		},
		{
			Model:          chassis,
			ModelPredicate: func(ch *sbdb.Chassis) bool { return ch.Name == name },
			OnModelUpdates: []interface{}{
				&chassis.ExternalIDs,
				&chassis.OtherConfig,
			},
			OnModelMutations: []interface{}{
				&chassis.Encaps,
			},
		},
	}

	if _, err := m.CreateOrUpdate(opModels...); err != nil {
		return err
	}
	return nil
}

func UpdateChassisToLocal(sbClient libovsdbclient.Client, hostname, name string) error {
	chassis := &sbdb.Chassis{
		Hostname: hostname,
		Name:     name,
	}
	chassis, err := GetChassis(sbClient, chassis)
	if err != nil {
		return fmt.Errorf("failed to get chassis id %s(%s), error: %v", name, hostname, err)
	}

	if chassis.ExternalIDs != nil {
		chassis.ExternalIDs["is-remote"] = "false"
	} else {
		chassis.ExternalIDs = map[string]string{
			"is-remote": "false",
		}
	}

	if chassis.OtherConfig != nil {
		chassis.OtherConfig["is-remote"] = "false"
	} else {
		chassis.OtherConfig = map[string]string{
			"is-remote": "false",
		}
	}

	opModel := operationModel{
		Model:          chassis,
		ModelPredicate: func(item *sbdb.Chassis) bool { return item.Name == chassis.Name },
		OnModelUpdates: onModelUpdatesAllNonDefault(),
		ErrNotFound:    false,
		BulkOp:         false,
	}

	m := newModelClient(sbClient)
	_, err = m.CreateOrUpdate(opModel)
	return err
}
