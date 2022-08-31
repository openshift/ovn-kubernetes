package libovsdbops

import (
	"context"
	"fmt"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/vswitchdb"
)

type InterfacePredicate func(*vswitchdb.Interface) bool

// FindInterfacesWithPredicate looks up Interfaces from the cache based on a
// given predicate
func FindInterfacesWithPredicate(vsClient libovsdbclient.Client, p InterfacePredicate) ([]*vswitchdb.Interface, error) {
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()
	found := []*vswitchdb.Interface{}
	err := vsClient.WhereCache(p).List(ctx, &found)
	return found, err
}

// FindInterfaceByName looks up an Interface from the cache by name
func FindInterfaceByName(vsClient libovsdbclient.Client, ifaceName string) (*vswitchdb.Interface, error) {
	found := []*vswitchdb.Interface{}
	opModel := operationModel{
		Model:          &vswitchdb.Interface{Name: ifaceName},
		ExistingResult: &found,
		ErrNotFound:    true,
		BulkOp:         false,
	}

	m := newModelClient(vsClient)
	if err := m.Lookup(opModel); err != nil {
		return nil, fmt.Errorf("error looking up Interface %q: %w", ifaceName, err)
	}

	return found[0], nil
}

// CreateOrUpdatePortAndAddToBridge creates or updates the provided Interface
// Interfae template, provided Port template, and adds the Port to the given bridge
func CreateOrUpdatePortAndAddToBridge(vsClient libovsdbclient.Client, bridgeUUID string, portTemplate *vswitchdb.Port, ifaceTemplate *vswitchdb.Interface) error {
	ifaceTemplate.Name = portTemplate.Name
	bridge := &vswitchdb.Bridge{
		UUID: bridgeUUID,
	}
	opModels := []operationModel{
		{
			Model:          ifaceTemplate,
			OnModelUpdates: onModelUpdatesNone(),
			DoAfter:        func() { portTemplate.Interfaces = append(portTemplate.Interfaces, ifaceTemplate.UUID) },
			ErrNotFound:    false,
			BulkOp:         false,
		},
		{
			Model:            portTemplate,
			OnModelMutations: []interface{}{&portTemplate.Interfaces},
			DoAfter:          func() { bridge.Ports = append(bridge.Ports, portTemplate.UUID) },
			ErrNotFound:      false,
			BulkOp:           false,
		},
		{
			Model:            bridge,
			OnModelMutations: []interface{}{&bridge.Ports},
			ErrNotFound:      true,
			BulkOp:           false,
		},
	}

	m := newModelClient(vsClient)
	_, err := m.CreateOrUpdate(opModels...)
	return err
}

// DeleteInterfacesIfaceID returns the ops to clear the iface-id ExternalID on the given Interfaces.
func DeleteInterfacesIfaceID(vsClient libovsdbclient.Client, interfaces ...*vswitchdb.Interface) error {
	opModels := make([]operationModel, 0, len(interfaces))
	delIfaceIDMap := map[string]string{
		"iface-id": "",
	}
	for i := range interfaces {
		iface := &vswitchdb.Interface{
			UUID: interfaces[i].UUID,
		}
		opModel := operationModel{
			Model:            iface,
			OnModelMutations: []interface{}{&delIfaceIDMap},
			ErrNotFound:      false,
			BulkOp:           false,
		}
		opModels = append(opModels, opModel)
	}

	m := newModelClient(vsClient)
	return m.Delete(opModels...)
}

// DeleteInterfacesOps returns the ops to delete the provided Interfaces.
func DeleteInterfacesOps(vsClient libovsdbclient.Client, ops []libovsdb.Operation, interfaces ...*vswitchdb.Interface) ([]libovsdb.Operation, error) {
	opModels := make([]operationModel, 0, len(interfaces))
	for i := range interfaces {
		// can't use i in the predicate, for loop replaces it in-memory
		iface := interfaces[i]
		opModel := operationModel{
			Model:       iface,
			ErrNotFound: false,
			BulkOp:      false,
		}
		opModels = append(opModels, opModel)
	}

	modelClient := newModelClient(vsClient)
	return modelClient.DeleteOps(ops, opModels...)
}

// FindBridgeByName finds a bridge by name
func FindBridgeByName(vsClient libovsdbclient.Client, bridgeName string) (*vswitchdb.Bridge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()
	found := []*vswitchdb.Bridge{}
	err := vsClient.WhereCache(func(item *vswitchdb.Bridge) bool {
		return item.Name == bridgeName
	}).List(ctx, &found)
	if err != nil {
		return nil, fmt.Errorf("failed to find bridge %q: %w", bridgeName, err)
	}
	if len(found) > 1 {
		return nil, fmt.Errorf("expected only one bridge %q", bridgeName)
	}

	return found[0], nil
}
