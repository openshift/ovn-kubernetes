package libovsdbops

import (
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

// BuildPortGroup builds a port group referencing the provided ports and ACLs
func BuildPortGroup(hashName, name string, ports []*nbdb.LogicalSwitchPort, acls []*nbdb.ACL) *nbdb.PortGroup {
	pg := nbdb.PortGroup{
		Name:        hashName,
		ExternalIDs: map[string]string{"name": name},
	}

	if len(acls) > 0 {
		pg.ACLs = make([]string, 0, len(acls))
		for _, acl := range acls {
			pg.ACLs = append(pg.ACLs, acl.UUID)
		}
	}

	if len(ports) > 0 {
		pg.Ports = make([]string, 0, len(ports))
		for _, port := range ports {
			pg.Ports = append(pg.Ports, port.UUID)
		}
	}

	return &pg
}

// CreateOrUpdatePortGroupsOps creates or updates the provided port groups
// returning the corresponding ops
func CreateOrUpdatePortGroupsOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, pgs ...*nbdb.PortGroup) ([]libovsdb.Operation, error) {
	opModels := make([]operationModel, 0, len(pgs))
	for i := range pgs {
		pg := pgs[i]
		opModel := operationModel{
			Model:          pg,
			OnModelUpdates: onModelUpdatesAll(),
			ErrNotFound:    false,
			BulkOp:         false,
		}
		opModels = append(opModels, opModel)
	}

	m := newModelClient(nbClient)
	return m.CreateOrUpdateOps(ops, opModels...)
}

// CreateOrUpdatePortGroups creates or updates the provided port groups
func CreateOrUpdatePortGroups(nbClient libovsdbclient.Client, pgs ...*nbdb.PortGroup) error {
	ops, err := CreateOrUpdatePortGroupsOps(nbClient, nil, pgs...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}

func AddPortsToPortGroupOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, name string, ports ...string) ([]libovsdb.Operation, error) {
	if len(ports) == 0 {
		return ops, nil
	}

	pg := nbdb.PortGroup{
		Name:  name,
		Ports: ports,
	}

	opModel := operationModel{
		Model:            &pg,
		OnModelMutations: []interface{}{&pg.Ports},
		ErrNotFound:      true,
		BulkOp:           false,
	}

	m := newModelClient(nbClient)
	return m.CreateOrUpdateOps(ops, opModel)
}

// AddPortsToPortGroup adds the provided ports to the provided port group
func AddPortsToPortGroup(nbClient libovsdbclient.Client, name string, ports ...string) error {
	ops, err := AddPortsToPortGroupOps(nbClient, nil, name, ports...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}

// DeletePortsFromPortGroupOps removes the provided ports from the provided port
// group and returns the corresponding ops
func DeletePortsFromPortGroupOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, name string, ports ...string) ([]libovsdb.Operation, error) {
	if len(ports) == 0 {
		return ops, nil
	}

	pg := nbdb.PortGroup{
		Name:  name,
		Ports: ports,
	}

	opModel := operationModel{
		Model:            &pg,
		OnModelMutations: []interface{}{&pg.Ports},
		ErrNotFound:      true,
		BulkOp:           false,
	}

	m := newModelClient(nbClient)
	return m.DeleteOps(ops, opModel)
}

// DeletePortsFromPortGroup removes the provided ports from the provided port
// group
func DeletePortsFromPortGroup(nbClient libovsdbclient.Client, name string, ports ...string) error {
	ops, err := DeletePortsFromPortGroupOps(nbClient, nil, name, ports...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}

// AddACLsToPortGroupOps adds the provided ACLs to the provided port group and
// returns the corresponding ops
func AddACLsToPortGroupOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, name string, acls ...*nbdb.ACL) ([]libovsdb.Operation, error) {
	if len(acls) == 0 {
		return ops, nil
	}

	pg := nbdb.PortGroup{
		Name: name,
		ACLs: make([]string, 0, len(acls)),
	}

	for _, acl := range acls {
		pg.ACLs = append(pg.ACLs, acl.UUID)
	}

	opModel := operationModel{
		Model:            &pg,
		OnModelMutations: []interface{}{&pg.ACLs},
		ErrNotFound:      true,
		BulkOp:           false,
	}

	m := newModelClient(nbClient)
	return m.CreateOrUpdateOps(ops, opModel)
}

// DeleteACLsFromPortGroupOps removes the provided ACLs from the provided port
// group and returns the corresponding ops
func DeleteACLsFromPortGroupOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, name string, acls ...*nbdb.ACL) ([]libovsdb.Operation, error) {
	if len(acls) == 0 {
		return ops, nil
	}

	pg := nbdb.PortGroup{
		Name: name,
		ACLs: make([]string, 0, len(acls)),
	}

	for _, acl := range acls {
		pg.ACLs = append(pg.ACLs, acl.UUID)
	}

	opModel := operationModel{
		Model:            &pg,
		OnModelMutations: []interface{}{&pg.ACLs},
		ErrNotFound:      true,
		BulkOp:           false,
	}

	m := newModelClient(nbClient)
	return m.DeleteOps(ops, opModel)
}

// DeletePortGroupsOps deletes the provided port groups and returns the
// corresponding ops
func DeletePortGroupsOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, names ...string) ([]libovsdb.Operation, error) {
	opModels := make([]operationModel, 0, len(names))
	for _, name := range names {
		pg := nbdb.PortGroup{
			Name: name,
		}
		opModel := operationModel{
			Model:       &pg,
			ErrNotFound: false,
			BulkOp:      false,
		}
		opModels = append(opModels, opModel)
	}

	m := newModelClient(nbClient)
	return m.DeleteOps(ops, opModels...)
}

// DeletePortGroups deletes the provided port groups and returns the
// corresponding ops
func DeletePortGroups(nbClient libovsdbclient.Client, names ...string) error {
	ops, err := DeletePortGroupsOps(nbClient, nil, names...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}
