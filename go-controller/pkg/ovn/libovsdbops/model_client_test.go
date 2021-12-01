package libovsdbops

import (
	"fmt"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
)

var (
	adressSetTestName         = "test"
	adressSetTestUUID         = "test-uuid"
	adressSetTestAdress       = "test-adress"
	portGroupTestName         = "test-port-group"
	portGroupTestUUID         = "test-port-group-uuid"
	aclTestUUID               = "test-acl-uuid"
	logicalSwitchTestName     = "test-switch"
	logicalSwitchTestUUID     = "test-switch-uuid"
	logicalSwitchPortTestName = "test-switch-port"
	logicalSwitchPortTestUUID = "test-switch-port-uuid"
	logicalSwitchPortAddress  = "test-switch-port-address"
)

type OperationModelTestCase struct {
	name                     string
	generateCreateOrUpdateOp func() []OperationModel
	initialDB                []libovsdbtest.TestData
	expectedDB               []libovsdbtest.TestData
}

func runTestCase(t *testing.T, tCase OperationModelTestCase, shouldDelete bool) error {
	dbSetup := libovsdbtest.TestSetup{
		NBData: tCase.initialDB,
	}

	nbClient, cleanup, err := libovsdbtest.NewNBTestHarness(dbSetup, nil)
	if err != nil {
		return err
	}
	t.Cleanup(cleanup.Cleanup)

	modelClient := NewModelClient(nbClient)

	opModel := tCase.generateCreateOrUpdateOp()

	if shouldDelete {
		err := modelClient.Delete(opModel...)
		if err != nil {
			return fmt.Errorf("test: \"%s\" couldn't generate the Delete operations, err: %v", tCase.name, err)
		}
	} else {
		_, err := modelClient.CreateOrUpdate(opModel...)
		if err != nil {
			return fmt.Errorf("test: \"%s\" couldn't generate the CreateOrUpdate operations, err: %v", tCase.name, err)
		}
	}

	matcher := libovsdbtest.HaveData(tCase.expectedDB)
	success, err := matcher.Match(nbClient)
	if !success {
		return fmt.Errorf("test: \"%s\" didn't match expected with actual, err: %s", tCase.name, matcher.FailureMessage(nbClient))
	}
	if err != nil {
		return fmt.Errorf("test: \"%s\" encountered error: %v", tCase.name, err)
	}

	return nil
}

// This test uses an AddressSet for its assertion, mainly because AddressSet
// is specified as root and indexed by name in the OVN NB schema, which can
// evaluate all test cases correctly without having to specify a UUID.
func TestCreateOrUpdateForRootObjects(t *testing.T) {
	tt := []OperationModelTestCase{
		{
			"Test create non-existing item by model predicate specification",
			func() []OperationModel {
				return []OperationModel{
					{
						Model: &nbdb.AddressSet{
							Name: adressSetTestName,
						},
						ModelPredicate: func(a *nbdb.AddressSet) bool { return a.Name == adressSetTestName },
					},
				}
			},
			[]libovsdbtest.TestData{},
			[]libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name: adressSetTestName,
					UUID: adressSetTestUUID,
				},
			},
		},
		{
			"Test create non-existing item by model",
			func() []OperationModel {
				return []OperationModel{
					{
						Model: &nbdb.AddressSet{
							Name: adressSetTestName,
						},
					},
				}
			},
			[]libovsdbtest.TestData{},
			[]libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name: adressSetTestName,
					UUID: adressSetTestUUID,
				},
			},
		},
		{
			"Test update existing item by model predicate specification",
			func() []OperationModel {
				model := nbdb.AddressSet{
					Name:      adressSetTestName,
					Addresses: []string{adressSetTestAdress},
				}
				return []OperationModel{
					{
						Model:          &model,
						ModelPredicate: func(a *nbdb.AddressSet) bool { return a.Name == adressSetTestName },
						OnModelUpdates: []interface{}{
							&model.Addresses,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name: adressSetTestName,
					UUID: adressSetTestUUID,
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name:      adressSetTestName,
					UUID:      adressSetTestUUID,
					Addresses: []string{adressSetTestAdress},
				},
			},
		},
		{
			"Test update existing item by model",
			func() []OperationModel {
				model := nbdb.AddressSet{
					Name:      adressSetTestName,
					Addresses: []string{adressSetTestAdress},
				}
				return []OperationModel{
					{
						Model: &model,
						OnModelUpdates: []interface{}{
							&model.Addresses,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name: adressSetTestName,
					UUID: adressSetTestUUID,
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name:      adressSetTestName,
					UUID:      adressSetTestUUID,
					Addresses: []string{adressSetTestAdress},
				},
			},
		},
		{
			"Test create/update of non-existing item by model",
			func() []OperationModel {
				model := nbdb.AddressSet{
					Name:      adressSetTestName,
					Addresses: []string{adressSetTestAdress},
				}
				return []OperationModel{
					{
						Model: &model,
						OnModelUpdates: []interface{}{
							&model.Addresses,
						},
					},
				}
			},
			[]libovsdbtest.TestData{},
			[]libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name:      adressSetTestName,
					UUID:      adressSetTestUUID,
					Addresses: []string{adressSetTestAdress},
				},
			},
		},
	}

	for _, tCase := range tt {
		if err := runTestCase(t, tCase, false); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeleteForRootObjects(t *testing.T) {
	tt := []OperationModelTestCase{
		{
			"Test delete non-existing item by model predicate specification",
			func() []OperationModel {
				return []OperationModel{
					{
						Model: &nbdb.AddressSet{
							Name: adressSetTestName,
						},
						ModelPredicate: func(a *nbdb.AddressSet) bool { return a.Name == adressSetTestName },
					},
				}
			},
			[]libovsdbtest.TestData{},
			[]libovsdbtest.TestData{},
		},
		{
			"Test delete non-existing item by model specification",
			func() []OperationModel {
				return []OperationModel{
					{
						Model: &nbdb.AddressSet{
							Name: adressSetTestName,
						},
					},
				}
			},
			[]libovsdbtest.TestData{},
			[]libovsdbtest.TestData{},
		},
		{
			"Test delete existing item by model predicate specification",
			func() []OperationModel {
				return []OperationModel{
					{
						Model: &nbdb.AddressSet{
							Name: adressSetTestName,
						},
						ModelPredicate: func(a *nbdb.AddressSet) bool { return a.Name == adressSetTestName },
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name: adressSetTestName,
				},
			},
			[]libovsdbtest.TestData{},
		},
		{
			"Test delete existing item by model specification",
			func() []OperationModel {
				return []OperationModel{
					{
						Model: &nbdb.AddressSet{
							Name: adressSetTestName,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.AddressSet{
					Name: adressSetTestName,
				},
			},
			[]libovsdbtest.TestData{},
		},
	}

	for _, tCase := range tt {
		if err := runTestCase(t, tCase, true); err != nil {
			t.Fatal(err)
		}
	}
}

// This test uses a LogicalSwitch and LogicalSwitchPort for its assertion,
// mainly because LogicalSwitchPort is specified as non-root, indexed by name
// and referenced by LogicalSwitch in the OVN NB schema, which can evaluate all
// test cases correctly.
func TestCreateOrUpdateForNonRootObjects(t *testing.T) {
	tt := []OperationModelTestCase{
		{
			"Test create non-existing no-root by model predicate specification and parent model mutation",
			func() []OperationModel {
				m := nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
				}
				parentModel := nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
				}
				return []OperationModel{
					{
						Model:          &m,
						ModelPredicate: func(lsp *nbdb.LogicalSwitchPort) bool { return lsp.Name == logicalSwitchPortTestName },
						DoAfter: func() {
							parentModel.Ports = []string{m.UUID}
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
					UUID: logicalSwitchTestUUID,
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
			},
		},
		{
			"Test create non-existing no-root by model predicate specification and non-existing parent model mutation",
			func() []OperationModel {
				m := nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
				}
				parentModel := nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
				}
				return []OperationModel{
					{
						Model:          &m,
						ModelPredicate: func(lsp *nbdb.LogicalSwitchPort) bool { return lsp.Name == logicalSwitchPortTestName },
						DoAfter: func() {
							parentModel.Ports = []string{m.UUID}
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
			},
		},
		{
			"Test create non-existing no-root by model predicate specification and parent model update",
			func() []OperationModel {
				parentModel := nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					Ports: []string{logicalSwitchPortTestUUID},
				}
				return []OperationModel{
					{
						Model: &nbdb.LogicalSwitchPort{
							Name: logicalSwitchPortTestName,
						},
						ModelPredicate: func(lsp *nbdb.LogicalSwitchPort) bool { return lsp.Name == logicalSwitchPortTestName },
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelUpdates: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
					UUID: logicalSwitchTestUUID,
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
			},
		},
		{
			"Test create non-existing no-root by model and parent model mutate",
			func() []OperationModel {
				m := nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
				}
				parentModel := nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
				}
				return []OperationModel{
					{
						Model: &m,
						DoAfter: func() {
							parentModel.Ports = []string{m.UUID}
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
					UUID: logicalSwitchTestUUID,
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
			},
		},
		{
			"Test create non-existing no-root by model and parent model update",
			func() []OperationModel {
				parentModel := nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					Ports: []string{logicalSwitchPortTestUUID},
				}
				return []OperationModel{
					{
						Model: &nbdb.LogicalSwitchPort{
							Name: logicalSwitchPortTestName,
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelUpdates: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
					UUID: logicalSwitchTestUUID,
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
			},
		},
		{
			"Test update existing no-root by model update and parent model update",
			func() []OperationModel {
				model := nbdb.LogicalSwitchPort{
					Name:      logicalSwitchPortTestName,
					Addresses: []string{logicalSwitchPortAddress},
				}
				parentModel := nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					Ports: []string{logicalSwitchPortTestUUID},
				}
				return []OperationModel{
					{
						Model: &model,
						OnModelUpdates: []interface{}{
							&model.Addresses,
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelUpdates: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name:      logicalSwitchPortTestName,
					UUID:      logicalSwitchPortTestUUID,
					Addresses: []string{logicalSwitchPortAddress},
				},
			},
		},
		{
			"Test update existing no-root by model mutation and parent model update",
			func() []OperationModel {
				m := nbdb.LogicalSwitchPort{
					Name:      logicalSwitchPortTestName,
					Addresses: []string{logicalSwitchPortAddress},
				}
				pm := nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					Ports: []string{logicalSwitchPortTestUUID},
				}
				return []OperationModel{
					{
						Model: &m,
						OnModelMutations: []interface{}{
							&m.Addresses,
						},
					},
					{
						Model:          &pm,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelUpdates: []interface{}{
							&pm.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name:      logicalSwitchPortTestName,
					UUID:      logicalSwitchPortTestUUID,
					Addresses: []string{logicalSwitchPortAddress},
				},
			},
		},
		{
			"Test update non-existing no-root by model mutation and parent model mutation",
			func() []OperationModel {
				m := nbdb.LogicalSwitchPort{
					Name:      logicalSwitchPortTestName,
					Addresses: []string{logicalSwitchPortAddress},
				}
				pm := nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
				}
				return []OperationModel{
					{
						Model: &m,
						OnModelMutations: []interface{}{
							&m.Addresses,
						},
						DoAfter: func() {
							pm.Ports = []string{m.UUID}
						},
					},
					{
						Model:          &pm,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&pm.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
					UUID: logicalSwitchTestUUID,
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name:      logicalSwitchPortTestName,
					UUID:      logicalSwitchPortTestUUID,
					Addresses: []string{logicalSwitchPortAddress},
				},
			},
		},
		{
			"Test update existing no-root by model specification and parent model mutation without specifying direct ID",
			func() []OperationModel {
				m := nbdb.LogicalSwitchPort{
					Name:      logicalSwitchPortTestName,
					Addresses: []string{logicalSwitchPortAddress},
				}
				parentModel := nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
				}
				return []OperationModel{
					{
						Model: &m,
						OnModelUpdates: []interface{}{
							&m.Addresses,
						},
						DoAfter: func() {
							parentModel.Ports = []string{m.UUID}
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name:      logicalSwitchPortTestName,
					UUID:      logicalSwitchPortTestUUID,
					Addresses: []string{logicalSwitchPortAddress},
				},
			},
		},
		{
			"Test no update of existing non-root object by model specification and parent model mutation without specifying direct ID",
			func() []OperationModel {
				m := nbdb.LogicalSwitchPort{
					Name:      logicalSwitchPortTestName,
					Addresses: []string{logicalSwitchPortAddress},
				}
				parentModel := nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
				}
				return []OperationModel{
					{
						Model: &m,
						DoAfter: func() {
							parentModel.Ports = []string{m.UUID}
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
			},
		},
	}

	for _, tCase := range tt {
		if err := runTestCase(t, tCase, false); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeleteForNonRootObjects(t *testing.T) {
	tt := []OperationModelTestCase{
		{
			"Test delete non-existing no-root by model predicate specification and parent model mutation",
			func() []OperationModel {
				parentModel := nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					Ports: []string{logicalSwitchPortTestUUID},
				}
				return []OperationModel{
					{
						Model: &nbdb.LogicalSwitchPort{
							Name: logicalSwitchPortTestName,
						},
						ModelPredicate: func(lsp *nbdb.LogicalSwitchPort) bool { return lsp.Name == logicalSwitchPortTestName },
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
					UUID: logicalSwitchTestUUID,
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
					UUID: logicalSwitchTestUUID,
				},
			},
		},
		{
			"Test delete existing no-root by model predicate specification and parent model mutation",
			func() []OperationModel {
				parentModel := nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
				}
				logicalSwitchPortRes := []nbdb.LogicalSwitchPort{}
				return []OperationModel{
					{
						ModelPredicate: func(lsp *nbdb.LogicalSwitchPort) bool { return lsp.Name == logicalSwitchPortTestName },
						ExistingResult: &logicalSwitchPortRes,
						DoAfter: func() {
							parentModel.Ports = ExtractUUIDsFromModels(&logicalSwitchPortRes)
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
					UUID: logicalSwitchTestUUID,
				},
			},
		},
		{
			"Test delete existing no-root by model specification and parent model mutation without specifying direct ID",
			func() []OperationModel {
				m := nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
				}
				parentModel := nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
				}
				return []OperationModel{
					{
						Model: &m,
						DoAfter: func() {
							parentModel.Ports = []string{m.UUID}
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
					UUID: logicalSwitchPortTestUUID,
				},
				&nbdb.LogicalSwitch{
					Name:  logicalSwitchTestName,
					UUID:  logicalSwitchTestUUID,
					Ports: []string{logicalSwitchPortTestUUID},
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
					UUID: logicalSwitchTestUUID,
				},
			},
		},
		{
			"Test delete existing non-root by model specification and parent model mutation without predicate",
			func() []OperationModel {
				parentModel := nbdb.PortGroup{
					Name: portGroupTestName,
				}
				aclRes := []nbdb.ACL{}
				return []OperationModel{
					{
						ModelPredicate: func(acl *nbdb.ACL) bool { return acl.Action == nbdb.ACLActionAllow },
						ExistingResult: &aclRes,
						DoAfter: func() {
							parentModel.ACLs = ExtractUUIDsFromModels(&aclRes)
						},
					},
					{
						Model: &parentModel,
						OnModelMutations: []interface{}{
							&parentModel.ACLs,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.ACL{
					Action: nbdb.ACLActionAllow,
					UUID:   aclTestUUID,
				},
				&nbdb.PortGroup{
					Name: portGroupTestName,
					UUID: portGroupTestUUID,
					ACLs: []string{aclTestUUID},
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.PortGroup{
					Name: portGroupTestName,
					UUID: portGroupTestUUID,
				},
			},
		},
		{
			"Test delete existing no-root by model specification and parent model mutation with empty ID slice",
			func() []OperationModel {
				m := nbdb.LogicalSwitchPort{
					Name: logicalSwitchPortTestName,
				}
				parentModel := nbdb.LogicalSwitch{
					Name: logicalSwitchTestName,
				}
				return []OperationModel{
					{
						Model: &m,
						DoAfter: func() {
							parentModel.Ports = []string{m.UUID}
						},
					},
					{
						Model:          &parentModel,
						ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == logicalSwitchTestName },
						OnModelMutations: []interface{}{
							&parentModel.Ports,
						},
					},
				}
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					UUID: logicalSwitchTestUUID,
					Name: logicalSwitchTestName,
				},
			},
			[]libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					UUID: logicalSwitchTestUUID,
					Name: logicalSwitchTestName,
				},
			},
		},
	}

	for _, tCase := range tt {
		if err := runTestCase(t, tCase, true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCreateWithAdHocClient(t *testing.T) {
	tt := []OperationModelTestCase{
		{
			"Test create non-existing item by model predicate specification",
			func() []OperationModel {
				return []OperationModel{
					{
						Model: &sbdb.Chassis{
							Name: "chassis-name",
						},
						ModelPredicate: func(c *sbdb.Chassis) bool { return c.Name == "chassis-name" },
					},
				}
			},
			[]libovsdbtest.TestData{},
			[]libovsdbtest.TestData{
				&sbdb.Chassis{
					Name: "chassis-name",
					UUID: "chassis-uuid",
				},
			},
		},
	}

	for _, tCase := range tt {
		dbSetup := libovsdbtest.TestSetup{
			SBData: tCase.initialDB,
		}

		nbClient, sbClient, cleanup, err := libovsdbtest.NewNBSBTestHarness(dbSetup)
		if err != nil {
			t.Fatalf("test: \"%s\" failed to set up test harness: %v", tCase.name, err)
		}
		t.Cleanup(cleanup.Cleanup)

		modelClient := NewModelClient(nbClient)

		opModel := tCase.generateCreateOrUpdateOp()
		modelClient.WithClient(sbClient).CreateOrUpdate(opModel...)

		matcher := libovsdbtest.HaveData(tCase.expectedDB)
		success, err := matcher.Match(sbClient)
		if !success {
			t.Fatalf("test: \"%s\" didn't match expected with actual, err: %s", tCase.name, matcher.FailureMessage(sbClient))
		}
		if err != nil {
			t.Fatalf("test: \"%s\" encountered error: %v", tCase.name, err)
		}
	}
}
