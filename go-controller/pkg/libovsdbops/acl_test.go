package libovsdbops

import (
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"strings"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

func TestCleanupEquivalentACLs(t *testing.T) {
	aclName := "acl1"
	anotherACLName := "acl2"
	aclSev := nbdb.ACLSeverityInfo
	aclMeter := types.OvnACLLoggingMeter
	initialACL := &nbdb.ACL{
		UUID:        buildNamedUUID(),
		Action:      nbdb.ACLActionAllow,
		Direction:   nbdb.ACLDirectionToLport,
		ExternalIDs: map[string]string{"key": "value"},
		Log:         true,
		Match:       "match",
		Meter:       &aclMeter,
		Name:        &aclName,
		Options:     nil,
		Priority:    1,
		Severity:    &aclSev,
	}
	sameNameExitIDsACL := &nbdb.ACL{
		UUID:        buildNamedUUID(),
		Action:      nbdb.ACLActionAllow,
		Direction:   nbdb.ACLDirectionToLport,
		ExternalIDs: map[string]string{"key": "value"},
		Log:         true,
		Match:       "match1",
		Meter:       &aclMeter,
		Name:        &aclName,
		Options:     map[string]string{"key": "value"},
		Priority:    2,
		Severity:    &aclSev,
	}
	same4FieldACL := &nbdb.ACL{
		UUID:        buildNamedUUID(),
		Action:      nbdb.ACLActionAllow,
		Direction:   nbdb.ACLDirectionToLport,
		ExternalIDs: map[string]string{"key1": "value"},
		Log:         true,
		Match:       "match",
		Meter:       &aclMeter,
		Name:        &anotherACLName,
		Options:     nil,
		Priority:    1,
		Severity:    &aclSev,
	}

	pg := &nbdb.PortGroup{
		Name: "testPG",
		ACLs: []string{initialACL.UUID, sameNameExitIDsACL.UUID, same4FieldACL.UUID},
	}

	initialDB := []libovsdbtest.TestData{
		initialACL,
		sameNameExitIDsACL,
		same4FieldACL,
		pg,
	}

	// searchACL is initialACL without UUID, because we need to use predicate search
	searchACL := &nbdb.ACL{
		Action:      nbdb.ACLActionAllow,
		Direction:   nbdb.ACLDirectionToLport,
		ExternalIDs: map[string]string{"key": "value"},
		Log:         true,
		Match:       "match",
		Meter:       &aclMeter,
		Name:        &aclName,
		Options:     nil,
		Priority:    1,
		Severity:    &aclSev,
	}

	tests := []struct {
		desc string
		f    func(nbClient libovsdbclient.Client) error
	}{
		{
			desc: "CreateOrUpdateACLsOps",
			f: func(nbClient libovsdbclient.Client) error {
				_, err := CreateOrUpdateACLsOps(nbClient, nil, searchACL)
				return err
			},
		},
		{
			desc: "UpdateACLsLoggingOps",
			f: func(nbClient libovsdbclient.Client) error {
				_, err := UpdateACLsLoggingOps(nbClient, nil, searchACL)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			nbClient, cleanup, err := libovsdbtest.NewNBTestHarness(libovsdbtest.TestSetup{
				NBData: initialDB,
			}, nil)
			if err != nil {
				t.Fatalf("test: \"%s\" failed to set up test harness: %v", tt.desc, err)
			}
			t.Cleanup(cleanup.Cleanup)

			pg, err := GetPortGroup(nbClient, pg)
			if err != nil {
				t.Fatalf("test: \"%s\": failed to get port group", tt.desc)
			}
			if len(pg.ACLs) != 3 {
				t.Fatalf("test: \"%s\" setup failed: expected port group to have 3 ACLs, got %+v", tt.desc, pg.ACLs)
			}

			err = tt.f(nbClient)
			if err == nil {
				t.Fatalf("test: \"%s\" expected to return error", tt.desc)
			}
			if !strings.Contains(err.Error(), "unexpectedly found multiple results for provided predicate") {
				t.Fatalf("test: \"%s\": error %s doesn't match expected", tt.desc, err.Error())
			}

			pg, err = GetPortGroup(nbClient, pg)
			if err != nil {
				t.Fatalf("test: \"%s\": failed to get port group", tt.desc)
			}
			if len(pg.ACLs) != 1 {
				t.Fatalf("test: \"%s\": expected port group to have only 1 ACL left, got %+v", tt.desc, pg.ACLs)
			}
		})
	}
}
