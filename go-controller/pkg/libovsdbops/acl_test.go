package libovsdbops

import (
	"fmt"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"sync/atomic"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

func buildNamedUUID() string {
	return fmt.Sprintf("%c%010d", namedUUIDPrefix, atomic.AddUint32(&namedUUIDCounter, 1))
}

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
	searchACL := nbdb.ACL{
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
		desc      string
		f         func(nbClient libovsdbclient.Client) error
		noChanges bool
	}{
		{
			desc: "CreateOrUpdateACLsOps",
			f: func(nbClient libovsdbclient.Client) error {
				// reset UUID that may be set by the previous tests
				searchACL.UUID = ""
				_, err := CreateOrUpdateACLsOps(nbClient, nil, &searchACL)
				return err
			},
		},
		{
			desc: "DeleteACLs",
			f: func(nbClient libovsdbclient.Client) error {
				// reset UUID that may be set by the previous tests
				searchACL.UUID = ""
				err := DeleteACLs(nbClient, []nbdb.ACL{searchACL})
				return err
			},
			noChanges: true,
		},
		{
			desc: "UpdateACLsLoggingOps",
			f: func(nbClient libovsdbclient.Client) error {
				// reset UUID that may be set by the previous tests
				searchACL.UUID = ""
				_, err := UpdateACLsLoggingOps(nbClient, nil, &searchACL)
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
			if err != nil {
				t.Fatalf("test: \"%s\" returned error: %v", tt.desc, err)
			}

			pg, err = GetPortGroup(nbClient, pg)
			if err != nil {
				t.Fatalf("test: \"%s\": failed to get port group", tt.desc)
			}
			expectedACLNum := 1
			if tt.noChanges {
				expectedACLNum = 3
			}
			if len(pg.ACLs) != expectedACLNum {
				t.Fatalf("test: \"%s\": expected port group to have %d ACL left, got %+v", tt.desc, expectedACLNum, pg.ACLs)
			}
		})
	}
}
