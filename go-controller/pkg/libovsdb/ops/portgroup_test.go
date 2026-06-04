// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ops

import (
	"context"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/nbdb"
	libovsdbtest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
)

func TestCreateOrUpdatePortGroupsOps_NilPortsPreservesExisting(t *testing.T) {
	aclUUID := buildNamedUUID()
	lspUUID := buildNamedUUID()
	lsUUID := buildNamedUUID()
	pgUUID := buildNamedUUID()

	initialNbdb := libovsdbtest.TestSetup{
		NBData: []libovsdbtest.TestData{
			&nbdb.ACL{
				UUID:      aclUUID,
				Action:    nbdb.ACLActionAllow,
				Direction: nbdb.ACLDirectionToLport,
				Match:     "ip4",
				Priority:  1000,
			},
			&nbdb.LogicalSwitchPort{
				UUID: lspUUID,
				Name: "lsp1",
			},
			&nbdb.LogicalSwitch{
				UUID:  lsUUID,
				Name:  "sw1",
				Ports: []string{lspUUID},
			},
			&nbdb.PortGroup{
				UUID:  pgUUID,
				Name:  "test-pg",
				ACLs:  []string{aclUUID},
				Ports: []string{lspUUID},
				ExternalIDs: map[string]string{
					"key": "old-value",
				},
			},
		},
	}

	nbClient, cleanup, err := libovsdbtest.NewNBTestHarness(initialNbdb, nil)
	if err != nil {
		t.Fatalf("failed to set up test harness: %v", err)
	}
	t.Cleanup(cleanup.Cleanup)

	// Look up real UUIDs from the client cache.
	var acls []*nbdb.ACL
	if err := nbClient.List(context.Background(), &acls); err != nil || len(acls) != 1 {
		t.Fatalf("failed to list ACLs: %v (count: %d)", err, len(acls))
	}
	var pgs []*nbdb.PortGroup
	if err := nbClient.List(context.Background(), &pgs); err != nil || len(pgs) != 1 {
		t.Fatalf("failed to list PortGroups: %v (count: %d)", err, len(pgs))
	}
	var lsps []*nbdb.LogicalSwitchPort
	if err := nbClient.List(context.Background(), &lsps); err != nil || len(lsps) != 1 {
		t.Fatalf("failed to list LSPs: %v (count: %d)", err, len(lsps))
	}

	// Call CreateOrUpdatePortGroupsOps with nil Ports but updated ExternalIDs.
	// This simulates what happens during re-sync when BuildPortGroup(ids, nil, acls)
	// is called followed by CreateOrUpdatePortGroupsOps.
	updatePG := &nbdb.PortGroup{
		Name: "test-pg",
		ACLs: []string{acls[0].UUID},
		ExternalIDs: map[string]string{
			"key": "new-value",
		},
		// Ports is nil — must NOT clear existing ports
	}

	ops, err := CreateOrUpdatePortGroupsOps(nbClient, nil, updatePG)
	if err != nil {
		t.Fatalf("CreateOrUpdatePortGroupsOps() error = %v", err)
	}
	_, err = TransactAndCheck(nbClient, ops)
	if err != nil {
		t.Fatalf("TransactAndCheck() error = %v", err)
	}

	// Verify ports are preserved.
	var resultPGs []*nbdb.PortGroup
	if err := nbClient.List(context.Background(), &resultPGs); err != nil || len(resultPGs) != 1 {
		t.Fatalf("failed to list result PortGroups: %v (count: %d)", err, len(resultPGs))
	}
	pg := resultPGs[0]

	if len(pg.Ports) != 1 || pg.Ports[0] != lsps[0].UUID {
		t.Fatalf("expected ports to be preserved [%s], got %v", lsps[0].UUID, pg.Ports)
	}
	if pg.ExternalIDs["key"] != "new-value" {
		t.Fatalf("expected ExternalIDs to be updated to 'new-value', got %v", pg.ExternalIDs)
	}
}

func TestCreateOrUpdatePortGroupsOps_ExplicitPortsReplaceExisting(t *testing.T) {
	aclUUID := buildNamedUUID()
	lsp1UUID := buildNamedUUID()
	lsp2UUID := buildNamedUUID()
	lsUUID := buildNamedUUID()
	pgUUID := buildNamedUUID()

	initialNbdb := libovsdbtest.TestSetup{
		NBData: []libovsdbtest.TestData{
			&nbdb.ACL{
				UUID:      aclUUID,
				Action:    nbdb.ACLActionAllow,
				Direction: nbdb.ACLDirectionToLport,
				Match:     "ip4",
				Priority:  1000,
			},
			&nbdb.LogicalSwitchPort{
				UUID: lsp1UUID,
				Name: "lsp1",
			},
			&nbdb.LogicalSwitchPort{
				UUID: lsp2UUID,
				Name: "lsp2",
			},
			&nbdb.LogicalSwitch{
				UUID:  lsUUID,
				Name:  "sw1",
				Ports: []string{lsp1UUID, lsp2UUID},
			},
			&nbdb.PortGroup{
				UUID:  pgUUID,
				Name:  "test-pg",
				ACLs:  []string{aclUUID},
				Ports: []string{lsp1UUID},
				ExternalIDs: map[string]string{
					"key": "value",
				},
			},
		},
	}

	nbClient, cleanup, err := libovsdbtest.NewNBTestHarness(initialNbdb, nil)
	if err != nil {
		t.Fatalf("failed to set up test harness: %v", err)
	}
	t.Cleanup(cleanup.Cleanup)

	// Look up real UUIDs.
	var acls []*nbdb.ACL
	if err := nbClient.List(context.Background(), &acls); err != nil || len(acls) != 1 {
		t.Fatalf("failed to list ACLs: %v (count: %d)", err, len(acls))
	}
	var lsps []*nbdb.LogicalSwitchPort
	if err := nbClient.List(context.Background(), &lsps); err != nil || len(lsps) != 2 {
		t.Fatalf("failed to list LSPs: %v (count: %d)", err, len(lsps))
	}
	// Find lsp2's real UUID.
	var lsp2RealUUID string
	for _, lsp := range lsps {
		if lsp.Name == "lsp2" {
			lsp2RealUUID = lsp.UUID
		}
	}
	if lsp2RealUUID == "" {
		t.Fatal("failed to find lsp2 UUID")
	}

	// Call CreateOrUpdatePortGroupsOps with explicit (non-nil) Ports pointing to lsp2.
	// This should REPLACE existing ports (lsp1 -> lsp2).
	updatePG := &nbdb.PortGroup{
		Name:  "test-pg",
		Ports: []string{lsp2RealUUID},
		ACLs:  []string{acls[0].UUID},
		ExternalIDs: map[string]string{
			"key": "value",
		},
	}

	ops, err := CreateOrUpdatePortGroupsOps(nbClient, nil, updatePG)
	if err != nil {
		t.Fatalf("CreateOrUpdatePortGroupsOps() error = %v", err)
	}
	_, err = TransactAndCheck(nbClient, ops)
	if err != nil {
		t.Fatalf("TransactAndCheck() error = %v", err)
	}

	// Verify ports were replaced.
	var resultPGs []*nbdb.PortGroup
	if err := nbClient.List(context.Background(), &resultPGs); err != nil || len(resultPGs) != 1 {
		t.Fatalf("failed to list result PortGroups: %v (count: %d)", err, len(resultPGs))
	}
	pg := resultPGs[0]

	if len(pg.Ports) != 1 || pg.Ports[0] != lsp2RealUUID {
		t.Fatalf("expected ports to be replaced with [%s], got %v", lsp2RealUUID, pg.Ports)
	}
}

func TestCreateOrUpdatePortGroupsOps_CreateWithNilPorts(t *testing.T) {
	aclUUID := buildNamedUUID()
	// Include a PG that references the ACL so the ACL isn't garbage-collected
	// during setup (ACLs are non-root in OVN NB schema).
	holderPGUUID := buildNamedUUID()

	initialNbdb := libovsdbtest.TestSetup{
		NBData: []libovsdbtest.TestData{
			&nbdb.ACL{
				UUID:      aclUUID,
				Action:    nbdb.ACLActionAllow,
				Direction: nbdb.ACLDirectionToLport,
				Match:     "ip4",
				Priority:  1000,
			},
			&nbdb.PortGroup{
				UUID: holderPGUUID,
				Name: "holder-pg",
				ACLs: []string{aclUUID},
			},
		},
	}

	nbClient, cleanup, err := libovsdbtest.NewNBTestHarness(initialNbdb, nil)
	if err != nil {
		t.Fatalf("failed to set up test harness: %v", err)
	}
	t.Cleanup(cleanup.Cleanup)

	// Look up real ACL UUID.
	var acls []*nbdb.ACL
	if err := nbClient.List(context.Background(), &acls); err != nil || len(acls) != 1 {
		t.Fatalf("failed to list ACLs: %v (count: %d)", err, len(acls))
	}

	// Create a new PG with nil Ports (simulating BuildPortGroup(ids, nil, acls)).
	newPG := &nbdb.PortGroup{
		Name: "new-pg",
		ACLs: []string{acls[0].UUID},
		ExternalIDs: map[string]string{
			"key": "value",
		},
		// Ports is nil — new PG should be created with empty ports
	}

	ops, err := CreateOrUpdatePortGroupsOps(nbClient, nil, newPG)
	if err != nil {
		t.Fatalf("CreateOrUpdatePortGroupsOps() error = %v", err)
	}
	_, err = TransactAndCheck(nbClient, ops)
	if err != nil {
		t.Fatalf("TransactAndCheck() error = %v", err)
	}

	// Verify the new PG was created.
	pg, err := GetPortGroup(nbClient, &nbdb.PortGroup{Name: "new-pg"})
	if err != nil {
		t.Fatalf("GetPortGroup() error = %v", err)
	}
	if len(pg.Ports) != 0 {
		t.Fatalf("expected new PG to have empty ports, got %v", pg.Ports)
	}
	if len(pg.ACLs) != 1 || pg.ACLs[0] != acls[0].UUID {
		t.Fatalf("expected new PG to have ACL [%s], got %v", acls[0].UUID, pg.ACLs)
	}
	if pg.ExternalIDs["key"] != "value" {
		t.Fatalf("expected ExternalIDs key=value, got %v", pg.ExternalIDs)
	}
}
