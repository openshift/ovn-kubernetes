// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import (
	"context"
	"fmt"

	kubevirtv1 "kubevirt.io/api/core/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// MigrationPhase reads the migration that the test created, rather than an
// earlier migration of the same VM or a migration belonging to another test.
func MigrationPhase(ctx context.Context, client crclient.Reader, migration *kubevirtv1.VirtualMachineInstanceMigration) (kubevirtv1.VirtualMachineInstanceMigrationPhase, error) {
	current := &kubevirtv1.VirtualMachineInstanceMigration{}
	key := crclient.ObjectKeyFromObject(migration)
	if err := client.Get(ctx, key, current); err != nil {
		return kubevirtv1.MigrationPhaseUnset, err
	}
	if current.UID != migration.UID {
		return kubevirtv1.MigrationPhaseUnset, fmt.Errorf("migration %s was replaced: expected UID %s, got %s", key, migration.UID, current.UID)
	}
	return current.Status.Phase, nil
}
