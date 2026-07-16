// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ovn

import (
	"strings"
	"testing"
)

func TestCleanupNoOverlaySNATExemptionAddressSetNilFactory(t *testing.T) {
	err := cleanupNoOverlaySNATExemptionAddressSet(nil, nil, "")
	if err == nil {
		t.Fatalf("expected nil factory cleanup to fail")
	}
	if !strings.Contains(err.Error(), "address set factory is nil") {
		t.Fatalf("expected missing address set factory error, got: %v", err)
	}
}
