package util

import (
	"fmt"
	"testing"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestChassisIDSyncValidation validates the critical fix:
// "Do not continue with annotation when syncing OVS fails"
//
// This test ensures that GetNodeChassisIDWithFallback() fails fast when
// it cannot sync the annotation to OVS, preventing split-brain gateway
// ownership issues.
func TestChassisIDSyncValidation(t *testing.T) {
	const (
		annotationChassisID = "aaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		ovsChassisID        = "xxxx-yyyy-zzzz-wwww-qqqqqqqqqqqq"
		nodeName            = "test-node"
	)

	tests := []struct {
		name        string
		description string
		node        *corev1.Node
		ovsCommands []ovntest.ExpectedCmd
		expectError bool
		expectedID  string
		validates   string
	}{
		{
			name:        "valid annotation with successful OVS sync",
			description: "When annotation is valid and OVS sync succeeds, return annotation value",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					Annotations: map[string]string{
						OvnNodeChassisID: annotationChassisID,
					},
				},
			},
			ovsCommands: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovs-vsctl --timeout=15 get Open_vSwitch . external_ids:system-id",
					Output: fmt.Sprintf("\"%s\"", ovsChassisID), // Different from annotation
				},
				{
					Cmd:    fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:system-id=%s", annotationChassisID),
					Output: "",
				},
			},
			expectError: false,
			expectedID:  annotationChassisID,
			validates:   "Normal flow: annotation synced to OVS successfully",
		},
		{
			name:        "valid annotation but OVS sync fails - MUST FAIL",
			description: "CRITICAL: When OVS sync fails, must return error to prevent annotation/OVS mismatch",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					Annotations: map[string]string{
						OvnNodeChassisID: annotationChassisID,
					},
				},
			},
			ovsCommands: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovs-vsctl --timeout=15 get Open_vSwitch . external_ids:system-id",
					Output: fmt.Sprintf("\"%s\"", ovsChassisID),
				},
				{
					Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:system-id=%s", annotationChassisID),
					Err: fmt.Errorf("OVS temporarily unavailable"),
				},
			},
			expectError: true,
			expectedID:  "",
			validates:   "CRITICAL FIX: Must fail when OVS sync fails (prevents gateway ownership breakage)",
		},
		{
			name:        "annotation and OVS already match - no sync needed",
			description: "When annotation matches OVS, skip sync and return immediately",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					Annotations: map[string]string{
						OvnNodeChassisID: annotationChassisID,
					},
				},
			},
			ovsCommands: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovs-vsctl --timeout=15 get Open_vSwitch . external_ids:system-id",
					Output: fmt.Sprintf("\"%s\"", annotationChassisID), // Matches annotation
				},
				// No set command - sync not needed
			},
			expectError: false,
			expectedID:  annotationChassisID,
			validates:   "Optimization: Skip sync when values already match",
		},
		{
			name:        "invalid annotation - graceful fallback to OVS",
			description: "When annotation has invalid UUID, fall back to reading from OVS",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					Annotations: map[string]string{
						OvnNodeChassisID: "not-a-valid-uuid-format",
					},
				},
			},
			ovsCommands: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:system-id",
					Output: ovsChassisID,
				},
			},
			expectError: false,
			expectedID:  ovsChassisID,
			validates:   "Graceful degradation: Invalid annotation falls back to OVS",
		},
		{
			name:        "OVS read fails but set succeeds",
			description: "When OVS read fails but set succeeds, still return annotation",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					Annotations: map[string]string{
						OvnNodeChassisID: annotationChassisID,
					},
				},
			},
			ovsCommands: []ovntest.ExpectedCmd{
				{
					Cmd: "ovs-vsctl --timeout=15 get Open_vSwitch . external_ids:system-id",
					Err: fmt.Errorf("OVS read temporarily unavailable"),
				},
				{
					Cmd:    fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:system-id=%s", annotationChassisID),
					Output: "",
				},
			},
			expectError: false,
			expectedID:  annotationChassisID,
			validates:   "Resilience: Can recover from read failure if set succeeds",
		},
		{
			name:        "nil node - fallback to OVS",
			description: "When node is nil, fall back to reading from OVS",
			node:        nil,
			ovsCommands: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:system-id",
					Output: ovsChassisID,
				},
			},
			expectError: false,
			expectedID:  ovsChassisID,
			validates:   "Safety: Handle nil node gracefully",
		},
		{
			name:        "no annotation - fallback to OVS",
			description: "When annotation is missing, fall back to reading from OVS",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
				},
			},
			ovsCommands: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:system-id",
					Output: ovsChassisID,
				},
			},
			expectError: false,
			expectedID:  ovsChassisID,
			validates:   "Normal flow: Fresh node creation reads from OVS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Test: %s", tt.description)
			t.Logf("Validates: %s", tt.validates)

			// Setup fake executor with expected commands
			fexec := ovntest.NewFakeExec()
			for _, cmd := range tt.ovsCommands {
				fexec.AddFakeCmd(&cmd)
			}
			err := SetExec(fexec)
			require.NoError(t, err)

			// Execute the function under test
			chassisID, err := GetNodeChassisIDWithFallback(tt.node)

			// Verify expectations
			if tt.expectError {
				assert.Error(t, err, "Expected error but got none")
				assert.Empty(t, chassisID, "Chassis ID should be empty on error")
				t.Logf("✓ Correctly failed with error: %v", err)
			} else {
				assert.NoError(t, err, "Unexpected error")
				assert.Equal(t, tt.expectedID, chassisID, "Chassis ID mismatch")
				t.Logf("✓ Correctly returned chassis ID: %s", chassisID)
			}

			// Verify all expected OVS commands were called
			assert.NoError(t, fexec.ExpectationsWereMet(), "Not all expected OVS commands were executed")
		})
	}
}

// TestChassisIDSyncFailurePreventsGatewayBreakage demonstrates why OVS sync must succeed
func TestChassisIDSyncFailurePreventsGatewayBreakage(t *testing.T) {
	const (
		annotationID = "aaaa-1111-2222-3333-444444444444"
		ovsID        = "bbbb-5555-6666-7777-888888888888"
	)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gateway-node",
			Annotations: map[string]string{
				OvnNodeChassisID: annotationID,
			},
		},
	}

	t.Run("scenario: OVS sync fails - function must return error", func(t *testing.T) {
		fexec := ovntest.NewFakeExec()
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-vsctl --timeout=15 get Open_vSwitch . external_ids:system-id",
			Output: fmt.Sprintf("\"%s\"", ovsID),
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:system-id=%s", annotationID),
			Err: fmt.Errorf("OVS database locked"),
		})
		err := SetExec(fexec)
		require.NoError(t, err)

		_, err = GetNodeChassisIDWithFallback(node)

		assert.Error(t, err, "MUST return error when OVS sync fails")
		t.Log("✓ CRITICAL: Function correctly failed when OVS sync failed")
		t.Log("  This prevents the following failure scenario:")
		t.Log("  1. Node publishes annotation ID (" + annotationID + ") in L3 gateway config")
		t.Log("  2. OVN controller uses OVS ID (" + ovsID + ")")
		t.Log("  3. Gateway ownership breaks - traffic fails")
		t.Log("  By returning error, we force retry until sync succeeds")
	})

	t.Run("scenario: OVS sync succeeds - both values match", func(t *testing.T) {
		fexec := ovntest.NewFakeExec()
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-vsctl --timeout=15 get Open_vSwitch . external_ids:system-id",
			Output: fmt.Sprintf("\"%s\"", ovsID),
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:system-id=%s", annotationID),
			Output: "",
		})
		err := SetExec(fexec)
		require.NoError(t, err)

		chassisID, err := GetNodeChassisIDWithFallback(node)

		assert.NoError(t, err)
		assert.Equal(t, annotationID, chassisID)
		t.Log("✓ SUCCESS: Both annotation and OVS now have same value")
		t.Log("  Node publishes: " + annotationID)
		t.Log("  OVN controller uses: " + annotationID)
		t.Log("  Gateway ownership works correctly ✓")
	})
}

// TestChassisIDQuoteStripping verifies OVS output quote handling
func TestChassisIDQuoteStripping(t *testing.T) {
	const (
		chassisID = "test-chassis-id-1234567890ab"
		nodeName  = "test-node"
	)

	tests := []struct {
		name      string
		ovsOutput string
	}{
		{
			name:      "OVS output with quotes",
			ovsOutput: fmt.Sprintf("\"%s\"", chassisID),
		},
		{
			name:      "OVS output without quotes",
			ovsOutput: chassisID,
		},
		{
			name:      "OVS output with extra whitespace",
			ovsOutput: fmt.Sprintf("  \"%s\"  \n", chassisID),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 get Open_vSwitch . external_ids:system-id",
				Output: tt.ovsOutput,
			})
			// No set command - OVS matches annotation
			err := SetExec(fexec)
			require.NoError(t, err)

			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					Annotations: map[string]string{
						OvnNodeChassisID: chassisID,
					},
				},
			}

			result, err := GetNodeChassisIDWithFallback(node)

			assert.NoError(t, err)
			assert.Equal(t, chassisID, result, "Should correctly handle OVS output format")
			assert.NoError(t, fexec.ExpectationsWereMet(), "Should skip set when values match")
			t.Logf("✓ Correctly parsed OVS output: %q -> %q", tt.ovsOutput, result)
		})
	}
}
