package nmstate

import (
	"context"
	"fmt"
	"time"

	nmstateshared "github.com/nmstate/kubernetes-nmstate/api/shared"
	nmstatev1 "github.com/nmstate/kubernetes-nmstate/api/v1"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// waitForNNCPAvailable waits for the policy to be available again. When the
// policy is patched its conditions keep reporting the previous desired state
// until the controller reconciles it, so previous, if not nil, is the condition
// observed before the patch and the wait does not complete until that condition
// is reported again.
func waitForNNCPAvailable(
	ctx context.Context,
	reader client.Reader,
	policy *nmstatev1.NodeNetworkConfigurationPolicy,
	previous *nmstateshared.Condition,
	timeout time.Duration,
) error {
	return waitForCondition(ctx, reader, policy, nmstateshared.NodeNetworkConfigurationPolicyConditionAvailable, previous, timeout)
}

func waitForNMStateAvailable(
	ctx context.Context,
	reader client.Reader,
	nmstate *nmstatev1.NMState,
	timeout time.Duration,
) error {
	return waitForCondition(ctx, reader, nmstate, nmstateshared.NmstateConditionAvailable, nil, timeout)
}

func waitForCondition(
	ctx context.Context,
	reader client.Reader,
	obj client.Object,
	conditionType nmstateshared.ConditionType,
	previous *nmstateshared.Condition,
	timeout time.Duration,
) error {
	objKind := kind(obj)
	var becameUnavailable bool
	err := wait.PollUntilContextTimeout(
		ctx,
		2*time.Second,
		timeout,
		true, // Check immediately before waiting.
		func(ctx context.Context) (bool, error) {
			if err := reader.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				if apierrors.IsNotFound(err) {
					// Allow waiting for a policy that has not been created yet.
					return false, nil
				}
				return false, fmt.Errorf("failed to get %s %q: %w", objKind, obj.GetName(), err)
			}
			conditions, err := extractConditions(obj)
			if err != nil {
				return false, err
			}

			condition := conditions.Find(conditionType)
			if condition == nil || condition.Status != corev1.ConditionTrue {
				// The controller has reported the object again since the wait
				// started, so a later available condition belongs to it.
				becameUnavailable = true
				return false, nil
			}
			if previous != nil && !becameUnavailable && !conditionAdvanced(*previous, *condition) {
				// The condition is still the one observed before the policy was
				// patched, so it does not report the new desired state yet.
				return false, nil
			}
			return true, nil
		},
	)
	if err != nil {
		return fmt.Errorf("waiting for %s %q to become Available: %w", objKind, obj.GetName(), err)
	}
	return nil
}

// conditionAdvanced reports whether current was reported by the controller after
// previous, that is, whether the controller has observed the object again.
func conditionAdvanced(previous, current nmstateshared.Condition) bool {
	return current.LastTransitionTime.After(previous.LastTransitionTime.Time) ||
		current.LastHeartbeatTime.After(previous.LastHeartbeatTime.Time)
}

func extractConditions(obj client.Object) (nmstateshared.ConditionList, error) {
	switch target := any(obj).(type) {
	case *nmstatev1.NMState:
		return target.Status.Conditions, nil
	case *nmstatev1.NodeNetworkConfigurationPolicy:
		return target.Status.Conditions, nil
	default:
		return nil, fmt.Errorf("unsupported object type %s for nmstate conditions", kind(obj))
	}
}

// kind returns a human readable kind for obj. Objects obtained from a typed
// client have an empty TypeMeta, so GroupVersionKind cannot be used here.
func kind(obj client.Object) string {
	switch obj.(type) {
	case *nmstatev1.NMState:
		return "NMState"
	case *nmstatev1.NodeNetworkConfigurationPolicy:
		return "NodeNetworkConfigurationPolicy"
	default:
		return fmt.Sprintf("%T", obj)
	}
}
