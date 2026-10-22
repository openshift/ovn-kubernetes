package nmstate

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nmstateshared "github.com/nmstate/kubernetes-nmstate/api/shared"
	nmstatev1 "github.com/nmstate/kubernetes-nmstate/api/v1"
)

func waitForNNCPAvailable(
	ctx context.Context,
	reader client.Reader,
	policy *nmstatev1.NodeNetworkConfigurationPolicy,
	timeout time.Duration,
) error {
	return waitForCondition(ctx, reader, policy, nmstateshared.NodeNetworkConfigurationPolicyConditionAvailable, timeout)
}

func waitForNMStateAvailable(
	ctx context.Context,
	reader client.Reader,
	nmstate *nmstatev1.NMState,
	timeout time.Duration,
) error {
	return waitForCondition(ctx, reader, nmstate, nmstateshared.NmstateConditionAvailable, timeout)
}

func waitForCondition(
	ctx context.Context,
	reader client.Reader,
	obj client.Object,
	conditionType nmstateshared.ConditionType,
	timeout time.Duration,
) error {
	gvk := obj.GetObjectKind().GroupVersionKind()
	err := wait.PollUntilContextTimeout(
		ctx,
		2*time.Second,
		timeout,
		true, // Check immediately before waiting.
		func(ctx context.Context) (bool, error) {

			// NNCPs are cluster-scoped: no namespace.
			if err := reader.Get(ctx, client.ObjectKey{Name: obj.GetName()}, obj); err != nil {
				if apierrors.IsNotFound(err) {
					// Allow waiting for a policy that has not been created yet.
					return false, nil
				}
				return false, fmt.Errorf("failed to get %+v %q: %w", gvk, obj.GetName(), err)
			}
			conditions, err := extractConditions(obj)
			if err != nil {
				return false, err
			}

			condition := conditions.Find(conditionType)
			return condition != nil &&
				condition.Status == corev1.ConditionTrue, nil
		},
	)
	if err != nil {
		return fmt.Errorf("waiting for %+v %q to become Available: %w", gvk, obj.GetName(), err)
	}
	return nil
}

func extractConditions(obj client.Object) (nmstateshared.ConditionList, error) {
	switch target := any(obj).(type) {
	case *nmstatev1.NMState:
		return target.Status.Conditions, nil
	case *nmstatev1.NodeNetworkConfigurationPolicy:
		return target.Status.Conditions, nil
	default:
		return nil, fmt.Errorf("unsupported object type %T for nmstate conditions", obj)
	}
}
