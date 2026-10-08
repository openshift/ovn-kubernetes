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
	err := wait.PollUntilContextTimeout(
		ctx,
		2*time.Second,
		timeout,
		true, // Check immediately before waiting.
		func(ctx context.Context) (bool, error) {

			// NNCPs are cluster-scoped: no namespace.
			if err := reader.Get(ctx, client.ObjectKey{Name: policy.Name}, policy); err != nil {
				if apierrors.IsNotFound(err) {
					// Allow waiting for a policy that has not been created yet.
					return false, nil
				}
				return false, fmt.Errorf("failed to get NNCP %q: %w", policy.Name, err)
			}

			condition := policy.Status.Conditions.Find(
				nmstateshared.NodeNetworkConfigurationPolicyConditionAvailable,
			)
			return condition != nil &&
				condition.Status == corev1.ConditionTrue, nil
		},
	)
	if err != nil {
		return fmt.Errorf("waiting for NNCP %q to become Available: %w", policy.Name, err)
	}
	return nil
}
