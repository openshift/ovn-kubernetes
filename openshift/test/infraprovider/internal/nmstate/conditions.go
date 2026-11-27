// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package nmstate

import (
	"context"
	"fmt"
	"time"

	nmstateshared "github.com/nmstate/kubernetes-nmstate/api/shared"
	nmstatev1 "github.com/nmstate/kubernetes-nmstate/api/v1"
	nmstatev1beta1 "github.com/nmstate/kubernetes-nmstate/api/v1beta1"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const conditionPollInterval = 2 * time.Second

// NNCP conditions do not expose observedGeneration. Each selected node's
// enactment must acknowledge the written policy generation before an Available
// condition can be treated as completion of this update.
func waitForNNCPAvailable(
	ctx context.Context,
	reader client.Reader,
	policy *nmstatev1.NodeNetworkConfigurationPolicy,
) error {
	nodes := &corev1.NodeList{}
	if err := reader.List(ctx, nodes, client.MatchingLabels(policy.Spec.NodeSelector)); err != nil {
		return fmt.Errorf("failed to list nodes for NNCP %q: %w", policy.Name, err)
	}
	if len(nodes.Items) == 0 {
		return fmt.Errorf("NNCP %q does not match any nodes", policy.Name)
	}

	generation := policy.Generation
	err := wait.PollUntilContextCancel(ctx, conditionPollInterval, true, func(ctx context.Context) (bool, error) {
		if err := reader.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
			return false, fmt.Errorf("failed to get NNCP %q: %w", policy.Name, err)
		}
		if policy.Generation != generation {
			return false, fmt.Errorf("NNCP %q generation changed from %d to %d while waiting for availability",
				policy.Name, generation, policy.Generation)
		}
		condition := policy.Status.Conditions.Find(nmstateshared.NodeNetworkConfigurationPolicyConditionAvailable)
		if condition == nil || condition.Status != corev1.ConditionTrue {
			return false, nil
		}

		for _, node := range nodes.Items {
			enactment := &nmstatev1beta1.NodeNetworkConfigurationEnactment{}
			if err := reader.Get(ctx, nmstateshared.EnactmentKey(node.Name, policy.Name), enactment); err != nil {
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				return false, fmt.Errorf("failed to get NNCE for node %q and NNCP %q: %w", node.Name, policy.Name, err)
			}
			condition := enactment.Status.Conditions.Find(nmstateshared.NodeNetworkConfigurationEnactmentConditionAvailable)
			if enactment.Status.PolicyGeneration != generation || condition == nil || condition.Status != corev1.ConditionTrue {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("waiting for NNCP %q generation %d to become Available on all selected nodes: %w", policy.Name, generation, err)
	}
	return nil
}

func waitForNMStateAvailable(
	ctx context.Context,
	reader client.Reader,
	nmstate *nmstatev1.NMState,
) error {
	err := wait.PollUntilContextCancel(ctx, conditionPollInterval, true, func(ctx context.Context) (bool, error) {
		if err := reader.Get(ctx, client.ObjectKeyFromObject(nmstate), nmstate); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("failed to get NMState %q: %w", nmstate.Name, err)
		}
		condition := nmstate.Status.Conditions.Find(nmstateshared.NmstateConditionAvailable)
		return condition != nil && condition.Status == corev1.ConditionTrue, nil
	})
	if err != nil {
		return fmt.Errorf("waiting for NMState %q to become Available: %w", nmstate.Name, err)
	}
	return nil
}
