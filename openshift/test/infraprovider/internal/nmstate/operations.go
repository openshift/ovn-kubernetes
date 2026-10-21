package nmstate

import (
	"context"
	"fmt"
	"time"

	nmstateshared "github.com/nmstate/kubernetes-nmstate/api/shared"
	nmstatev1 "github.com/nmstate/kubernetes-nmstate/api/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"
)

func Deploy(ctx context.Context, cli client.Client) error {
	nmstate := &nmstatev1.NMState{
		ObjectMeta: metav1.ObjectMeta{
			Name: "nmstate",
		},
	}
	_, err := controllerutil.CreateOrPatch(ctx, cli, nmstate, func() error { return nil })
	if err != nil {
		return fmt.Errorf("failed to create or patch NMState %q: %w", nmstate.Name, err)
	}
	return waitForNMStateAvailable(ctx, cli, nmstate, 5*time.Minute)
}

func UpdateNNCP(ctx context.Context, cli client.Client, name string, configuration Configuration) error {
	marshalledConfiguration, err := yaml.Marshal(configuration)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration for NNCP %q: %w", name, err)
	}
	nncp := &nmstatev1.NodeNetworkConfigurationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	// An already available policy keeps reporting its previous desired state
	// until the controller reconciles the patch below, so remember the current
	// condition to not mistake it for the outcome of this update.
	previous, err := availableCondition(ctx, cli, name)
	if err != nil {
		return err
	}
	operation, err := controllerutil.CreateOrPatch(ctx, cli, nncp, func() error {
		nncp.Spec.DesiredState.Raw = marshalledConfiguration
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or patch NNCP %q: %w", name, err)
	}
	if operation == controllerutil.OperationResultNone {
		// The desired state is the one already applied: its condition is up to date.
		previous = nil
	}
	if err := waitForNNCPAvailable(ctx, cli, nncp, previous, time.Minute); err != nil {
		return err
	}
	return nil
}

// availableCondition returns the available condition currently reported by the
// NNCP, or nil if the policy or the condition does not exist.
func availableCondition(ctx context.Context, cli client.Client, name string) (*nmstateshared.Condition, error) {
	nncp := &nmstatev1.NodeNetworkConfigurationPolicy{}
	if err := cli.Get(ctx, client.ObjectKey{Name: name}, nncp); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get NNCP %q: %w", name, err)
	}
	condition := nncp.Status.Conditions.Find(nmstateshared.NodeNetworkConfigurationPolicyConditionAvailable)
	if condition == nil {
		return nil, nil
	}
	current := *condition
	return &current, nil
}

func DeleteNNCP(ctx context.Context, cli client.Client, name string) error {
	nncp := &nmstatev1.NodeNetworkConfigurationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if err := cli.Delete(ctx, nncp); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to delete NNCP %q: %w", name, err)
	}
	// The API accepting the deletion does not mean the policy is gone: it stays
	// around while its finalizers run, so wait for it to actually disappear to
	// not leave a stale policy behind for the next setup.
	err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		err := cli.Get(ctx, client.ObjectKey{Name: name}, &nmstatev1.NodeNetworkConfigurationPolicy{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("failed to get NNCP %q: %w", name, err)
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("waiting for NNCP %q to be deleted: %w", name, err)
	}
	return nil
}
