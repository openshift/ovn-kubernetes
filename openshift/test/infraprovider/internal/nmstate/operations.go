// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package nmstate

import (
	"context"
	"fmt"
	"time"

	nmstatev1 "github.com/nmstate/kubernetes-nmstate/api/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"
)

const (
	nmstateDeploymentTimeout = 5 * time.Minute
	nncpOperationTimeout     = time.Minute
	nncpDeletionPollInterval = 250 * time.Millisecond
)

func Deploy(ctx context.Context, cli client.Client) error {
	ctx, cancel := context.WithTimeout(ctx, nmstateDeploymentTimeout)
	defer cancel()

	nmstate := &nmstatev1.NMState{
		ObjectMeta: metav1.ObjectMeta{
			Name: "nmstate",
		},
	}
	_, err := controllerutil.CreateOrPatch(ctx, cli, nmstate, func() error { return nil })
	if err != nil {
		return fmt.Errorf("failed to create or patch NMState %q: %w", nmstate.Name, err)
	}
	return waitForNMStateAvailable(ctx, cli, nmstate)
}

func UpdateNNCP(ctx context.Context, cli client.Client, name string, configuration Configuration) error {
	ctx, cancel := context.WithTimeout(ctx, nncpOperationTimeout)
	defer cancel()

	marshalledConfiguration, err := yaml.Marshal(configuration)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration for NNCP %q: %w", name, err)
	}
	nncp := &nmstatev1.NodeNetworkConfigurationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	_, err = controllerutil.CreateOrPatch(ctx, cli, nncp, func() error {
		nncp.Spec.DesiredState.Raw = marshalledConfiguration
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or patch NNCP %q: %w", name, err)
	}
	return waitForNNCPAvailable(ctx, cli, nncp)
}

func DeleteNNCP(ctx context.Context, cli client.Client, name string) error {
	ctx, cancel := context.WithTimeout(ctx, nncpOperationTimeout)
	defer cancel()

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
	err := wait.PollUntilContextCancel(ctx, nncpDeletionPollInterval, true, func(ctx context.Context) (bool, error) {
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
