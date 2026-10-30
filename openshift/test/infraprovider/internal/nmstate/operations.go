package nmstate

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

	nmstatev1 "github.com/nmstate/kubernetes-nmstate/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	if _, err := controllerutil.CreateOrPatch(ctx, cli, nncp, func() error {
		nncp.Spec.DesiredState.Raw = marshalledConfiguration
		return nil
	}); err != nil {
		return fmt.Errorf("failed to create or patch NNCP %q: %w", name, err)
	}
	if err := waitForNNCPAvailable(ctx, cli, nncp, time.Minute); err != nil {
		return err
	}
	return nil
}

func DeleteNNCP(ctx context.Context, cli client.Client, name string) error {
	nncp := &nmstatev1.NodeNetworkConfigurationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if err := cli.Delete(ctx, nncp); err != nil {
		return fmt.Errorf("failed to delete NNCP %q: %w", name, err)
	}
	return nil
}
