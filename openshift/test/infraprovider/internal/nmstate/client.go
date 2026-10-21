// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package nmstate

import (
	"fmt"

	nmstatev1 "github.com/nmstate/kubernetes-nmstate/api/v1"
	nmstatev1beta1 "github.com/nmstate/kubernetes-nmstate/api/v1beta1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Client(config *rest.Config) (client.Client, error) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add core types to scheme: %w", err)
	}
	if err := nmstatev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add nmstate types to scheme: %w", err)
	}
	if err := nmstatev1beta1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add nmstate enactment types to scheme: %w", err)
	}

	cli, err := client.New(config, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create nmstate client: %w", err)
	}
	return cli, nil
}
