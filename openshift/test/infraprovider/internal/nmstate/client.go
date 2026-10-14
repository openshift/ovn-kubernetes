package nmstate

import (
	"fmt"

	nmstatev1 "github.com/nmstate/kubernetes-nmstate/api/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Client(config *rest.Config) (client.Client, error) {
	scheme := runtime.NewScheme()
	if err := nmstatev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add nmstate types to scheme: %w", err)
	}

	cli, err := client.New(config, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create nmstate client: %w", err)
	}
	return cli, nil
}
