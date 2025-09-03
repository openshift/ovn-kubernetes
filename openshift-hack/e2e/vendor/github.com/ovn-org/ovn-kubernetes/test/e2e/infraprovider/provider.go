package infraprovider

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/providers/kind"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/providers/openshift"

	"k8s.io/client-go/rest"
)

type Name string

func (n Name) String() string {
	return string(n)
}

var provider api.Provider

// Set detects which infrastructure provider. Arg config is not needed for KinD provider but downstream implementations
// will require access to the kapi to infer what platform k8 is running on.
func Set(config *rest.Config) error {
	if kind.IsProvider() {
		provider = kind.New()
	}
	isOpenShift, err := openshift.IsProvider(config)
	if err != nil {
		return fmt.Errorf("failed to detect if the cluster is OpenShift: %w", err)
	}
	if isOpenShift {
		provider, err = openshift.New(config)
		if err != nil {
			return fmt.Errorf("failed to get OpenShift provider: %w", err)
		}
	}
	if provider == nil {
		return fmt.Errorf("failed to find an infrastructure provider")
	}
	return nil
}

func Get() api.Provider {
	if provider == nil {
		panic("provider not set")
	}
	return provider
}
