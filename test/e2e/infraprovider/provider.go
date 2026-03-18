package infraprovider

import (
	"fmt"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/internal/kind"
)

var infraProvider api.Provider

// New creates a new infrastructure provider by name.
func New(providerName string) api.Provider {
	switch providerName {
	case "kind":
		return kind.New()
	default:
		panic(fmt.Sprintf("unknown infra provider %q", providerName))
	}
}

// IsKindProvider returns true if clusters provider is KinD.
func IsKindProvider() bool {
	return kind.IsProvider()
}

// Set infrastructure provider.
func Set(provider api.Provider) {
	infraProvider = provider
}

// Get infrastructure provider.
func Get() api.Provider {
	if infraProvider == nil {
		panic("infra provider not set")
	}
	return infraProvider
}
