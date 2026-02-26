package infraprovider

import (
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

type Name string

// CommandRunner executes docker/podman commands
type CommandRunner interface {
	Run(args ...string) (string, error)
}

func (n Name) String() string {
	return string(n)
}

var infraProvider api.Provider

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
