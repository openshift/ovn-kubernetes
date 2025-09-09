package deploymentconfig

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig/api"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig/configs/kind"

	"k8s.io/client-go/rest"
)

var Deployment api.DeploymentConfig

func Set(_ *rest.Config) error {
	// upstream currently uses KinD as its preferred platform infra, so if we detect KinD, its upstream
	if kind.IsKind() {
		Deployment = kind.New()
	}
	if Deployment == nil {
		return fmt.Errorf("failed to determine the deployment config")
	}
	return nil
}

func Get() api.DeploymentConfig {
	if Deployment == nil {
		panic("deployment config type not set")
	}
	return Deployment
}
