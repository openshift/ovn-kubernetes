package deploymentconfig

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig/api"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig/configs/kind"
)

var deployment api.DeploymentConfig

// SetDeployment injects a deployment config. Used by the OpenShift tests
// extension, which must set it before e2e BeforeSuite runs.
func SetDeployment(d api.DeploymentConfig) {
	deployment = d
}

func Set() {
	if deployment != nil {
		return
	}
	// upstream currently uses KinD as its preferred platform infra, so if we detect KinD, its upstream
	if kind.IsKind() {
		deployment = kind.New()
	}
	if deployment == nil {
		panic("failed to determine the deployment config")
	}
}

func Get() api.DeploymentConfig {
	if deployment == nil {
		panic("deployment config type not set")
	}
	return deployment
}
