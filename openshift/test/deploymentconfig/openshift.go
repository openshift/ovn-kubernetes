package deploymentconfig

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var deploymentConfig api.DeploymentConfig

func init() {
	deploymentConfig = openshift{}
	deploymentconfig.Set(deploymentConfig)
}

func IsOpenShift(config *rest.Config) (bool, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	// Check for OpenShift-specific API groups
	groups, err := kubeClient.Discovery().ServerGroups()
	if err != nil {
		return false, fmt.Errorf("failed to get server groups: %w", err)
	}
	for _, group := range groups.Groups {
		if strings.HasSuffix(group.Name, ".openshift.io") {
			return true, nil
		}
	}
	return false, nil
}

type openshift struct{}

func New() api.DeploymentConfig {
	return deploymentConfig
}

func (m openshift) OVNKubernetesNamespace() string {
	return "openshift-ovn-kubernetes"
}

func (m openshift) FRRK8sNamespace() string {
	return "openshift-frr-k8s"
}

func (m openshift) ExternalBridgeName() string {
	return "br-ex"
}

// primaryInterfaceEnvVar overrides the discovered primary interface name. Set it
// when the uplink cannot be derived from the external bridge, for example on a
// deployment that does not manage br-ex with OVS.
const primaryInterfaceEnvVar = "OVN_TEST_PRIMARY_INTERFACE"

// fallbackPrimaryInterfaceName is the interface name used by the baremetalds CI
// environment, kept as a last resort when discovery fails.
const fallbackPrimaryInterfaceName = "enp0s3"

var (
	primaryInterfaceOnce sync.Once
	primaryInterfaceName string
)

// PrimaryInterfaceName returns the node uplink enslaved to the external bridge.
// Tests such as the no-overlay ones capture on it to prove that pod traffic
// leaves the node unencapsulated, so it has to be the physical NIC rather than
// the br-ex internal port, which only sees traffic to and from the local stack.
func (m openshift) PrimaryInterfaceName() string {
	primaryInterfaceOnce.Do(func() {
		if name := os.Getenv(primaryInterfaceEnvVar); name != "" {
			primaryInterfaceName = name
			return
		}
		name, err := discoverPrimaryInterfaceName()
		if err != nil {
			framework.Logf("Failed to discover the primary interface name, falling back to %q: %v",
				fallbackPrimaryInterfaceName, err)
			primaryInterfaceName = fallbackPrimaryInterfaceName
			return
		}
		framework.Logf("Discovered primary interface name %q", name)
		primaryInterfaceName = name
	})
	return primaryInterfaceName
}

// discoverPrimaryInterfaceName resolves the uplink of the external bridge the
// same way ovn-kubernetes itself does: prefer the bridge-uplink external-id that
// NicToBridge() records, and otherwise fall back to the bridge's only physical
// port. ovs-vsctl reports an empty type for a plain physical port, while
// NetworkManager sets it to "system" explicitly, so both are accepted.
func discoverPrimaryInterfaceName() (string, error) {
	bridge := deploymentConfig.ExternalBridgeName()
	cmd := fmt.Sprintf(`set -e
uplink=$(ovs-vsctl --timeout=15 br-get-external-id %[1]s bridge-uplink 2>/dev/null || true)
if [ -n "$uplink" ]; then echo "$uplink"; exit 0; fi
for port in $(ovs-vsctl --timeout=15 list-ports %[1]s); do
  type=$(ovs-vsctl --timeout=15 --if-exists get Interface "$port" type)
  if [ "$type" = '""' ] || [ "$type" = "system" ]; then echo "$port"; exit 0; fi
done
exit 1`, bridge)

	config, err := framework.LoadConfig()
	if err != nil {
		return "", fmt.Errorf("failed to load cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	namespace := deploymentConfig.OVNKubernetesNamespace()
	pods, err := client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: "app=ovnkube-node",
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return "", fmt.Errorf("failed to list ovnkube-node pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no running ovnkube-node pod found in namespace %s", namespace)
	}
	pod := pods.Items[0]
	out, err := e2epodoutput.RunHostCmd(pod.Namespace, pod.Name, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to resolve the uplink of bridge %s from pod %s/%s: %w",
			bridge, pod.Namespace, pod.Name, err)
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return "", fmt.Errorf("bridge %s reported an empty uplink", bridge)
	}
	return name, nil
}

func (m openshift) GetAgnHostContainerImage() string {
	// use downloadable image for external container.
	// ref: https://github.com/openshift/release/blob/db6697de61f4ae7e05c5a2db782a87c459e849bf/ci-operator/step-registry/baremetalds/e2e/ovn/bgp/pre/baremetalds-e2e-ovn-bgp-pre-commands.sh#L197
	return "registry.k8s.io/e2e-test-images/agnhost:2.40"
}

func (m openshift) IsConfigurationEnabled(config api.Config) bool {
	return false
}

func (m openshift) NBDBContainerName() string {
	return "nbdb"
}
