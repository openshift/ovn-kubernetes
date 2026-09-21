package deploymentconfig

import (
	"context"
	"fmt"
	"strings"
	"time"

	ovnkconfig "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	gcfg "gopkg.in/gcfg.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
)

func (m *openshift) preconfiguredUDNAddressesEnabled() (bool, error) {
	client := m.configClient
	if client == nil {
		config, err := framework.LoadConfig()
		if err != nil {
			return false, err
		}
		client, err = kubernetes.NewForConfig(config)
		if err != nil {
			return false, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cm, err := client.CoreV1().ConfigMaps(m.OVNKubernetesNamespace()).Get(ctx, "ovnkube-config", metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("read OVN feature configuration: %w", err)
	}
	contents, ok := cm.Data["ovnkube.conf"]
	if !ok {
		return false, fmt.Errorf("ovnkube-config is missing ovnkube.conf")
	}
	// Read the same configuration format as ovnkube rather than assuming
	// OpenShift renders the Kind-specific DaemonSet environment variable.
	var config struct {
		OVNKubernetesFeature ovnkconfig.OVNKubernetesFeatureConfig
	}
	if err := gcfg.FatalOnly(gcfg.ReadInto(&config, strings.NewReader(contents))); err != nil {
		return false, fmt.Errorf("parse ovnkube.conf: %w", err)
	}
	return config.OVNKubernetesFeature.EnablePreconfiguredUDNAddresses, nil
}
