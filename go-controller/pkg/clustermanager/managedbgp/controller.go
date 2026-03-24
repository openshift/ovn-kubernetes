package managedbgp

import (
	"context"
	"fmt"
	"hash/fnv"
	"reflect"
	"sort"

	frrtypes "github.com/metallb/frr-k8s/api/v1beta1"
	frrclientset "github.com/metallb/frr-k8s/pkg/client/clientset/versioned"
	frrlisters "github.com/metallb/frr-k8s/pkg/client/listers/api/v1beta1"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	controllerutil "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	ratypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1"
	raclientset "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1/apis/clientset/versioned"
	ralisters "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1/apis/listers/routeadvertisements/v1"
	apitypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

const (
	// ControllerName is the name of the managed BGP controller
	ControllerName = "managed-bgp-controller"
	// fieldManager identifies writes performed by this controller.
	fieldManager = "clustermanager-managedbgp-controller"
	// FRRConfigManagedLabel is the label used to identify FRRConfigurations managed by this controller
	FRRConfigManagedLabel = "k8s.ovn.org/managed-internal-fabric"
	// FRRConfigManagedValue is the value used for the FRRConfigManagedLabel
	FRRConfigManagedValue = "bgp"
	// ManagedRANetworkLabel is the label set on managed RouteAdvertisements to identify the network they advertise
	ManagedRANetworkLabel = "k8s.ovn.org/managed-network"
	// managedNamePrefix is the prefix for managed resource names
	managedNamePrefix = "ovnk-managed-"
)

func managedHashedName(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%s%x", managedNamePrefix, h.Sum64())
}

// ManagedRouteAdvertisementName returns the name of the managed RouteAdvertisement
// for the given network name. The name follows the pattern "ovnk-managed-<hash>"
// where <hash> is derived from the network name.
func ManagedRouteAdvertisementName(networkName string) string {
	return managedHashedName(networkName)
}

// BaseFRRConfigName returns the name of the base FRRConfiguration that
// configures the cluster internal BGP fabric. This FRRConfiguration is shared
// by all networks in managed routing mode. The name follows the pattern
// "ovnk-managed-<hash>" where <hash> is derived from the configured AS number.
func BaseFRRConfigName() string {
	return managedHashedName(fmt.Sprintf("%d", config.ManagedBGP.ASNumber))
}

// Controller manages the BGP topology for no-overlay networks with managed routing
type Controller struct {
	frrClient            frrclientset.Interface
	frrLister            frrlisters.FRRConfigurationLister
	raClient             raclientset.Interface
	raLister             ralisters.RouteAdvertisementsLister
	nodeController       controllerutil.Controller
	managedRAController  controllerutil.Controller
	managedFRRController controllerutil.Controller
	wf                   *factory.WatchFactory
	recorder             record.EventRecorder
}

// NewController creates a new managed BGP controller
func NewController(
	wf *factory.WatchFactory,
	frrClient frrclientset.Interface,
	raClient raclientset.Interface,
	recorder record.EventRecorder,
) *Controller {
	c := &Controller{
		frrClient: frrClient,
		frrLister: wf.FRRConfigurationsInformer().Lister(),
		raClient:  raClient,
		raLister:  wf.RouteAdvertisementsInformer().Lister(),
		wf:        wf,
		recorder:  recorder,
	}

	nodeConfig := &controllerutil.ControllerConfig[corev1.Node]{
		RateLimiter:    workqueue.DefaultTypedControllerRateLimiter[string](),
		Reconcile:      c.reconcileNode,
		Threadiness:    1,
		Informer:       wf.NodeCoreInformer().Informer(),
		Lister:         wf.NodeCoreInformer().Lister().List,
		ObjNeedsUpdate: c.nodeNeedsUpdate,
	}
	c.nodeController = controllerutil.NewController(ControllerName, nodeConfig)

	managedRAConfig := &controllerutil.ControllerConfig[ratypes.RouteAdvertisements]{
		RateLimiter:    workqueue.DefaultTypedControllerRateLimiter[string](),
		Reconcile:      c.reconcileManagedRouteAdvertisement,
		Threadiness:    1,
		Informer:       wf.RouteAdvertisementsInformer().Informer(),
		Lister:         wf.RouteAdvertisementsInformer().Lister().List,
		ObjNeedsUpdate: c.managedRANeedsUpdate,
	}
	c.managedRAController = controllerutil.NewController(ControllerName+"-routeadvertisement", managedRAConfig)

	managedFRRConfig := &controllerutil.ControllerConfig[frrtypes.FRRConfiguration]{
		RateLimiter:    workqueue.DefaultTypedControllerRateLimiter[string](),
		Reconcile:      c.reconcileManagedFRRConfiguration,
		Threadiness:    1,
		Informer:       wf.FRRConfigurationsInformer().Informer(),
		Lister:         wf.FRRConfigurationsInformer().Lister().List,
		ObjNeedsUpdate: c.managedFRRConfigNeedsUpdate,
	}
	c.managedFRRController = controllerutil.NewController(ControllerName+"-frrconfiguration", managedFRRConfig)

	return c
}

// Start starts the managed BGP controller.
// If managed routing mode is not active, it cleans up any previously created
// managed resources and returns without starting the controllers.
func (c *Controller) Start() error {
	klog.Infof("Starting managed BGP controller")

	if config.Default.Transport != types.NetworkTransportNoOverlay || config.NoOverlay.Routing != config.NoOverlayRoutingManaged {
		klog.Infof("Managed routing mode is not active, cleaning up any stale managed resources")
		return c.cleanupManagedResources()
	}

	return controllerutil.StartWithInitialSync(c.ensureManagedResources, c.nodeController, c.managedRAController, c.managedFRRController)
}

// Stop stops the managed BGP controller
func (c *Controller) Stop() {
	klog.Infof("Stopping managed BGP controller")
	controllerutil.Stop(c.nodeController, c.managedRAController, c.managedFRRController)
}

func (c *Controller) nodeNeedsUpdate(oldNode, newNode *corev1.Node) bool {
	if oldNode == nil || newNode == nil {
		return true
	}
	// We care about node IP changes
	oldV4, oldV6 := util.GetNodeInternalAddrs(oldNode)
	newV4, newV6 := util.GetNodeInternalAddrs(newNode)
	return !reflect.DeepEqual(oldV4, newV4) || !reflect.DeepEqual(oldV6, newV6)
}

func (c *Controller) managedRANeedsUpdate(oldRA, newRA *ratypes.RouteAdvertisements) bool {
	if newRA == nil || newRA.Name != c.defaultManagedRAName() {
		return false
	}
	if isOwnUpdate(newRA.ManagedFields) {
		return false
	}
	if oldRA == nil {
		return true
	}
	return !reflect.DeepEqual(oldRA.Spec, newRA.Spec) || !reflect.DeepEqual(oldRA.Labels, newRA.Labels)
}

func (c *Controller) managedFRRConfigNeedsUpdate(oldConfig, newConfig *frrtypes.FRRConfiguration) bool {
	if newConfig == nil || newConfig.Namespace != config.ManagedBGP.FRRNamespace || newConfig.Name != BaseFRRConfigName() {
		return false
	}
	if isOwnUpdate(newConfig.ManagedFields) {
		return false
	}
	if oldConfig == nil {
		return true
	}
	return !reflect.DeepEqual(oldConfig.Spec, newConfig.Spec) || !reflect.DeepEqual(oldConfig.Labels, newConfig.Labels)
}

func isOwnUpdate(managedFields []metav1.ManagedFieldsEntry) bool {
	return util.IsLastUpdatedByManager(fieldManager, managedFields)
}

func (c *Controller) reconcileManagedRouteAdvertisement(key string) error {
	if key != c.defaultManagedRAName() {
		return nil
	}
	if err := c.ensureManagedRouteAdvertisement(types.DefaultNetworkName); err != nil {
		return fmt.Errorf("failed to ensure managed RouteAdvertisement: %w", err)
	}
	return nil
}

func (c *Controller) reconcileManagedFRRConfiguration(key string) error {
	if key != c.managedBaseFRRConfigKey() {
		return nil
	}
	return c.ensureManagedBaseFRRConfiguration()
}

func (c *Controller) defaultManagedRAName() string {
	return ManagedRouteAdvertisementName(types.DefaultNetworkName)
}

func (c *Controller) managedBaseFRRConfigKey() string {
	return fmt.Sprintf("%s/%s", config.ManagedBGP.FRRNamespace, BaseFRRConfigName())
}

func (c *Controller) ensureManagedResources() error {
	if err := c.ensureManagedRouteAdvertisement(types.DefaultNetworkName); err != nil {
		return fmt.Errorf("failed to ensure managed RouteAdvertisement: %w", err)
	}

	return c.ensureManagedBaseFRRConfiguration()
}

func (c *Controller) reconcileNode(_ string) error {
	return c.ensureManagedResources()
}

func (c *Controller) ensureManagedBaseFRRConfiguration() error {
	if config.ManagedBGP.Topology != config.ManagedBGPTopologyFullMesh {
		return fmt.Errorf("unsupported managed BGP topology: %s", config.ManagedBGP.Topology)
	}

	nodes, err := c.wf.GetNodes()
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	// For full-mesh, we ensure there is a single base FRRConfiguration peering with all nodes.
	// The RouteAdvertisements controller will then generate per-node configs based on this,
	// excluding self-peering.
	if err := c.ensureBaseFRRConfiguration(nodes); err != nil {
		klog.Errorf("Failed to ensure base FRRConfiguration: %v", err)
		return err
	}

	return nil
}

// ensureBaseFRRConfiguration creates or updates the base FRRConfiguration
// for iBGP full-mesh peering between all cluster nodes.
func (c *Controller) ensureBaseFRRConfiguration(allNodes []*corev1.Node) error {
	neighbors := []frrtypes.Neighbor{}
	for _, node := range allNodes {
		v4, v6 := util.GetNodeInternalAddrs(node)
		if v4 != nil {
			neighbors = append(neighbors, frrtypes.Neighbor{
				Address:   v4.String(),
				ASN:       config.ManagedBGP.ASNumber,
				DisableMP: true,
			})
		}
		if v6 != nil {
			neighbors = append(neighbors, frrtypes.Neighbor{
				Address:   v6.String(),
				ASN:       config.ManagedBGP.ASNumber,
				DisableMP: true,
			})
		}
	}

	sort.Slice(neighbors, func(i, j int) bool {
		return neighbors[i].Address < neighbors[j].Address
	})

	baseName := BaseFRRConfigName()
	if err := c.cleanupStaleFRRConfigurations(baseName); err != nil {
		return err
	}

	frrConfig := &frrtypes.FRRConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baseName,
			Namespace: config.ManagedBGP.FRRNamespace,
			Labels: map[string]string{
				FRRConfigManagedLabel: FRRConfigManagedValue,
			},
		},
		Spec: frrtypes.FRRConfigurationSpec{
			// Empty NodeSelector means it applies as a base for all nodes by RouteAdvertisements controller
			NodeSelector: metav1.LabelSelector{},
			BGP: frrtypes.BGPConfig{
				Routers: []frrtypes.Router{
					{
						ASN:       config.ManagedBGP.ASNumber,
						Neighbors: neighbors,
					},
				},
			},
		},
	}

	existing, err := c.frrClient.ApiV1beta1().FRRConfigurations(config.ManagedBGP.FRRNamespace).Get(context.TODO(), baseName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.Infof("Creating base FRRConfiguration %s", baseName)
			_, err = c.frrClient.ApiV1beta1().FRRConfigurations(config.ManagedBGP.FRRNamespace).Create(context.TODO(), frrConfig, metav1.CreateOptions{
				FieldManager: fieldManager,
			})
			if err != nil && !apierrors.IsAlreadyExists(err) {
				return err
			}
			return nil
		}
		return err
	}

	needsUpdate := !reflect.DeepEqual(existing.Spec, frrConfig.Spec) ||
		existing.Labels[FRRConfigManagedLabel] != FRRConfigManagedValue
	if needsUpdate {
		klog.Infof("Updating base FRRConfiguration %s", baseName)
		updated := existing.DeepCopy()
		if updated.Labels == nil {
			updated.Labels = map[string]string{}
		}
		updated.Labels[FRRConfigManagedLabel] = FRRConfigManagedValue
		updated.Spec = frrConfig.Spec
		_, err = c.frrClient.ApiV1beta1().FRRConfigurations(config.ManagedBGP.FRRNamespace).Update(context.TODO(), updated, metav1.UpdateOptions{
			FieldManager: fieldManager,
		})
		return err
	}

	return nil
}

// cleanupStaleFRRConfigurations removes any FRRConfigurations with the managed label
// whose name doesn't match the current base name (e.g. after an AS number change).
func (c *Controller) cleanupStaleFRRConfigurations(currentBaseName string) error {
	managedConfigs, err := c.frrLister.FRRConfigurations(config.ManagedBGP.FRRNamespace).List(
		labels.SelectorFromSet(labels.Set{FRRConfigManagedLabel: FRRConfigManagedValue}),
	)
	if err != nil {
		return err
	}
	for _, cfg := range managedConfigs {
		if cfg.Name == currentBaseName {
			continue
		}
		if err := c.frrClient.ApiV1beta1().FRRConfigurations(config.ManagedBGP.FRRNamespace).Delete(
			context.TODO(), cfg.Name, metav1.DeleteOptions{},
		); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete stale FRRConfiguration %s: %w", cfg.Name, err)
		}
	}
	return nil
}

// ensureManagedRouteAdvertisement ensures that the managed RouteAdvertisement for the given
// network exists with the correct spec. It selects the base FRRConfiguration and advertises
// pod networks for the specified network.
func (c *Controller) ensureManagedRouteAdvertisement(networkName string) error {
	var netSelector apitypes.NetworkSelectors
	if networkName == types.DefaultNetworkName {
		if config.Default.Transport != types.NetworkTransportNoOverlay || config.NoOverlay.Routing != config.NoOverlayRoutingManaged {
			return nil
		}
		netSelector = apitypes.NetworkSelectors{{NetworkSelectionType: apitypes.DefaultNetwork}}
	} else {
		// CUDN: build a selector that matches the CUDN by the managed network label
		netSelector = apitypes.NetworkSelectors{{
			NetworkSelectionType: apitypes.ClusterUserDefinedNetworks,
			ClusterUserDefinedNetworkSelector: &apitypes.ClusterUserDefinedNetworkSelector{
				NetworkSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						ManagedRANetworkLabel: networkName,
					},
				},
			},
		}}
	}

	raName := ManagedRouteAdvertisementName(networkName)
	ra := &ratypes.RouteAdvertisements{
		ObjectMeta: metav1.ObjectMeta{
			Name: raName,
			Labels: map[string]string{
				ManagedRANetworkLabel: networkName,
			},
		},
		Spec: ratypes.RouteAdvertisementsSpec{
			NetworkSelectors: netSelector,
			Advertisements: []ratypes.AdvertisementType{
				ratypes.PodNetwork,
			},
			FRRConfigurationSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					FRRConfigManagedLabel: FRRConfigManagedValue,
				},
			},
			// nodeSelector must select all nodes for PodNetwork
			NodeSelector: metav1.LabelSelector{},
		},
	}

	existing, err := c.raLister.Get(raName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.Infof("Creating managed RouteAdvertisement %s for network %s", raName, networkName)
			_, err = c.raClient.K8sV1().RouteAdvertisements().Create(context.TODO(), ra, metav1.CreateOptions{
				FieldManager: fieldManager,
			})
			if err != nil && !apierrors.IsAlreadyExists(err) {
				return err
			}
			return nil
		}
		return err
	}

	needsUpdate := !reflect.DeepEqual(existing.Spec, ra.Spec) ||
		existing.Labels[ManagedRANetworkLabel] != networkName
	if needsUpdate {
		klog.Infof("Updating managed RouteAdvertisement %s for network %s", raName, networkName)
		updated := existing.DeepCopy()
		if updated.Labels == nil {
			updated.Labels = map[string]string{}
		}
		updated.Labels[ManagedRANetworkLabel] = networkName
		updated.Spec = ra.Spec
		_, err = c.raClient.K8sV1().RouteAdvertisements().Update(context.TODO(), updated, metav1.UpdateOptions{
			FieldManager: fieldManager,
		})
		return err
	}

	return nil
}

// cleanupManagedResources removes the default network's managed RouteAdvertisement
// and the base FRRConfiguration (if no other RA still selects it).
func (c *Controller) cleanupManagedResources() error {
	// Delete the default network's managed RouteAdvertisement
	raName := ManagedRouteAdvertisementName(types.DefaultNetworkName)
	err := c.raClient.K8sV1().RouteAdvertisements().Delete(context.TODO(), raName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete managed RouteAdvertisement %s: %w", raName, err)
	}

	// Delete the base FRRConfiguration if no remaining RA selects it.
	// Other CUDNs in managed mode may still reference it.
	managedConfigs, err := c.frrLister.FRRConfigurations(config.ManagedBGP.FRRNamespace).List(
		labels.SelectorFromSet(labels.Set{FRRConfigManagedLabel: FRRConfigManagedValue}),
	)
	if err != nil {
		return err
	}
	if len(managedConfigs) == 0 {
		return nil
	}

	// If any other managed RA exists (e.g. CUDN), keep the base FRRConfiguration.
	managedRAReq, _ := labels.NewRequirement(ManagedRANetworkLabel, selection.Exists, nil)
	nonDefaultReq, _ := labels.NewRequirement(ManagedRANetworkLabel, selection.NotEquals, []string{types.DefaultNetworkName})
	remainingManagedRAs, err := c.raLister.List(labels.NewSelector().Add(*managedRAReq, *nonDefaultReq))
	if err != nil {
		return fmt.Errorf("failed to list RouteAdvertisements: %w", err)
	}
	if len(remainingManagedRAs) > 0 {
		klog.Infof("Base FRRConfiguration still in use by %d managed RouteAdvertisement(s), skipping deletion", len(remainingManagedRAs))
		return nil
	}

	for _, cfg := range managedConfigs {
		klog.Infof("Deleting managed base FRRConfiguration %s", cfg.Name)
		if err := c.frrClient.ApiV1beta1().FRRConfigurations(config.ManagedBGP.FRRNamespace).Delete(
			context.TODO(), cfg.Name, metav1.DeleteOptions{},
		); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete base FRRConfiguration %s: %w", cfg.Name, err)
		}
	}

	return nil
}
