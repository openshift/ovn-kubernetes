package kubevirt

// AllowPodBridgeNetworkLiveMigration will return true if the pod belongs
// to kubevirt and should use the live migration features
func AllowPodBridgeNetworkLiveMigration(annotations map[string]string) bool {
	_, ok := annotations[AllowPodBridgeNetworkLiveMigrationAnnotation]
	return ok
}
