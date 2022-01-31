package services

import (
	"encoding/json"

	v1 "k8s.io/api/core/v1"
)

// isImplicitDualStackIpFamilyPolicy checks if the service implicitly sets ipFamilyPolicy for DualStack services.
// This is deprecated in 4.8 and 4.9 as admins must set ipFamilyPolicy explicitly in 4.10 and beyond.
// Note that this will only work with K8s v1.22 and v1.21 as earlier versions set the f:ipFamilyPolicy
// field even if the client had ommitted it.
func isImplicitDualStackIpFamilyPolicy(service *v1.Service) bool {
	// return false if this is not a DualStack Service
	if len(service.Spec.ClusterIPs) < 2 && len(service.Spec.IPFamilies) < 2 {
		return false
	}

	// check if any of the managedFieldEntries contains "f:ipFamilyPolicy". We'd ideally use
	// https://github.com/kubernetes/apiserver/blob/v0.21.0/pkg/endpoints/handlers/fieldmanager/fieldmanager.go#L115
	// but that's only available with apiserver v0.21.0 and beyond, and OCP 4.9 and 4.8 are on v0.20.0
	// for a lot of dependencies. So, using that library creates a lot of dependency issues
	managedFieldEntries := service.GetManagedFields()

	for _, entry := range managedFieldEntries {
		// fallback, continue if FieldsV1 is not set
		if entry.FieldsV1 == nil {
			continue
		}

		var fieldsV1Map map[string]interface{}
		err := json.Unmarshal(entry.FieldsV1.Raw, &fieldsV1Map)
		// fallback, continue if we cannot decode
		if err != nil {
			continue
		}
		// fallback, continue if key "f:spec" is not set
		// fallback, continue if "f:spec" is set but is nil
		fspec, ok := fieldsV1Map["f:spec"]
		if !ok || fspec == nil {
			continue
		}
		// fallback, continue if "f:spec" is set, is not nil but is not a map with string keys
		fspecMap, ok := fspec.(map[string]interface{})
		if !ok {
			continue
		}
		// If this service definition contains an explicit ipFamilyPolicy, return false
		if _, ok := fspecMap["f:ipFamilyPolicy"]; ok {
			return false
		}
	}

	// This service set field ipFamilyPolicy implicitly if
	//     (len(service.Spec.ClusterIPs) == 2 || len(service.Spec.IpFamilies) == 2)
	//         and "f:ipFamilyPolicy"
	// is not set for any of the managedFieldEntries
	return true
}
