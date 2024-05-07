package ovnwebhook

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/exp/maps"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	listers "k8s.io/client-go/listers/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// checkPodAnnot defines additional checks for the allowed annotations
type checkPodAnnot func(nodeLister listers.NodeLister, v annotationChange, pod *corev1.Pod, nodeName string) error

// PodAdmissionConditionOptions specifies additional validate admission for pod.
type PodAdmissionConditionOption struct {
	// CommonNamePrefix specifies common name in Usename
	CommonNamePrefix string `json:"commonNamePrefix"`
	// AllowedPodAnnotations contains annotation list to check Pod's annotation for webhook
	// this is used for Defaut=false because ovn-node case requires more detailed pod annotation
	// check
	AllowedPodAnnotations []string `json:"allowedPodAnnotations"`
	// AllowedPodAnnotationKeys contains AllowedPodAnnotations value as sets.Set[]
	AllowedPodAnnotationKeys sets.Set[string]
}

// InitPodAdmissionConditionOptions initializes PodAdmissionConditionOption: Load json from fileName
func InitPodAdmissionConditionOptions(fileName string) (podAdmissions []PodAdmissionConditionOption, err error) {
	if fileName != "" {
		file, err := os.ReadFile(fileName)
		if err != nil {
			return nil, err
		}

		if err = json.Unmarshal(file, &podAdmissions); err != nil {
			return nil, err
		}
	}

	// initialize Sets from slices
	for i, v := range podAdmissions {
		podAdmissions[i].AllowedPodAnnotationKeys = sets.New[string](v.AllowedPodAnnotations...)
	}

	return podAdmissions, nil
}

type PodAdmission struct {
	extraAllowedUsers sets.Set[string]
	podAdmissions     []PodAdmissionConditionOption
}

func NewPodAdmissionWebhook(podAdmissions []PodAdmissionConditionOption, extraAllowedUsers ...string) *PodAdmission {
	return &PodAdmission{
		extraAllowedUsers: sets.New[string](extraAllowedUsers...),
		podAdmissions:     podAdmissions,
	}
}

func (p PodAdmission) ValidateCreate(ctx context.Context, obj runtime.Object) (err error) {
	// Ignore creation, the webhook is configured to only handle pod/status updates
	return nil
}

func (p PodAdmission) ValidateDelete(_ context.Context, _ runtime.Object) (err error) {
	// Ignore creation, the webhook is configured to only handle pod/status updates
	return nil
}

var _ admission.CustomValidator = &PodAdmission{}

func (p PodAdmission) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (err error) {
	oldPod := oldObj.(*corev1.Pod)
	newPod := newObj.(*corev1.Pod)

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return err
	}
	_, podAdmission, nodeName := checkNodeIdentity(p.podAdmissions, req.UserInfo)

	changes := mapDiff(oldPod.Annotations, newPod.Annotations)
	changedKeys := maps.Keys(changes)

	// user is in additional acceptance condition list
	if podAdmission != nil {
		// additional acceptance condition check
		if !podAdmission.AllowedPodAnnotationKeys.HasAll(changedKeys...) {
			return fmt.Errorf("%s node: %q is not allowed to set the following annotations on pod: %q: %v", podAdmission.CommonNamePrefix, nodeName, newPod.Name, sets.New[string](changedKeys...).Difference(podAdmission.AllowedPodAnnotationKeys).UnsortedList())
		}
	}

	// if there is no matched acceptanceCondition as well as ovnkube-node, then skip following check
	if podAdmission == nil {
		return nil
	}

	prefixName := podAdmission.CommonNamePrefix

	if oldPod.Spec.NodeName != nodeName {
		return fmt.Errorf("%s on node: %q is not allowed to modify pods %q annotations", prefixName, nodeName, oldPod.Name)
	}
	if newPod.Spec.NodeName != nodeName {
		return fmt.Errorf("%s on node: %q is not allowed to modify pods %q annotations", prefixName, nodeName, newPod.Name)
	}

	// Verify that nothing but the annotations changed.
	// Since ovnkube-node only has the pod/status permissions, it is enough to check .Status and .ObjectMeta only.
	// Ignore .ManagedFields fields which are modified on every update.
	oldPodShallowCopy := oldPod
	newPodShallowCopy := newPod
	oldPodShallowCopy.Annotations = nil
	newPodShallowCopy.Annotations = nil
	oldPodShallowCopy.ManagedFields = nil
	newPodShallowCopy.ManagedFields = nil
	if !apiequality.Semantic.DeepEqual(oldPodShallowCopy.ObjectMeta, newPodShallowCopy.ObjectMeta) ||
		!apiequality.Semantic.DeepEqual(oldPodShallowCopy.Status, newPodShallowCopy.Status) {
		return fmt.Errorf("%s on node: %q is not allowed to modify anything other than annotations", prefixName, nodeName)
	}

	return nil
}
