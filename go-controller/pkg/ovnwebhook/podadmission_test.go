package ovnwebhook

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	admv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type fakeNodeLister struct {
	nodes map[string]*corev1.Node
}

func (f *fakeNodeLister) List(selector labels.Selector) (ret []*corev1.Node, err error) {
	panic("implement me")
}

func (f *fakeNodeLister) Get(name string) (*corev1.Node, error) {
	node, ok := f.nodes[name]
	if !ok {
		return nil, fmt.Errorf("nodr %q not found", name)
	}
	return node, nil
}

var _ listersv1.NodeLister = &fakeNodeLister{}

const podName = "testpod"

func TestPodAdmission_ValidateUpdate(t *testing.T) {
	tests := []struct {
		name        string
		node        *corev1.Node
		ctx         context.Context
		oldObj      runtime.Object
		newObj      runtime.Object
		expectedErr error
	}{
		{
			name: "error out if the request is not in context",
			node: &corev1.Node{},
			ctx:  context.TODO(),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: podName,
				},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{"new": "value"},
				},
			},
			expectedErr: errors.New("admission.Request not found in context"),
		},
		// additional acceptance conditions
		{
			name: "additonal acceptance conditions valid",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
				},
			},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: admv1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: additionalUserName,
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{"pod-annotation-valid1": "old"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{"pod-annotation-valid1": "new"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
		},
		{
			name: "additonal acceptance conditions invalid",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
				},
			},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: admv1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: additionalUserName,
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{"pod-annotation-invalid1": "old"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{"pod-annotation-invalid1": "new"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			expectedErr: fmt.Errorf("%s node: %q is not allowed to set the following annotations on pod: \"testpod\": [pod-annotation-invalid1]", additionalNamePrefix, nodeName),
		},
	}

	allowedPodAnnotations := []string{"pod-annotation-valid1"}
	additionalPodAdmissions := PodAdmissionConditionOption{
		CommonNamePrefix:         additionalNamePrefix,
		AllowedPodAnnotations:    allowedPodAnnotations,
		AllowedPodAnnotationKeys: sets.New[string](allowedPodAnnotations...),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padm := NewPodAdmissionWebhook(
				[]PodAdmissionConditionOption{
					additionalPodAdmissions,
				})
			err := padm.ValidateUpdate(tt.ctx, tt.oldObj, tt.newObj)
			if !reflect.DeepEqual(err, tt.expectedErr) {
				t.Errorf("ValidateUpdate() error = %v, expectedErr %v", err, tt.expectedErr)
				return
			}
		})
	}
}
