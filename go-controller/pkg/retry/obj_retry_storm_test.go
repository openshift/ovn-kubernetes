// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package retry

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// alwaysFailHandler is a mock EventHandler where AddResource always returns
// an error, simulating the "invalid primary network state" condition seen
// during UDN namespace teardown.
type alwaysFailHandler struct {
	DefaultEventHandler

	obj      interface{}
	addCalls int
	addErr   error
}

func (h *alwaysFailHandler) AddResource(_ interface{}, _ bool) error {
	h.addCalls++
	return h.addErr
}

func (h *alwaysFailHandler) UpdateResource(_, _ interface{}, _ bool) error {
	return nil
}

func (h *alwaysFailHandler) DeleteResource(_, _ interface{}) error {
	return nil
}

func (h *alwaysFailHandler) GetResourceFromInformerCache(_ string) (interface{}, error) {
	return h.obj, nil
}

func (h *alwaysFailHandler) FilterOutResource(_ interface{}) bool {
	return false
}

func newTestFramework(handler *alwaysFailHandler) *RetryFramework {
	return NewRetryFramework(
		"test",
		make(chan struct{}),
		&sync.WaitGroup{},
		nil,
		&ResourceHandler{
			HasUpdateFunc:          false,
			NeedsUpdateDuringRetry: false,
			ObjType:                reflect.TypeOf(&corev1.Service{}),
			EventHandler:           handler,
		},
	)
}

func newTestService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc",
			Namespace: "test-ns",
		},
	}
}

// TestFailedAttemptsPreservedOnReAdd verifies that when an informer update
// event fires for a service that is already failing, initRetryObjWithAdd
// preserves the existing failedAttempts counter. The entry is correctly
// dropped after MaxFailedAttempts even with update events between retries.
func TestFailedAttemptsPreservedOnReAdd(t *testing.T) {
	svc := newTestService()
	handler := &alwaysFailHandler{
		obj: svc,
		addErr: fmt.Errorf("invalid primary network state for namespace %q: "+
			"a valid primary user defined network or network attachment definition "+
			"custom resource, and required namespace label must both be present",
			svc.Namespace),
	}
	rf := newTestFramework(handler)
	key := "test-ns/test-svc"

	// Seed the retry entry (simulates initial add event).
	rf.DoWithLock(key, func(k string) {
		rf.initRetryObjWithAddBackoff(svc, k, noBackoff)
	})

	// Run one retry cycle — AddResource fails, failedAttempts should be 1.
	rf.resourceRetry(key, time.Now())

	entry, found := GetRetryObj(key, rf)
	if !found {
		t.Fatal("retry entry should exist after first failed attempt")
	}
	if entry.failedAttempts != 1 {
		t.Fatalf("expected failedAttempts=1 after first retry, got %d", entry.failedAttempts)
	}

	// Simulate an informer update event: initRetryObjWithAdd must preserve
	// failedAttempts for an already-existing entry.
	rf.DoWithLock(key, func(k string) {
		rf.initRetryObjWithAdd(svc, k)
	})

	entry, _ = GetRetryObj(key, rf)
	if entry.failedAttempts != 1 {
		t.Fatalf("expected failedAttempts=1 preserved after re-add, got %d",
			entry.failedAttempts)
	}

	// Simulate retry + update event cycles past MaxFailedAttempts.
	// The entry should be dropped once MaxFailedAttempts is reached.
	for i := 1; i < MaxFailedAttempts+5; i++ {
		if !CheckRetryObj(key, rf) {
			t.Logf("Fix confirmed: entry dropped after %d total failed attempts "+
				"(MaxFailedAttempts=%d) despite update events between retries",
				i, MaxFailedAttempts)
			return
		}
		SetRetryObjWithNoBackoff(key, rf)
		rf.resourceRetry(key, time.Now())

		// Simulate update event between retry sweeps.
		if CheckRetryObj(key, rf) {
			rf.DoWithLock(key, func(k string) {
				rf.initRetryObjWithAdd(svc, k)
			})
		}
	}

	if CheckRetryObj(key, rf) {
		t.Fatalf("entry should have been dropped after MaxFailedAttempts=%d "+
			"even with update events between retries", MaxFailedAttempts)
	}
}

// TestFailedAttemptsNotResetReachesMax is the control case: without update
// events resetting the counter, MaxFailedAttempts is reached and the entry
// is correctly dropped from the retry cache.
func TestFailedAttemptsNotResetReachesMax(t *testing.T) {
	svc := newTestService()
	handler := &alwaysFailHandler{
		obj:    svc,
		addErr: fmt.Errorf("permanent failure"),
	}
	rf := newTestFramework(handler)
	key := "test-ns/test-svc"

	// Seed the retry entry.
	rf.DoWithLock(key, func(k string) {
		rf.initRetryObjWithAddBackoff(svc, k, noBackoff)
	})

	// Retry without any update events in between.
	for i := 0; i < MaxFailedAttempts+1; i++ {
		if !CheckRetryObj(key, rf) {
			// Entry was dropped — verify it happened at the right time.
			if i < MaxFailedAttempts {
				t.Fatalf("entry dropped after %d attempts, expected %d",
					i, MaxFailedAttempts)
			}
			t.Logf("Control confirmed: entry correctly dropped after %d failed attempts "+
				"(MaxFailedAttempts=%d)", i, MaxFailedAttempts)
			return
		}
		SetRetryObjWithNoBackoff(key, rf)
		rf.resourceRetry(key, time.Now())
	}

	if CheckRetryObj(key, rf) {
		t.Fatalf("entry should have been dropped after %d attempts", MaxFailedAttempts)
	}

	t.Logf("Control confirmed: entry correctly dropped at MaxFailedAttempts=%d",
		MaxFailedAttempts)
}
