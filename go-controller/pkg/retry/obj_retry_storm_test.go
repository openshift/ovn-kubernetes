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

// TestFailedAttemptsResetOnReAdd demonstrates the retry storm bug:
// when an informer update event fires for a service that is already failing,
// initRetryObjWithAdd resets failedAttempts to 0, preventing MaxFailedAttempts
// from ever being reached. The service retries indefinitely.
func TestFailedAttemptsResetOnReAdd(t *testing.T) {
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

	// Simulate an informer update event: this calls initRetryObjWithAdd,
	// which resets failedAttempts to 0. This is the bug.
	rf.DoWithLock(key, func(k string) {
		rf.initRetryObjWithAdd(svc, k)
	})

	entry, _ = GetRetryObj(key, rf)
	if entry.failedAttempts != 0 {
		t.Fatalf("expected failedAttempts=0 after re-add (demonstrating the bug), got %d",
			entry.failedAttempts)
	}

	// Now simulate the full storm: retry + re-add in a loop, well past MaxFailedAttempts.
	// The entry should never be dropped because each re-add resets the counter.
	totalCycles := MaxFailedAttempts + 5
	for i := 0; i < totalCycles; i++ {
		// Clear backoff so resourceRetry doesn't skip due to timer.
		SetRetryObjWithNoBackoff(key, rf)

		rf.resourceRetry(key, time.Now())

		// Simulate the update event that arrives between retry sweeps.
		rf.DoWithLock(key, func(k string) {
			rf.initRetryObjWithAdd(svc, k)
		})
	}

	// The entry should still exist — MaxFailedAttempts was never reached
	// because every update event reset failedAttempts to 0.
	if !CheckRetryObj(key, rf) {
		t.Fatalf("retry entry was dropped after %d cycles, but should have survived "+
			"indefinitely due to failedAttempts reset (the retry storm bug)", totalCycles)
	}

	// Verify AddResource was called on every cycle (no retries were skipped).
	// 1 initial + totalCycles = total calls.
	expectedCalls := 1 + totalCycles
	if handler.addCalls != expectedCalls {
		t.Fatalf("expected AddResource to be called %d times, got %d",
			expectedCalls, handler.addCalls)
	}

	t.Logf("Bug confirmed: entry survived %d retry cycles (MaxFailedAttempts=%d) "+
		"because update events reset failedAttempts to 0 each time",
		totalCycles, MaxFailedAttempts)
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
