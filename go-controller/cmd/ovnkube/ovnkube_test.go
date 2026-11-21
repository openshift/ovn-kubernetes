// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	testLeaseNamespace = "ovn-kubernetes"
	testLeaseName      = "ovn-kubernetes-master"
	testGaugeName      = "test_cluster_manager_leader"
	testRetryPeriod    = 100 * time.Millisecond
	testWaitTimeout    = 10 * time.Second
)

// competingLeaderMetricsProvider stands in for a leader election metrics
// provider that another package registered before ovnkube set up leader
// election.
type competingLeaderMetricsProvider struct{}

func (competingLeaderMetricsProvider) NewLeaderMetric() leaderelection.LeaderMetric {
	return competingLeaderMetric{}
}

type competingLeaderMetric struct{}

func (competingLeaderMetric) On(string)                {}
func (competingLeaderMetric) Off(string)               {}
func (competingLeaderMetric) SlowpathExercised(string) {}

func TestMain(m *testing.M) {
	// client-go keeps one process-wide leader election metrics provider and
	// ignores every SetProvider call after the first. In the ovnkube binary a
	// linked package (controller-runtime's metrics) registers its provider
	// during init, before leader election is set up. Register one here as well
	// so that the leader election tests do not depend on the import graph.
	leaderelection.SetProvider(competingLeaderMetricsProvider{})
	os.Exit(m.Run())
}

// leaderCandidate is one ovnkube cluster manager instance taking part in
// leader election, wired the same way as startOvnKube wires it.
type leaderCandidate struct {
	gauge     prometheus.Gauge
	lifecycle *leaderLifecycle
	elector   *leaderelection.LeaderElector
	ctx       context.Context
	cancel    context.CancelFunc
	started   chan struct{}
	done      chan struct{}
}

// newLeaderCandidate creates a candidate whose components run until they are
// cancelled, or return runErr right after starting when it is not nil.
func newLeaderCandidate(g *gomega.WithT, client *fake.Clientset, identity string, leaseDuration time.Duration, runErr error) *leaderCandidate {
	ctx, cancel := context.WithCancel(context.Background())
	c := &leaderCandidate{
		gauge:   prometheus.NewGauge(prometheus.GaugeOpts{Name: testGaugeName}),
		ctx:     ctx,
		cancel:  cancel,
		started: make(chan struct{}),
		done:    make(chan struct{}),
	}
	c.lifecycle = &leaderLifecycle{
		identity:    identity,
		leaderGauge: c.gauge,
		run: func(ctx context.Context) error {
			close(c.started)
			if runErr != nil {
				return runErr
			}
			<-ctx.Done()
			return nil
		},
		cancel:  cancel,
		startWg: &sync.WaitGroup{},
	}
	lock, err := resourcelock.New(resourcelock.LeasesResourceLock, testLeaseNamespace, testLeaseName,
		client.CoreV1(), client.CoordinationV1(), resourcelock.ResourceLockConfig{Identity: identity})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	c.elector, err = leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   leaseDuration,
		RenewDeadline:   leaseDuration / 2,
		RetryPeriod:     testRetryPeriod,
		ReleaseOnCancel: true,
		Callbacks:       c.lifecycle.callbacks(),
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	return c
}

// start runs leader election the way startOvnKube does and makes sure the
// election goroutine has returned before the test ends.
func (c *leaderCandidate) start(t *testing.T) {
	t.Helper()
	go func() {
		defer close(c.done)
		c.elector.Run(c.ctx)
		c.lifecycle.markStopped()
	}()
	t.Cleanup(func() {
		c.cancel()
		<-c.done
	})
}

func gaugeValue(gauge prometheus.Gauge) float64 {
	m := &dto.Metric{}
	if err := gauge.Write(m); err != nil {
		return -1
	}
	return m.GetGauge().GetValue()
}

func TestClusterManagerLeaderGaugeFollowsLeadership(t *testing.T) {
	g := gomega.NewWithT(t)
	client := fake.NewClientset()
	active := newLeaderCandidate(g, client, "node-a", 10*time.Second, nil)
	standby := newLeaderCandidate(g, client, "node-b", 10*time.Second, nil)
	g.Expect(gaugeValue(active.gauge)).To(gomega.BeZero())
	g.Expect(gaugeValue(standby.gauge)).To(gomega.BeZero())

	active.start(t)
	g.Eventually(active.started, testWaitTimeout).Should(gomega.BeClosed())
	g.Expect(gaugeValue(active.gauge)).To(gomega.Equal(1.0))

	standby.start(t)
	g.Eventually(standby.elector.GetLeader, testWaitTimeout).Should(gomega.Equal("node-a"))
	g.Consistently(func() float64 { return gaugeValue(standby.gauge) }, time.Second, 50*time.Millisecond).Should(gomega.BeZero())
	g.Expect(standby.started).NotTo(gomega.BeClosed())
	g.Expect(gaugeValue(active.gauge)).To(gomega.Equal(1.0))

	// Giving up leadership resets the gauge and lets the standby take over.
	active.cancel()
	g.Eventually(active.done, testWaitTimeout).Should(gomega.BeClosed())
	g.Expect(gaugeValue(active.gauge)).To(gomega.BeZero())

	g.Eventually(standby.started, testWaitTimeout).Should(gomega.BeClosed())
	g.Expect(standby.elector.GetLeader()).To(gomega.Equal("node-b"))
	g.Expect(gaugeValue(standby.gauge)).To(gomega.Equal(1.0))

	standby.cancel()
	g.Eventually(standby.done, testWaitTimeout).Should(gomega.BeClosed())
	g.Expect(gaugeValue(standby.gauge)).To(gomega.BeZero())
}

func TestClusterManagerLeaderGaugeResetsWhenRenewalFails(t *testing.T) {
	g := gomega.NewWithT(t)
	client := fake.NewClientset()
	// Reactors must be installed before the elector starts using the fake
	// client, so the failure is switched on later instead.
	var failLeaseUpdates atomic.Bool
	client.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failLeaseUpdates.Load() {
			return true, nil, errors.New("injected lease update failure")
		}
		return false, nil, nil
	})
	leader := newLeaderCandidate(g, client, "node-a", 2*time.Second, nil)

	leader.start(t)
	g.Eventually(leader.started, testWaitTimeout).Should(gomega.BeClosed())
	g.Expect(gaugeValue(leader.gauge)).To(gomega.Equal(1.0))

	// The leader can no longer renew its lease, so it loses leadership.
	failLeaseUpdates.Store(true)
	g.Eventually(leader.done, testWaitTimeout).Should(gomega.BeClosed())
	g.Expect(gaugeValue(leader.gauge)).To(gomega.BeZero())
}

func TestClusterManagerLeaderGaugeResetsWhenComponentsFail(t *testing.T) {
	g := gomega.NewWithT(t)
	client := fake.NewClientset()
	leader := newLeaderCandidate(g, client, "node-a", 10*time.Second, errors.New("injected component failure"))

	leader.start(t)
	g.Eventually(leader.started, testWaitTimeout).Should(gomega.BeClosed())
	g.Eventually(leader.done, testWaitTimeout).Should(gomega.BeClosed())
	g.Expect(gaugeValue(leader.gauge)).To(gomega.BeZero())
}

func TestLeaderLifecycleDoesNotStartAfterStop(t *testing.T) {
	g := gomega.NewWithT(t)
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: testGaugeName})
	ran := false
	l := &leaderLifecycle{
		identity:    "node-a",
		leaderGauge: gauge,
		run: func(context.Context) error {
			ran = true
			return nil
		},
		cancel:  func() {},
		startWg: &sync.WaitGroup{},
	}

	// OnStartedLeading may run after OnStoppedLeading; the late start must
	// neither start the components nor report leadership.
	l.onStoppedLeading()
	l.onStartedLeading(context.Background())
	g.Expect(ran).To(gomega.BeFalse())
	g.Expect(gaugeValue(gauge)).To(gomega.BeZero())
}
