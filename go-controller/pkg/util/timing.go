package util

import (
	"time"

	"k8s.io/klog/v2"
)

// Timer is a simple timing helper that measures operation duration
type Timer struct {
	name      string
	startTime time.Time
	verbosity klog.Level
}

// StartTimer creates and starts a new timer for the given operation name.
// The timer will log at the specified klog verbosity level (typically V(4) for timing info).
func StartTimer(name string, verbosity klog.Level) *Timer {
	return &Timer{
		name:      name,
		startTime: time.Now(),
		verbosity: verbosity,
	}
}

// End logs the elapsed time since the timer was started.
// This should typically be called with defer, e.g.:
//
//	timer := util.StartTimer("myOperation", 4)
//	defer timer.End()
func (t *Timer) End() {
	duration := time.Since(t.startTime)
	klog.V(t.verbosity).Infof("Finished %s, took %v", t.name, duration)
}

// LogMilestone logs an intermediate timing checkpoint without ending the timer.
// Useful for tracking progress within a long-running operation.
func (t *Timer) LogMilestone(milestone string) {
	duration := time.Since(t.startTime)
	klog.V(t.verbosity).Infof("%s - %s (elapsed: %v)", t.name, milestone, duration)
}
