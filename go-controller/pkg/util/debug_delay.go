package util

import (
	"sync"
	"time"

	"k8s.io/klog/v2"
)

var debugDelayOnce sync.Map

// MaybeSleepOnce is a DNM/TEST fault-injection helper that sleeps once per key.
// This is intentionally baked into the repro branch so CI-built images widen the
// race window without any external deployment changes.
func MaybeSleepOnce(key string, delay time.Duration, reason string) {
	if delay <= 0 {
		return
	}

	onceValue, _ := debugDelayOnce.LoadOrStore(key, &sync.Once{})
	once := onceValue.(*sync.Once)
	once.Do(func() {
		klog.Warningf("DNM/TEST fault injection: sleeping %v at %s", delay, reason)
		time.Sleep(delay)
	})
}
