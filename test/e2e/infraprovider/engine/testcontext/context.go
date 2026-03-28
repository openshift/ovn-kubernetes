package testcontext

import (
	"errors"
	"sync"

	"k8s.io/kubernetes/test/e2e/framework"
)

type TestContext struct {
	sync.Mutex
	cleanUpFns []func() error
}

func (c *TestContext) AddCleanUpFn(cleanUpFn func() error) {
	c.Lock()
	defer c.Unlock()
	c.addCleanUpFn(cleanUpFn)
}

func (c *TestContext) addCleanUpFn(cleanUpFn func() error) {
	c.cleanUpFns = append(c.cleanUpFns, cleanUpFn)
}

func (c *TestContext) CleanUp() error {
	c.Lock()
	defer c.Unlock()
	err := c.cleanUp()
	if err != nil {
		framework.Logf("Cleanup failed: %v", err)
	}
	return err
}

// CleanUp must be synchronized by caller
func (c *TestContext) cleanUp() error {
	var errs []error
	// generic cleanup activities
	for i := len(c.cleanUpFns) - 1; i >= 0; i-- {
		if err := c.cleanUpFns[i](); err != nil {
			errs = append(errs, err)
		}
	}
	c.cleanUpFns = nil
	return errors.Join(errs...)
}
