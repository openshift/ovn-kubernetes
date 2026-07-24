package otp

import (
	_ "unsafe" // required for go:linkname
)

// Link to the private testsStarted variable from OpenShift Origin
//go:linkname testsStarted github.com/openshift/origin/test/extended/util.testsStarted
var testsStarted bool

func init() {
	// Mark tests as started so exutil functions work properly
	testsStarted = true
}
