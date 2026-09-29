package ote

import (
	_ "unsafe" // required for go:linkname
)

// Link to the private testsStarted variable from OpenShift Origin.
//
// This links to an UNEXPORTED symbol in a pinned version of Origin and is
// fragile: re-verify the symbol and update this directive whenever the
// github.com/openshift/origin dependency changes. See README.md in this
// package for details.
//
//go:linkname testsStarted github.com/openshift/origin/test/extended/util.testsStarted
var testsStarted bool

func init() {
	// Mark tests as started so exutil functions work properly
	testsStarted = true
}
