package test

import "k8s.io/kubernetes/test/e2e/framework"

// SIGDescribe annotates the test with the SIG label.
var SIGDescribe = framework.SIGDescribe("network")
