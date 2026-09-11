// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
)

// NodeExecutor executes a command in a cluster node's host network namespace and
// filesystem. It is the pluggable seam behind ExecK8NodeCommand: different
// environments reach a node's host differently (container exec, kubectl debug,
// direct SSH to the node), and a caller selects the right strategy via
// Config.NodeExecutor.
//
// The default is engineNodeExecutor (container runtime "exec" over SSH), which
// suits the kind-over-ssh guardrail where nodes are containers on the same
// daemon. Callers whose nodes are real VMs or cloud instances inject their own
// NodeExecutor.
type NodeExecutor interface {
	Exec(nodeName string, cmd []string) (string, error)
}

// engineNodeExecutor runs commands on a node that is itself a container managed
// by the (remote) container engine, i.e. `<runtime> exec <node> <cmd>` executed
// over SSH. This is the default for the kind-over-ssh guardrail, where cluster
// nodes are containers on the same daemon we reach over SSH.
type engineNodeExecutor struct {
	engine *container.Engine
}

// NewEngineNodeExecutor returns a NodeExecutor that execs into the node treating
// it as a container on the engine.
func NewEngineNodeExecutor(engine *container.Engine) NodeExecutor {
	return &engineNodeExecutor{engine: engine}
}

func (e *engineNodeExecutor) Exec(nodeName string, cmd []string) (string, error) {
	return e.engine.ExecContainerCommand(nodeName, cmd)
}
