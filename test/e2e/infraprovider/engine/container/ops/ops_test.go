// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ops

import (
	"fmt"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

// fakeNet is a minimal api.Network used to drive ContainerOps without a runtime.
type fakeNet struct{ name string }

func (f fakeNet) Name() string             { return f.name }
func (f fakeNet) String() string           { return f.name }
func (f fakeNet) Equal(c api.Network) bool { return c != nil && c.Name() == f.name }
func (f fakeNet) IPv4IPv6Subnets() (string, string, error) {
	return "", "", nil
}

// recordingRunner records every command and simulates a container's lifecycle:
// the container "exists" only after a `run` and before a `rm`. Setting failRun
// makes the create command fail so the pre-defer error path can be exercised.
type recordingRunner struct {
	failRun bool
	created bool
	calls   [][]string
}

func (r *recordingRunner) Run(command string, args ...string) (string, error) {
	call := append([]string{command}, args...)
	r.calls = append(r.calls, call)
	if len(args) == 0 {
		return "", nil
	}
	switch args[0] {
	case "run":
		if r.failRun {
			return "boom", fmt.Errorf("simulated run failure")
		}
		r.created = true
		return "", nil
	case "rm":
		r.created = false
		return "", nil
	case "ps":
		// Both the existence check (--format {{.State}}) and the post-delete
		// check (-q) route here; "exists" is keyed off the create/rm lifecycle.
		if r.created {
			return "running", nil
		}
		return "", nil
	default:
		return "", nil
	}
}

func (r *recordingRunner) called(verb, name string) bool {
	for _, c := range r.calls {
		if len(c) < 2 || c[1] != verb {
			continue
		}
		for _, a := range c[1:] {
			if a == name {
				return true
			}
		}
	}
	return false
}

// A host-networked container never gets an IP, so it skips IP polling and then
// fails IsValidPostCreate. That is a deterministic post-`run` failure: the fix
// must remove the container that `run` just created rather than leak it.
func TestCreateExternalContainerCleansUpOnPostCreateFailure(t *testing.T) {
	r := &recordingRunner{}
	o := NewContainerOps("docker", r)
	// CmdArgs is set so create does not consult images.AgnHost() (which needs a
	// deployment config this unit test does not configure).
	c := api.ExternalContainer{Name: "c1", Image: "img", Network: fakeNet{name: "host"}, CmdArgs: []string{"sleep", "infinity"}}

	if _, err := o.CreateExternalContainer(c); err == nil {
		t.Fatalf("expected post-create validation to fail (host-networked, no IPs); calls=%v", r.calls)
	}
	if !r.called("run", "c1") {
		t.Fatalf("expected a `docker run ... --name c1`; calls=%v", r.calls)
	}
	if !r.called("rm", "c1") {
		t.Fatalf("expected cleanup `docker rm -f c1` after the post-create failure; calls=%v", r.calls)
	}
}

// When `run` itself fails, no container was created, so the cleanup defer (which
// is registered only after a successful run) must not fire.
func TestCreateExternalContainerNoCleanupWhenRunFails(t *testing.T) {
	r := &recordingRunner{failRun: true}
	o := NewContainerOps("docker", r)
	c := api.ExternalContainer{Name: "c2", Image: "img", Network: fakeNet{name: "host"}, CmdArgs: []string{"sleep", "infinity"}}

	if _, err := o.CreateExternalContainer(c); err == nil {
		t.Fatal("expected create to fail when run fails")
	}
	if r.called("rm", "c2") {
		t.Fatalf("did not expect cleanup when the container was never created; calls=%v", r.calls)
	}
}
