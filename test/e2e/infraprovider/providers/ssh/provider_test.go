// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/portalloc"
)

// newTestProvider builds a Provider wired to a fakeRunner (no SSH). If nodeExec
// is nil the default engine-based executor is used.
func newTestProvider(t *testing.T, fake *fakeRunner, nodeExec NodeExecutor) *Provider {
	t.Helper()
	cfg := testConfig()
	remote := mustRemote(t, cfg, fake)
	if nodeExec == nil {
		nodeExec = NewEngineNodeExecutor(remote.Engine())
	}
	return &Provider{
		cfg:      cfg,
		remote:   remote,
		hostPort: portalloc.New(1024, 65535),
		nodeExec: nodeExec,
	}
}

func TestProviderName(t *testing.T) {
	p := newTestProvider(t, &fakeRunner{}, nil)
	if p.Name() != "ssh" {
		t.Fatalf("Name = %q, want ssh", p.Name())
	}
}

func TestProviderImplementsAPIProvider(t *testing.T) {
	// Compile-time assurance the struct satisfies the interface when constructed
	// the way tests do.
	var _ api.Provider = newTestProvider(t, &fakeRunner{}, nil)
}

func TestProviderExecK8NodeCommandDefaultEngine(t *testing.T) {
	fake := &fakeRunner{respond: func(_ string, args []string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return "running", nil
		}
		if len(args) > 0 && args[0] == "exec" {
			return "node-out", nil
		}
		return "", nil
	}}
	p := newTestProvider(t, fake, nil)
	out, err := p.ExecK8NodeCommand("ovn-worker", []string{"ip", "addr"})
	if err != nil {
		t.Fatalf("ExecK8NodeCommand: %v", err)
	}
	if out != "node-out" {
		t.Fatalf("out = %q, want node-out", out)
	}
	if !fake.sawCall("docker exec ovn-worker ip addr") {
		t.Fatalf("expected `exec` call, got %v", fake.callStrings())
	}
}

func TestProviderExecK8NodeCommandCustomExecutor(t *testing.T) {
	custom := &recordingNodeExecutor{out: "custom-out"}
	p := newTestProvider(t, &fakeRunner{}, custom)
	out, err := p.ExecK8NodeCommand("node1", []string{"whoami"})
	if err != nil {
		t.Fatalf("ExecK8NodeCommand: %v", err)
	}
	if out != "custom-out" {
		t.Fatalf("out = %q, want custom-out", out)
	}
	if custom.node != "node1" {
		t.Fatalf("node = %q, want node1", custom.node)
	}
	if !reflect.DeepEqual(custom.cmd, []string{"whoami"}) {
		t.Fatalf("cmd = %v, want [whoami]", custom.cmd)
	}
}

// TestProviderExecK8NodeCommandWrapsNodeNameAndError proves the node name is
// included in the error and that api.NotFound propagates through the provider's
// own wrapping (%w).
func TestProviderExecK8NodeCommandWrapsNodeNameAndError(t *testing.T) {
	fake := &fakeRunner{respond: func(_ string, args []string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return "", nil // node/container does not exist
		}
		return "", nil
	}}
	p := newTestProvider(t, fake, nil)
	_, err := p.ExecK8NodeCommand("worker", []string{"true"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "worker") {
		t.Fatalf("error should mention node name: %v", err)
	}
	if !errors.Is(err, api.NotFound) {
		t.Fatalf("error should propagate api.NotFound via %%w: %v", err)
	}
}

func TestProviderShutdownNode(t *testing.T) {
	fake := &fakeRunner{respond: func(_ string, args []string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return "running", nil
		}
		return "", nil
	}}
	p := newTestProvider(t, fake, nil)
	if err := p.ShutdownNode("ovn-worker"); err != nil {
		t.Fatalf("ShutdownNode: %v", err)
	}
	if !fake.sawCall("docker stop ovn-worker") {
		t.Fatalf("expected `stop` call, got %v", fake.callStrings())
	}
}

func TestProviderStartNode(t *testing.T) {
	fake := &fakeRunner{respond: func(_ string, args []string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return "exited", nil
		}
		return "", nil
	}}
	p := newTestProvider(t, fake, nil)
	if err := p.StartNode("ovn-worker"); err != nil {
		t.Fatalf("StartNode: %v", err)
	}
	if !fake.sawCall("docker start ovn-worker") {
		t.Fatalf("expected `start` call, got %v", fake.callStrings())
	}
}

func TestProviderGetK8HostPort(t *testing.T) {
	p := newTestProvider(t, &fakeRunner{}, nil)
	if p.GetK8HostPort() == 0 {
		t.Fatal("expected nonzero host port")
	}
}

func TestProviderSetupUnderlayUnsupported(t *testing.T) {
	pc := &providerContext{}
	err := pc.SetupUnderlay(nil, api.Underlay{})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("SetupUnderlay err = %v, want ErrUnsupported", err)
	}
}

func TestProviderPreloadImagesDelegates(t *testing.T) {
	var got []string
	cfg := testConfig()
	cfg.ImagePreloader = func(imgs []string) error {
		got = append(got, imgs...)
		return nil
	}
	remote := mustRemote(t, cfg, &fakeRunner{})
	p := &Provider{cfg: cfg, remote: remote, hostPort: portalloc.New(1024, 65535), nodeExec: NewEngineNodeExecutor(remote.Engine())}
	p.PreloadImages([]string{"img:a", "img:b"})
	if len(got) != 2 || got[0] != "img:a" || got[1] != "img:b" {
		t.Fatalf("ImagePreloader should have received the images, got %v", got)
	}
}

func TestProviderUnsupportedCapabilities(t *testing.T) {
	p := newTestProvider(t, &fakeRunner{}, nil)
	found := false
	for _, c := range p.UnsupportedCapabilities() {
		if c == "SetupUnderlay" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected SetupUnderlay in unsupported capabilities, got %v", p.UnsupportedCapabilities())
	}
}

type recordingNodeExecutor struct {
	node string
	cmd  []string
	out  string
	err  error
}

func (r *recordingNodeExecutor) Exec(nodeName string, cmd []string) (string, error) {
	r.node = nodeName
	r.cmd = cmd
	return r.out, r.err
}
