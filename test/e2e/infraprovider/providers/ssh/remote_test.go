// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"errors"
	"strings"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	netpkg "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
)

// testConfig returns a defaulted Config for tests (docker runtime, kind primary
// network). Connection fields are placeholders; tests inject a fakeRunner so no
// SSH occurs.
func testConfig() Config {
	c := Config{Host: "h", User: "u", PrivateKeyPath: "/k"}
	c.applyDefaults()
	return c
}

// mustRemote builds a RemoteContainerInfra, failing the test on error.
func mustRemote(t *testing.T, cfg Config, r api.Runner) *RemoteContainerInfra {
	t.Helper()
	ri, err := NewRemoteContainerInfra(cfg, r)
	if err != nil {
		t.Fatalf("NewRemoteContainerInfra: %v", err)
	}
	return ri
}

func TestRemoteListNetworks(t *testing.T) {
	fake := &fakeRunner{respond: func(_ string, _ []string) (string, error) {
		return "kind\nbridge\n", nil
	}}
	r := mustRemote(t, testConfig(), fake)
	got, err := r.ListNetworks()
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(got) != 2 || got[0] != "kind" || got[1] != "bridge" {
		t.Fatalf("ListNetworks = %v, want [kind bridge]", got)
	}
	if !fake.sawCall("docker network ls --format {{.Name}}") {
		t.Fatalf("expected `network ls` call, got %v", fake.callStrings())
	}
}

func TestRemoteExecExternalContainerCommand(t *testing.T) {
	fake := &fakeRunner{respond: func(_ string, args []string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return "running", nil // container exists precheck
		}
		if len(args) > 0 && args[0] == "exec" {
			return "hello-from-ext", nil
		}
		return "", nil
	}}
	r := mustRemote(t, testConfig(), fake)
	out, err := r.ExecExternalContainerCommand(api.ExternalContainer{Name: "ext"}, []string{"echo", "hi"})
	if err != nil {
		t.Fatalf("ExecExternalContainerCommand: %v", err)
	}
	if out != "hello-from-ext" {
		t.Fatalf("output = %q, want %q", out, "hello-from-ext")
	}
	if !fake.sawCall("docker exec ext echo hi") {
		t.Fatalf("expected exec call, got %v", fake.callStrings())
	}
}

func TestRemotePrimaryInterfaceName(t *testing.T) {
	r := mustRemote(t, testConfig(), &fakeRunner{})
	if got := r.ExternalContainerPrimaryInterfaceName(); got != "eth0" {
		t.Fatalf("primary interface = %q, want eth0", got)
	}
}

func TestRemoteExternalContainerPortUnique(t *testing.T) {
	r := mustRemote(t, testConfig(), &fakeRunner{})
	p1 := r.GetExternalContainerPort()
	p2 := r.GetExternalContainerPort()
	if p1 == 0 || p2 == 0 {
		t.Fatalf("ports must be nonzero, got %d %d", p1, p2)
	}
	if p1 == p2 {
		t.Fatalf("ports must differ, got %d twice", p1)
	}
}

func TestRemoteClose(t *testing.T) {
	fake := &fakeRunner{}
	r := mustRemote(t, testConfig(), fake)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fake.closed {
		t.Fatal("expected underlying runner Close to be called")
	}
}

// TestRemoteExecPropagatesNotFound proves the api.NotFound sentinel survives the
// engine/ops error wrapping (%w) all the way back to the caller.
func TestRemoteExecPropagatesNotFound(t *testing.T) {
	fake := &fakeRunner{respond: func(_ string, args []string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return "", nil // empty state => container does not exist
		}
		return "", nil
	}}
	r := mustRemote(t, testConfig(), fake)
	_, err := r.ExecExternalContainerCommand(api.ExternalContainer{Name: "missing"}, []string{"echo"})
	if err == nil {
		t.Fatal("expected error for missing container")
	}
	if !errors.Is(err, api.NotFound) {
		t.Fatalf("error should wrap api.NotFound via %%w, got %v", err)
	}
}

// TestRemoteGetExternalContainerNetworkInterfaceSequence verifies the full,
// ordered command sequence for a multi-step operation (network exists check ->
// container exists check -> inspect -> interface discovery), not just the first
// command, and that the parsed result is correct.
func TestRemoteGetExternalContainerNetworkInterfaceSequence(t *testing.T) {
	const inspectJSON = `[{"NetworkSettings":{"Networks":{"kind":{"Gateway":"10.0.0.1","IPAddress":"10.0.0.5","IPPrefixLen":24,"MacAddress":"aa:bb:cc:dd:ee:ff"}}}}]`
	fake := &fakeRunner{respond: func(_ string, args []string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case len(args) >= 2 && args[0] == "network" && args[1] == "ls":
			return "kind\n", nil
		case len(args) >= 1 && args[0] == "ps":
			return "running", nil
		case len(args) >= 1 && args[0] == "inspect":
			return inspectJSON, nil
		case len(args) >= 1 && args[0] == "exec" && strings.Contains(joined, "link show"):
			return "2: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP>", nil
		case len(args) >= 1 && args[0] == "exec":
			// `ip -br -4 a sh` output; first token is the interface name.
			return "eth0 UP 10.0.0.5/24", nil
		}
		return "", nil
	}}
	r := mustRemote(t, testConfig(), fake)
	ni, err := r.GetExternalContainerNetworkInterface(
		api.ExternalContainer{Name: "ext"},
		netpkg.ContainerEngineNetwork{NetName: "kind"},
	)
	if err != nil {
		t.Fatalf("GetExternalContainerNetworkInterface: %v", err)
	}
	if ni.IPv4 != "10.0.0.5" || ni.IPv4Prefix != "24" || ni.MAC != "aa:bb:cc:dd:ee:ff" || ni.InfName != "eth0" {
		t.Fatalf("parsed interface = %+v, want IPv4 10.0.0.5/24 mac aa:bb:cc:dd:ee:ff inf eth0", ni)
	}
	for _, want := range []string{
		"docker network ls --format {{.Name}}",
		"docker inspect ext",
		"docker exec -i ext ip -br -4 a sh",
		"docker exec -i ext ip link show eth0",
	} {
		if !fake.sawCall(want) {
			t.Errorf("expected call %q in sequence, calls were:\n%s", want, strings.Join(fake.callStrings(), "\n"))
		}
	}
}

// TestRemoteCreateAndCleanupExternalContainerSequence exercises the create
// happy-path (validate -> not-exists -> run -> poll interface for IP -> post
// validate) AND that the create registers a cleanup on the test context that
// deletes the container. A stateful fake models container existence flipping on
// create/rm so the multi-step sequence is genuinely driven, not short-circuited.
func TestRemoteCreateAndCleanupExternalContainerSequence(t *testing.T) {
	const inspectJSON = `[{"NetworkSettings":{"Networks":{"kind":{"Gateway":"10.0.0.1","IPAddress":"10.0.0.5","IPPrefixLen":24,"MacAddress":"aa:bb:cc:dd:ee:ff"}}}}]`
	var created bool
	fake := &fakeRunner{}
	fake.respond = func(_ string, args []string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case len(args) >= 1 && args[0] == "run":
			created = true
			return "", nil
		case len(args) >= 1 && args[0] == "rm":
			created = false
			return "", nil
		case len(args) >= 2 && args[0] == "network" && args[1] == "ls":
			return "kind\n", nil
		case len(args) >= 1 && args[0] == "inspect":
			return inspectJSON, nil
		case len(args) >= 1 && args[0] == "exec" && strings.Contains(joined, "link show"):
			return "2: eth0@if5: <UP>", nil
		case len(args) >= 1 && args[0] == "exec":
			return "eth0 UP 10.0.0.5/24", nil
		case len(args) >= 1 && args[0] == "ps":
			// delete-verification uses `-q`; existence/state uses `--format {{.State}}`.
			if containsArg(args, "-q") {
				if created {
					return "someid\n", nil
				}
				return "", nil
			}
			if created {
				return "running", nil
			}
			return "", nil
		}
		return "", nil
	}

	tc := &testcontext.TestContext{}
	r := mustRemote(t, testConfig(), fake)
	cctx := r.NewExternalContainerContext(tc)
	ec := api.ExternalContainer{
		Name:  "ext",
		Image: "img",
		// Explicit CmdArgs avoids ops.CreateExternalContainer's images.AgnHost()
		// path, which depends on the global deploymentconfig being Set (only true
		// inside the real TestMain).
		CmdArgs: []string{"pause"},
		Network: netpkg.ContainerEngineNetwork{NetName: "kind"},
	}
	got, err := cctx.CreateExternalContainer(ec)
	if err != nil {
		t.Fatalf("CreateExternalContainer: %v", err)
	}
	if got.IPv4 != "10.0.0.5" {
		t.Fatalf("populated IPv4 = %q, want 10.0.0.5", got.IPv4)
	}
	if !fake.sawCall("docker run -itd --privileged --name ext --network kind --hostname ext img pause") {
		t.Fatalf("unexpected create command; calls:\n%s", strings.Join(fake.callStrings(), "\n"))
	}
	// The create must have registered cleanup on the test context; running it
	// should delete the container.
	if err := tc.CleanUp(); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	create := fake.firstIndexOf("docker run -itd --privileged --name ext --network kind --hostname ext img pause")
	del := fake.firstIndexOf("docker rm -f ext")
	if create < 0 || del < 0 || create >= del {
		t.Fatalf("expected create(run) to strictly precede cleanup(rm); create=%d del=%d calls:\n%s",
			create, del, strings.Join(fake.callStrings(), "\n"))
	}
}

// TestRemoteAttachNetworkCleanupLIFO proves that AttachNetwork registers a
// disconnect cleanup and that, on CleanUp, the disconnect runs BEFORE the network
// deletion (LIFO cleanup ordering). A stateful fake models network existence and
// attachment so the ops-level exists/attached checks are genuinely driven.
func TestRemoteAttachNetworkCleanupLIFO(t *testing.T) {
	var netExists, attached bool
	fake := &fakeRunner{}
	fake.respond = func(_ string, args []string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case len(args) >= 2 && args[0] == "network" && args[1] == "ls":
			if netExists {
				return "n1\n", nil
			}
			return "", nil
		case len(args) >= 2 && args[0] == "network" && args[1] == "create":
			netExists = true
			return "", nil
		case len(args) >= 2 && args[0] == "network" && args[1] == "connect":
			attached = true
			return "", nil
		case len(args) >= 2 && args[0] == "network" && args[1] == "disconnect":
			attached = false
			return "", nil
		case len(args) >= 2 && args[0] == "network" && args[1] == "rm":
			netExists = false
			return "", nil
		case len(args) >= 2 && args[0] == "network" && args[1] == "inspect":
			// Used by GetNetwork (IPAM) and getContainersAttachedToNetwork
			// (Containers). Report no attached containers (detach already ran).
			return `[{"Name":"n1","IPAM":{"Config":[{"Subnet":"10.9.0.0/24"}]},"Containers":{}}]`, nil
		case len(args) >= 1 && args[0] == "ps":
			return "running", nil // container c1 exists
		case len(args) >= 1 && args[0] == "inspect":
			// Container inspect: include n1 only once attached.
			if attached {
				return `[{"NetworkSettings":{"Networks":{"n1":{"Gateway":"10.9.0.1","IPAddress":"10.9.0.5","IPPrefixLen":24,"MacAddress":"aa:bb:cc:dd:ee:ff"}}}}]`, nil
			}
			return `[{"NetworkSettings":{"Networks":{}}}]`, nil
		case len(args) >= 1 && args[0] == "exec" && strings.Contains(joined, "link show"):
			return "2: eth0@if5: <UP>", nil
		case len(args) >= 1 && args[0] == "exec":
			return "eth0 UP 10.9.0.5/24", nil
		}
		return "", nil
	}

	tc := &testcontext.TestContext{}
	r := mustRemote(t, testConfig(), fake)
	cctx := r.NewExternalContainerContext(tc)

	net, err := cctx.CreateNetwork("n1", "10.9.0.0/24")
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if _, err := cctx.AttachNetwork(net, "c1"); err != nil {
		t.Fatalf("AttachNetwork: %v", err)
	}
	if err := tc.CleanUp(); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	disconnect := fake.firstIndexOf("docker network disconnect n1 c1")
	rm := fake.firstIndexOf("docker network rm n1")
	if disconnect < 0 || rm < 0 {
		t.Fatalf("expected both disconnect and network rm; disconnect=%d rm=%d calls:\n%s",
			disconnect, rm, strings.Join(fake.callStrings(), "\n"))
	}
	if disconnect >= rm {
		t.Fatalf("expected disconnect (LIFO) to precede network rm; disconnect=%d rm=%d calls:\n%s",
			disconnect, rm, strings.Join(fake.callStrings(), "\n"))
	}
}

// TestNewRemoteContainerInfraValidation covers the constructor's fast-fail paths.
func TestNewRemoteContainerInfraValidation(t *testing.T) {
	if _, err := NewRemoteContainerInfra(testConfig(), nil); err == nil {
		t.Error("expected error for nil runner")
	}
	badCfg := Config{Host: "h", User: "u", PrivateKeyPath: "/k", Runtime: "containerd"}
	if _, err := NewRemoteContainerInfra(badCfg, &fakeRunner{}); err == nil {
		t.Error("expected error for invalid runtime")
	}
	// Zero Config defaults runtime to docker and succeeds with a non-nil runner.
	if _, err := NewRemoteContainerInfra(Config{}, &fakeRunner{}); err != nil {
		t.Errorf("zero config with runner should default runtime and succeed, got %v", err)
	}
}

func TestRemoteRuntimeSelectsBinary(t *testing.T) {
	cfg := Config{Host: "h", User: "u", PrivateKeyPath: "/k", Runtime: "podman"}
	cfg.applyDefaults()
	fake := &fakeRunner{respond: func(_ string, _ []string) (string, error) { return "", nil }}
	r := mustRemote(t, cfg, fake)
	_, _ = r.ListNetworks()
	if !fake.sawCall("podman network ls --format {{.Name}}") {
		t.Fatalf("expected podman command, got %v", fake.callStrings())
	}
}
