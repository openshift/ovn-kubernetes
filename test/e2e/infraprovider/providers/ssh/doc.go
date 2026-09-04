// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package ssh implements a generic, vendor-neutral infrastructure provider that
// drives the container runtime (docker/podman) on a remote host over SSH.
//
// It reuses the existing, transport-agnostic building blocks in
// test/e2e/infraprovider:
//
//   - engine/runner.NewSSHRunner  – executes commands on a remote host over SSH
//   - engine/container.Engine     – builds docker/podman commands and runs them
//     through whatever api.Runner it is given
//
// The kind provider wires container.Engine with a *local* runner
// (runner.NewDirectRunner). This provider wires the very same engine with an
// *SSH* runner, so `docker <args>` / `podman <args>` are executed on a remote
// host instead of locally.
//
// # Execution model
//
// The remote host is the container-engine boundary: we SSH to a host and run
// the container runtime there. We do NOT open an SSH session into every cluster
// node. For the kind-over-ssh guardrail the SSH target is the machine that runs
// the same container daemon that created the kind cluster (localhost is fine),
// so external containers land on the exact networks the kind nodes are on. The
// same model applies whenever the runtime daemon is reachable over SSH (for
// example a hypervisor running podman).
//
// Because commands run on the daemon host, any host paths a test passes via
// ExternalContainer.RuntimeArgs (e.g. bind mounts) are resolved on the REMOTE
// host, not where the test binary runs, and container capabilities (e.g.
// --privileged, in-container `ip`) must be satisfied by the remote daemon/image.
// This is expected for the SSH (Model 2) transport.
//
// # Composability
//
// The reusable substrate is RemoteContainerInfra, which owns the SSH runner and
// the container.Engine and implements the external-container/network surface. A
// composing provider can embed RemoteContainerInfra to inherit external-container
// behavior while supplying its own cluster-side behavior (for example a custom
// NodeExecutor). Provider is the complete, standalone provider built on top of
// that substrate.
//
// # Security
//
// This is a TEST-ONLY provider. The underlying SSH runner uses
// ssh.InsecureIgnoreHostKey() and authenticates with a private key only. Do not
// reuse this package outside of e2e testing against ephemeral infrastructure.
package ssh
