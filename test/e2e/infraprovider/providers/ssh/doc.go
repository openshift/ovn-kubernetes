// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package ssh implements a remote container-runtime infrastructure provider for
// OVN-Kubernetes e2e tests. Commands run on a host over SSH; the container
// engine (docker/podman) on that host is the operational boundary.
//
// It reuses the existing, transport-agnostic building blocks in
// test/e2e/infraprovider:
//
//   - engine/runner.NewSSHRunnerWithOptions – executes commands on a remote host over SSH
//   - engine/container.Engine     – builds docker/podman commands and runs them
//     through whatever api.Runner it is given
//
// The kind provider wires container.Engine with a *local* runner
// (runner.NewDirectRunner). This provider wires the same engine with an
// *SSH* runner, so `docker <args>` / `podman <args>` are executed on a remote
// host instead of locally.
//
// # Supported topology (upstream)
//
// The standalone Provider targets the **kind-over-ssh** guardrail: KinD (or any
// cluster whose nodes are containers on the SSH host's runtime daemon). SSH
// reaches the daemon host, not individual Kubernetes nodes. The default
// NodeExecutor uses runtime exec into node containers.
//
// VM/bare-metal clusters require a custom NodeExecutor and are expected to be
// wired by downstream adapters embedding RemoteContainerInfra instead of using
// Provider directly. See docs/developer-guide/ssh_infra_provider.md.
//
// # Execution model
//
// Because commands run on the daemon host, bind mounts and capabilities in
// ExternalContainer.RuntimeArgs are resolved on the REMOTE host.
//
// # Composability
//
// RemoteContainerInfra is the reusable substrate implementing the
// external-container/network surface. Provider is the complete standalone
// provider built on that substrate with a pluggable NodeExecutor.
//
// # Security
//
// TEST-ONLY. Host-key verification is enabled by default (known_hosts). Set
// OVN_TEST_SSH_INSECURE_HOST_KEY=1 to opt out for ephemeral local testing.
package ssh
