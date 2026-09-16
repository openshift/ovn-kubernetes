# OVN-Kubernetes test extension

The payload image includes `ovn-kubernetes-tests-ext`. Its
`ovn-kubernetes/conformance/serial/virtualization` suite is an ovnk conformance
suite selected directly by the dedicated metal virtualization OTE job
(`TEST_SUITE=ovn-kubernetes/conformance/serial/virtualization`), so the OVN
tests run on their own and not alongside the Origin virtualization tests. The
Layer2 cases run serially because they share cluster-wide resources.

Initially, six informing Layer2 cases are enabled: VM restart, VM migration,
and VMI migration on primary and secondary networks. Localnet, routed/EVPN,
static-address, and failed-migration cases are not on the allowlist.

## Build and discovery

```sh
./openshift/hack/build-tests-ext.sh
./openshift/hack/update-tests-annotation.sh
./openshift/hack/build-tests-ext.sh
./openshift/bin/ovn-kubernetes-tests-ext info
./openshift/bin/ovn-kubernetes-tests-ext list tests
```

Like Origin's live-migration tests, the extension uses the approved
`quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2` container disk.
It registers that source image with Kubernetes' `image.None` index (`0`). The
OpenShift deployment-config getter uses Kubernetes' standard image mapper with
`KUBE_TEST_REPO`, producing the same index-free mirror tag as Origin's
`image.LocationFor`. An empty repository uses the source image directly.
Shared tests select Fedora and netshoot through `test/e2e/images` and the
deployment-config getters. On OpenShift, the netshoot getter resolves the payload
image from the latest imported tag in the `openshift/network-tools` ImageStream, matching
Origin's EgressIP helpers. Payload images are not mapped into the community test
image repository. No netshoot image is registered for OTE.
The existing `NETSHOOT_IMAGE` override takes precedence over the provider getter.
Endpoint-preparation hooks preserve the image selected by the test.

## iperf3 preparation

`test/infraprovider/iperf.go` contains the OpenShift-specific preparation:

- Require a payload containing [network-tools#189](https://github.com/openshift/network-tools/pull/189),
  which adds `iperf3`. Older images fail with an explicit prerequisite error;
  no packages are installed at runtime.
- Wait for server readiness before generating traffic.
- Pull the external container image over hypervisor SSH using the cluster pull
  secret on stdin, without persisting an auth file or exposing credentials in
  command arguments.
- Preserve client PID-file handling for RHEL 9's iperf3 3.9, which only supports
  `--pidfile` for servers, and flush client logs for live traffic checks.

The upstream tests only have optional endpoint-preparation hooks. Payload image
resolution and iperf3 compatibility handling remain under `openshift/`.

## Metal CI

Use the existing OVN presubmit:

```text
/test e2e-metal-ipi-ovn-bgp-virt-dualstack
```

The job installs CNV and provides hypervisor SSH access through
`SHARED_DIR/server-ip` and the cluster profile's `equinix-ssh-key` (or
`packet-ssh-key`). Primary Layer2 peers run in per-test, host-networked Podman
containers on the hypervisor. They use its machine-network addresses and are
removed through the test context's cleanup. The dev-scripts bridge does not
allocate container addresses with IPAM.

## Local validation with the CI provider

Use a baremetal cluster with the same hypervisor SSH configuration as CI.
The upstream console client expects a cluster-compatible `virtctl` at
`/tmp/virtctl`.

```sh
export KUBECONFIG=/path/to/cluster/auth/kubeconfig
export SHARED_DIR=/path/to/shared-directory
export CLUSTER_PROFILE_DIR=/path/to/cluster-profile
export ARTIFACT_DIR=/path/to/artifacts

export EXTENSION_BINARY_OVERRIDE_OVN_KUBERNETES=/path/to/ovn-kubernetes-tests-ext
# For local testing against an older payload, discover only this extension.
export EXTENSION_BINARY_OVERRIDE_INCLUDE_TAGS=ovn-kubernetes
openshift-tests run ovn-kubernetes/conformance/serial/virtualization \
  --run 'ovn-kubernetes-ote' --max-parallel-tests 1 \
  --junit-dir "$ARTIFACT_DIR/junit"
```

Use a compatible `openshift-tests` binary. For an unmirrored local build,
`--from-repository=''` uses the Fedora source image; validate the CI mirror
separately. The extension's lightweight `run-suite` command can misparse JSON
from guest-console output with the current extension library, so use
`openshift-tests` for result reporting.

The cluster needs healthy virtualization-capable nodes, CUDN and IPAMClaims
APIs, the KubeVirt IPAM controller, and the `l2bridge` managed-tap binding for
primary UDNs. The tests create VMs, networks, and traffic pods; upstream failure
handling may retain their namespaces for diagnosis. Informing test failures
must be checked in the results/JUnit, even if the command exits successfully.

### Older-cluster compatibility

Current-main primary Layer2 migration tests expect the subnet-derived MAC of
the transit-router gateway. OpenShift 4.20 uses the older gateway-router layout,
so migration and traffic checks can succeed while the final gateway-MAC
assertion fails. Use a matching current-release cluster for full validation;
do not weaken the gateway assertion to accommodate the older topology.
