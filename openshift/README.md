# MAC security test extension

This branch enables MAC security tests for paired testing with
[CNO #3179](https://github.com/openshift/cluster-network-operator/pull/3179),
which supplies gated UDN/CUDN schemas, and
[API #3062](https://github.com/openshift/api/pull/3062), which registers the
`MACSecurity` feature gate. All enabled entries carry
`[OCPFeatureGate:MACSecurity]` for OpenShift runner filtering.

All 12 enabled MAC security entries run in
`ovn-kubernetes/conformance/serial/virtualization`: six pod connectivity cases,
four API validation entries, and two VM cases checking TCP traffic through
successful and failed migration. The suite sets `Parallelism: 1` so all entries
run sequentially. Localnet pod cases require
VLAN 100 transport. Five incompatible API validation entries remain disabled.
The ordinary parallel and serial suites exclude these virtualization-suite
entries, including the non-VM tests.
The entries use the OTE suite annotation rather than Origin's
`openshift/network/virtualization` annotation.

Build and validate discovery:

```sh
./openshift/hack/build-tests-ext.sh
./openshift/hack/update-tests-annotation.sh
./openshift/hack/validate-test-lists.sh
```

Runtime netshoot requests resolve to the payload `openshift/network-tools`
ImageStream (or `NETSHOOT_IMAGE`). The payload must contain iperf3 from
[network-tools #189](https://github.com/openshift/network-tools/pull/189).
VMs use `quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2`,
advertised with Kubernetes' `image.None` index to match Origin mirroring.
The runtime Fedora pullspec is returned directly from the image registry;
`KUBE_TEST_REPO` does not rewrite it.

Post on the OVN PR:

```text
/testwith openshift/ovn-kubernetes/main/e2e-metal-ipi-core-networking-virt-dualstack-serial-ote-tp openshift/cluster-network-operator#3179 openshift/api#3062
```

The virt lane installs CNV and provides `virtctl`. For local execution, supply
a compatible `/tmp/virtctl` and use `openshift-tests` with
`EXTENSION_BINARY_OVERRIDE_OVN_KUBERNETES` pointing to the built extension.
Tests are Informing: inspect individual results even when the lane is green.
The TP lane installs with `TechPreviewNoUpgrade`. Confirm `FeatureGate/cluster`
reports `MACSecurity` enabled and the installed schemas expose `macSecurity`.
