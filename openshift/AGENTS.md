# AGENTS.md -- OpenShift Test Extension (OTE)

Context for AI coding agents working on the `openshift/` directory.

## What is OTE?

OTE bridges upstream OVN-Kubernetes E2E tests with OpenShift CI. It vendors
upstream Ginkgo tests, assigns lifecycle labels (informing/blocking), appends
OpenShift-specific annotations, and provides platform-aware infrastructure
(external hosts, networks) that upstream tests need.

## Directory Layout

```text
openshift/
  cmd/
    ovn-kubernetes-tests-ext/   # Main OTE binary -- test registration, filtering, labels, suites
    annotate/                   # Generates zz_generated.annotations.go (appended labels/suites)
    list-test-names/            # Prints all test names (used by validate-test-lists.sh)
  test/
    tests.go                    # Hand-maintained lists: InformingTests, BlockingTests
    annotate/                   # Annotation generator logic and label rules (rules.go)
    generated/                  # zz_generated.annotations.go (auto-generated, do not edit)
    infraprovider/              # OpenShift infra provider (baremetal, cloud, base)
    deploymentconfig/           # OpenShift deployment config (images, node subnets, interface)
    namespace.go                # Namespace helpers
    e2e_test.go                 # go:generate directive for annotations
  hack/
    build-tests-ext.sh          # Build the OTE binary
    update-tests-annotation.sh  # Regenerate zz_generated.annotations.go
    validate-test-lists.sh      # Check for orphaned/missing tests in tests.go
    check-go-mod-consistency.sh # Verify go.mod stays in sync with go-controller
  vendor/                       # Vendored upstream OVN-Kubernetes tests and dependencies
  Makefile                      # Build, test, lint, license targets
```

## Build and Test

```bash
# Build the OTE binary
./hack/build-tests-ext.sh

# Run unit tests (excludes annotate, deploymentconfig, generated packages)
make test

# Regenerate annotations after upstream test changes
./hack/update-tests-annotation.sh

# Validate tests.go against binary (catches orphaned/missing tests)
./hack/validate-test-lists.sh

# Check/fix SPDX license headers
make license-check
make license-fix
```

## How Tests Get Registered

1. Upstream Ginkgo tests are imported via `_ "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e"`
2. `BuildExtensionTestSpecsFromOpenShiftGinkgoSuite` walks the Ginkgo tree and creates specs
3. Each spec gets labels (`sig-network`, `ovn-kubernetes-ote`) and prepended feature labels
4. `zz_generated.annotations.go` appends suite names (`[Suite:ovn-kubernetes/conformance/...]`)
5. Specs are matched against `tests.go` to assign lifecycle (informing/blocking); unmatched tests get empty lifecycle and are filtered out
6. `shouldIncludeTest` filters based on cluster capabilities (EVPN, GCP, secondary-host-eip)

## How to Add a Test to tests.go

You cannot discover test names from `list tests` output -- tests not on either
list are filtered out. Instead:

1. Find the upstream Ginkgo test name in `test/e2e/`
2. Compose the final name: prepended labels (sorted alphabetically) + upstream name + appended annotations from `rules.go`
3. Add to `InformingTests` or `BlockingTests` in `test/tests.go`
4. Rebuild: `./hack/build-tests-ext.sh`
5. Verify: `./bin/ovn-kubernetes-tests-ext list tests | jq -r '.[] | select(.name == "<test name>") | .lifecycle'`
6. Run `./hack/validate-test-lists.sh` to check for orphaned tests

## Labels

- `sig-network`, `ovn-kubernetes-ote` -- applied to all OTE tests
- `Feature:EVPN` -- EVPN tests, auto-prepends `FeatureGate:EVPN`
- `Feature:NetworkSegmentation` -- UDN tests, excluded on SingleReplica topology
- `Feature:EgressIP` -- EgressIP tests, GCP-specific filtering

Labels are prepended to test names sorted alphabetically in `[Label]` format.
Label-to-label mappings are in `cmd/ovn-kubernetes-tests-ext/labels.go`.
Label-to-test-name mappings are in `test/annotate/rules.go`.

## Disabling a Test

Tests are disabled by name in `test/annotate/rules.go`:

- `[Disabled:Unimplemented]` -- downstream infra cannot provide what the test needs
- `[Disabled:SpecialConfig]` -- needs an operator or config the lanes do not deploy
- `[Disabled:Broken]` -- known broken; always link an issue

Disabled specs are not listed by the OTE binary at all, so they appear in no
junit -- not as skips, not as failures. When you add an entry, also record the
reason in [test/README.md](test/README.md) so the coverage gap stays visible.

## Initialization Order

In `cmd/ovn-kubernetes-tests-ext/main.go`, order matters:

1. `deploymentconfig.Set()` -- must be first (infraprovider.New calls deploymentconfig.Get)
2. `infraprovider.Set()` -- must be before Ginkgo tree construction (Entry() arguments query infraprovider)
3. `BuildExtensionTestSpecsFromOpenShiftGinkgoSuite` -- constructs the Ginkgo tree

When no kubeconfig is available (e.g. `list tests`), a zero-value
`OpenshiftInfraProvider{}` is set so Entry() arguments don't panic.

## Key Packages

- **[test/infraprovider/](test/infraprovider/README.md)** -- Platform-specific
  test infrastructure (SSH, external containers, networks). See README for
  baremetal vs cloud setup and architecture diagrams.

- **[test/](test/README.md)** -- Test coverage matrix, platform skip reasons,
  and known issues across baremetal/AWS/Azure/GCP.
