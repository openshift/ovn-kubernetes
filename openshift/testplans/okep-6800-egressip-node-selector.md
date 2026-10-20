<!--
SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
SPDX-License-Identifier: Apache-2.0
-->

# Test Plan: OKEP-6800 EgressIP Node Selector (`egressNodeSelector`)

> **Template note.** First document under `openshift/testplans/`. Copy as the
> skeleton for future plans; keep the section order: *Metadata → Introduction →
> Unit Tests → E2E Tests → Cross-Feature Tests → Scale Testing*.

## 1. Metadata

| Field | Value |
|-------|-------|
| Feature | EgressIP `egressNodeSelector` + health-check scoping |
| Epic | [CORENET-7425](https://redhat.atlassian.net/browse/CORENET-7425) |
| OKEP | [okep-6800-egressip-node-selector](../../docs/okeps/okep-6800-egressip-node-selector.md) |
| Upstream PR | [ovn-kubernetes/ovn-kubernetes#6903](https://github.com/ovn-kubernetes/ovn-kubernetes/pull/6903) |
| Key review thread | [PR #6903 discussion r4283584603](https://github.com/ovn-kubernetes/ovn-kubernetes/pull/6903#discussion_r4283584603) |
| Downstream feature gate | [openshift/api#3032](https://github.com/openshift/api/pull/3032) |
| Component impacted | `ovnkube-cluster-manager` only (`egressIPClusterController`) — control plane |
| Data plane impact | None (selector affects assignment, not the datapath) |

## 2. Introduction

`egressNodeSelector` lets an EgressIP object restrict which nodes its IPs may be
assigned to. Omitting the field defaults to the legacy
`k8s.ovn.org/egress-assignable` label selector, so existing behavior is preserved.
A custom selector (`matchLabels` and/or `matchExpressions`) narrows the eligible
node pool to an arbitrary label scheme — zone, tenant, compliance domain, etc.

The feature is **control-plane only**: it changes which nodes
`ovnkube-cluster-manager` considers for assignment and which nodes it health-checks.
The datapath (SNAT, routing, marks) is unchanged, so the feature behaves identically
across the default cluster network and User Defined Networks (including BGP and
dynamic UDNs).

Three code paths became selector-aware: the **assignment** path, the **node/EIP
event handlers**, and the **periodic reachability (health-check) loop**. Only the
last is a scale concern (§5).

## 3. Unit Tests

File: `go-controller/pkg/clustermanager/egressip_controller_test.go`, suite
`OVN cluster-manager EgressIP Operations` → `Context("Egress Node Selector Operations")`.

| Sub-context | Representative `It` blocks | OKEP requirement |
|-------------|---------------------------|------------------|
| node events | assign/no-assign on add; rebalance + go-pending on delete; assign pending on new matching node without moving assigned; unassign on label removal; two-IP spread + toggle | subset match, label add/remove reassignment |
| EgressIP events | clear allocations on EIP delete; move on selector change; unassign when selector matches nothing | selector-update reassignment |
| ordering / readiness / restart | node added after EIP; EIP created after nodes; labels change to match / stop matching; NotReady→Ready; stale status moved on restart | ordering & restart robustness |
| corner cases | empty selector matches all; no match → pending; unrelated label change → no churn; selector update still matches → no churn; node shifts between pools; invalid selector skipped, valid ones assigned; warning event emitted on the EgressIP for an invalid selector | default behavior, no-churn, invalid-selector handling & event |
| matchExpressions | In / NotIn / Exists / DoesNotExist; matchLabels+matchExpressions spread | `matchExpressions` support |
| health-check scoping | only probe nodes matching ≥1 EIP selector; start probing after a matching EIP is added; stop after the last matching EIP is deleted; overlapping selectors; CloudPrivateIPConfig only for matching node; secondary-host-network + selector intersection | health-check membership reconciliation, cloud + multi-NIC interaction |

**Run:**
```bash
cd go-controller/
make test WHAT=pkg/clustermanager GINKGO_FOCUS="Egress Node Selector Operations"
```

## 4. E2E Tests

### 4.1 Upstream

File: `test/e2e/egressip.go`, inside the existing `DescribeTableSubtree` that fans
out across network types (CDN / UDN / Dynamic-UDN).

| `It` block | Validates | Network types |
|------------|-----------|---------------|
| `[Primary EgressIP] egressNodeSelector lifecycle` | 12-step lifecycle: node-first & EIP-first ordering; label add/remove → pending/reassign; selector update (pool round-trip + pool→hostname type change); EIP delete → node-IP fallback; anti-churn on unrelated label/selector changes; multi-IP active-active→active-passive; concurrent label+selector churn converges without duplication | CDN/UDN/D-UDN |
| `[Primary EgressIP] egressNodeSelector backward compatibility: legacy egress-assignable label` | omitted selector → CRD default (`egress-assignable: Exists`); healthcheck down/up → pending/reassign; label remove/restore → pending/reassign; EIP delete → node-IP fallback | CDN/UDN/D-UDN |
| `[Primary EgressIP] egressNodeSelector mixed fleet: legacy and custom selectors coexist` | legacy + custom selectors partition without cross-contamination; per-pod traffic isolation; add pool label → new eligibility without churning existing; egress-assignable remove/restore → pending/reassign; migrate legacy→custom selector moves the EIP | CDN/UDN/D-UDN |
| `[Primary EgressIP] egressNodeSelector multiple label ops in a single patch move the EgressIP` | atomic multi-label patch convergence, no dup/loss | CDN/UDN/D-UDN |
| `[Primary EgressIP] egressNodeSelector scopes health-check probes to matching nodes` | probes hit only matching nodes | CDN |
| `[Multi-NIC EgressIP] egressNodeSelector restricts assignment to labeled node` | selector + secondary host network intersection | CDN |

Tests 1–4 run on CDN/UDN/D-UDN. Tests 5 and 6 are CDN-only via the
`isUserDefinedNetwork` guard — test 5 because health-check probing is network-type
agnostic (CDN coverage suffices), test 6 because secondary-host EgressIP is
unsupported on UDNs.

**Run (Kind):**
```bash
cd test/
make -C e2e WHAT=egressip GINKGO_FOCUS="egressNodeSelector"
```

### 4.2 Downstream (OpenShift / OTE)

The same upstream `test/e2e` specs run downstream via the openshift-tests-extension
(OTE) binary built from `openshift/`. Downstream-specific notes:

- **Feature gate:** the EgressIP node selector API is gated behind the
  `EgressIPNodeSelector` feature gate added in
  [openshift/api#3032](https://github.com/openshift/api/pull/3032). Downstream we
  need to tag these specs with `[FeatureGate:EgressIPNodeSelector]` so the origin
  test selector runs them only where the gate is enabled (i.e. TechPreview clusters
  until the gate graduates to Default). While the feature is TechPreview (pre-GA) we
  will add a **`core-networking-serial-ote-techpreview`** lane that runs on a TechPreview-enabled cluster so these gated specs actually execute.
- **CI lanes (post-GA):** these are `[Feature:EgressIP]` and `[Serial]` specs
  (`openshift/test/annotate/rules.go`), so they run in the **core-networking serial
  OTE** lanes — the serial variant is required because EgressIP tests mutate node
  labels / readiness and must not run in parallel. They are **not** part of the
  parallel conformance suite. These lanes run the specs **unconditionally only once
  the gate is Default (post-GA)**; before then the gated specs execute via the
  `ote-techpreview` lane above. We plan to run the downstream tests in these lanes
  (across cloud providers and bare-metal dual-stack):
  - `pull-ci-openshift-ovn-kubernetes-main-e2e-aws-core-networking-serial-ote`
  - `pull-ci-openshift-ovn-kubernetes-main-e2e-azure-core-networking-serial-ote`
  - `pull-ci-openshift-ovn-kubernetes-main-e2e-gcp-core-networking-serial-ote`
  - `pull-ci-openshift-ovn-kubernetes-main-e2e-metal-ipi-core-networking-dualstack-serial-ote`
- **Regenerate the test list** after the specs land upstream and are vendored:
  ```bash
  make -C openshift update   # refreshes zz_generated.annotations.go / tests.go
  ```
  Confirm the new `egressNodeSelector` specs appear with the expected
  `[Feature:EgressIP][FeatureGate:EgressIPNodeSelector][Serial][Suite:...]`
  annotations.
- **Periodics & graduation:** beyond per-PR presubmits, we will hook these specs
  into **periodic** jobs so they run continuously against nightlies (not just on PRs
  touching this area). First they run in the **TechPreview periodics** (via the
  `ote-techpreview` lane). Once they pass at a sufficient rate there, we hook them
  into the **GA periodics** (the post-GA core-networking serial OTE lanes above).
  With those periodics wired into the component-readiness signal, we graduate the
  feature — promoting the `EgressIPNodeSelector` gate from TechPreview to Default (and
  the specs move from gated to unconditional conformance accordingly).

## 5. Cross-Feature Tests

These confirm the selector composes with adjacent EgressIP features. The selector
is IP-family- and network-type-agnostic (it only affects control-plane node
choice), so these are regression guards rather than new datapath logic.

| Interaction | What to verify | Notes |
|-------------|----------------|-------|
| **Dual-stack / IPv6** | selector filtering works for IPv4-only, IPv6-only, and dual-stack EgressIP assignments; correct source IP on egress | exercised on the **metal-ipi dual-stack serial OTE lane** (§4.2) — the on-prem dual-stack lane gives IPv4/IPv6/dual-stack datapath coverage; unit tests already parametrize the families |
| **UDN (User Defined Networks)** | EgressIP with `egressNodeSelector` works for pods on a UDN | run on `e2e-aws-core-networking-serial-ote`, `e2e-azure-core-networking-serial-ote`, `e2e-gcp-core-networking-serial-ote`, `e2e-metal-ipi-core-networking-dualstack-serial-ote` |
| **Multi-NIC (secondary host network)** | assignment only to a node satisfying **both** the selector and the secondary-host-network constraint | run on `e2e-aws-core-networking-serial-ote`, `e2e-azure-core-networking-serial-ote`, `e2e-gcp-core-networking-serial-ote`, `e2e-metal-ipi-core-networking-dualstack-serial-ote` |
| **Cloud (CloudPrivateIPConfig)** | `CloudPrivateIPConfig` created only for the selector-matched node | run on `e2e-aws-core-networking-serial-ote`, `e2e-azure-core-networking-serial-ote`, `e2e-gcp-core-networking-serial-ote`, `e2e-metal-ipi-core-networking-dualstack-serial-ote` |

Dynamic UDN is **not supported on OpenShift**, so the Dynamic-UDN interaction does
not need downstream coverage (the upstream `DescribeTableSubtree` D-UDN fan-out in
§4.1 covers it where it is supported).

The matrix is otherwise already exercised by the `DescribeTableSubtree` network-type
fan-out in §4.1 and the lanes in §4.2 — dual-stack via the on-prem dual-stack lane,
cloud via the AWS/Azure/GCP lanes.

## 6. Scale Testing

### 6.1 Health check

#### 6.1.1 What the health check does

`ovnkube-cluster-manager` (the EgressIP leader) periodically probes every egress
candidate node to decide whether it is reachable and therefore usable for
assignment. **On OpenShift the probe is always a gRPC health check** served by
`ovnkube-node` on each node's management-port IP: the Cluster Network Operator
renders `egressip-node-healthcheck-port` unconditionally (it defaults
`OVN_EGRESSIP_HEALTHCHECK_PORT` to **9107** when unset — see
`pkg/network/ovn_kubernetes.go` and `bindata/.../004-config.yaml` in
openshift/cluster-network-operator). Upstream ovn-kubernetes additionally supports a
legacy mode when the port is `0` — a plain TCP dial to port 9 (discard) via
`isReachableLegacy` — but OpenShift never sets `0`, so that path is not exercised
downstream and is noted here only for completeness.

```
 ovnkube-cluster-manager (leader)                    ovnkube-node  (every candidate node)
 ┌──────────────────────────────────────┐             ┌─────────────────────────────────────┐
 │ egressIPClusterController            │             │ EgressIPHealthServer                │
 │                                      │             │  gRPC server bound on               │
 │ checkEgressNodesReachability()       │             │  <nodeMgmtIP>:<healthCheckPort>     │
 │   time.Ticker, every 5s              │             │  (grpc_health_v1.Health)            │
 │        │                             │   gRPC      │                                     │
 │        ▼                             │  Health.    │  Check(service="Service_Egress_IP") │
 │ checkEgressNodesReachabilityIterate()│  Check ───▶│      → SERVING                      │
 │        │                             │ (TLS opt.)  │                                     │
 │        ▼                             │ ◀──────────│                                     │
 │ isReachableViaGRPC()                 │  SERVING    └─────────────────────────────────────┘
 │   EgressIPHealthClient.Connect/Probe │
 └──────────────────────────────────────┘
```

Key parameters (OVNKubernetesFeature config):

| Setting | Flag | Default | Meaning |
|---------|------|---------|---------|
| Health-check port | `egressip-node-healthcheck-port` | **9107 on OpenShift** (CNO; `0` is the upstream default) | gRPC port on the node's mgmt IP. **`0` ⇒ upstream-only legacy mode** (TCP dial to port 9 / discard); OpenShift always sets 9107, so gRPC is always used downstream |
| Reachability timeout | `egressip-reachability-total-timeout` | `1` (second) | per-poll dial/probe budget. `0` disables reachability checks entirely |
| Probe interval | *(constant)* | `5s` (`egressIPReachabilityCheckInterval`) | timer period of the loop |
| TLS | `EgressIPHealthCheckTLS` (cert/key, CA, CN) | insecure if unset | optional mTLS on the gRPC channel |

Flow per poll (`checkEgressNodesReachabilityIterate`,
`go-controller/pkg/clustermanager/egressip_controller.go:730`): for each candidate
node the client either `Connect`s (first time) or sends a `Probe`
(`grpc_health_v1.Health.Check` with service `Service_Egress_IP`, expecting
`SERVING`). A node that was reachable and fails is removed from assignment; a node
that becomes reachable is re-added.

#### 6.1.2 What behaviour changed (and why it's a scale question)

For scale, the only behaviour that matters is this periodic health-check loop,
because it runs unconditionally on a timer in cluster-manager. **On master its cost
was a function of node count only.** The `egressNodeSelector` feature is exactly
what makes it *also* a function of EgressIP count: every tick, the loop now compiles
every EgressIP's selector and matches each node against them. That new
`node-count × EgressIP-count` term is the whole reason this is a scale question at
all — it is introduced by the node selector, nothing else.

Concretely, per tick the PR adds:
- `compileEgressNodeSelectors()` — list all EgressIPs + one
  `metav1.LabelSelectorAsSelector()` per object → **O(EIPs)**;
- `matchesAnyEgressIPSelector()` per node → **O(nodes × EIPs)** `selector.Matches()`.

Master did neither — it only checked two boolean flags per node, then probed.

#### 6.1.3 Measuring it with a Go benchmark

A **[Go benchmark](https://pkg.go.dev/testing#hdr-Benchmarks)** is Go's built-in way
to time a piece of code: you write a `BenchmarkXxx(b *testing.B)` function that runs
the target in a loop `b.N` times (Go auto-tunes `b.N` for a stable measurement) and
`go test -bench` reports:
- **`ns/op`** — nanoseconds per operation, i.e. the average wall-clock time for one
  call (one "op" = one loop iteration). 1 ns = 10⁻⁹ s, so 1,000,000 ns = 1 ms.
- **`B/op`** — bytes of heap memory allocated per call (with `-benchmem`).
- **`allocs/op`** — number of heap allocation events per call (with `-benchmem`).

It's a stopwatch wired into the test toolchain. The reported `ns/op` is wall-clock
time; because we fake the probe (no network/blocking), that time is all CPU work —
which is exactly the cost we want to isolate.

It is the right instrument here precisely because it lets us **remove the network
probe from the measurement**. On a real cluster the probe is the dominant term and
it is *unchanged* by this PR; the quantity under scrutiny is only the added
selector-handling CPU. The benchmark fakes the health client (probes return
instantly), so what it measures *is* the new `O(EIPs)` + `O(nodes × EIPs)` cost and
nothing else — the master-vs-PR delta is exactly what the feature adds.

The benchmark lives **not in this test-plan commit** but in the two benchmark PRs:
`go-controller/pkg/clustermanager/egressip_controller_bench_test.go`,
`BenchmarkCheckEgressNodesReachabilityIterate`. The
[feature PR](https://github.com/openshift/ovn-kubernetes/pull/3564) carries the
version that compiles against the egressNodeSelector API; the
[baseline PR](https://github.com/openshift/ovn-kubernetes/pull/3563) carries the
master-API-adapted version. It sweeps nodes {50, 120, 250} × EIPs
{0, 10, 50, 100, 250} × selector {custom, default}, where `custom` is the
`O(nodes × EIPs)` worst case (non-matching nodes evaluate every selector) and
`default` reproduces master's probe set. Run it from a checkout of either branch:

**Benchmark node model:** `total nodes` is the whole cluster. Every node has
`isEgressAssignable = true` (the field means "node has host-CIDRs"). The first
`min(total nodes, 50)` nodes are the `eligible nodes`, labeled `egress-assignable=""`
and `egress-pool=pool-0`; the remaining `total nodes − 50` carry no labels.

Which eligible nodes are actually probed differs by code path: **master** probes all
50 eligible nodes whenever they are labeled, regardless of EIP count (so 50 labeled
nodes + 0 EIPs still means 50 probes); the **feature** probes an eligible node only
when some EIP selector matches it, so at `EIPs = 0` it probes none.

EIP → node matching across the sweep (10/50/100/250 EIPs):
- **default**: every EIP uses the `egress-assignable` selector, so **all N EIPs match
  all 50 eligible nodes**.
- **custom**: EIP *i* selects `egress-pool=pool-i`, so **only EIP-0 matches the 50
  eligible nodes**; EIPs 1…N−1 select empty pools and match no node. This is
  intentional — it maximizes selector-evaluation work: an eligible node short-circuits
  on EIP-0, but every non-matching node (the `total nodes − 50`) must evaluate all N
  selectors before failing. On top of that, **every** poll pays an `O(EIPs)` cost to
  list all EgressIPs and compile their selectors, independent of node count — which is
  why even the 50-node rows (no non-matching nodes) still grow with EIP count. So the
  feature's per-poll cost is `O(EIPs)` (list + compile) + `(total nodes − 50) × EIPs`
  (non-matching selector checks).

```bash
cd go-controller/
go test ./pkg/clustermanager/ -run=NONE \
  -bench=BenchmarkCheckEgressNodesReachabilityIterate -benchmem -benchtime=200x
```

**Results (dev laptop, Intel i7-11850H; `-benchtime=100x -count=6`, mean ns/op —
reproduce on your own hardware):**

Master's loop iterates the whole `nodeAllocator` cache — one entry per cluster node,
i.e. `total nodes` — and for each node either probes it (the 50 eligible ones) or
calls `Disconnect` (the rest, cheap). It never lists EgressIPs. So master's
per-poll time scales only with `total nodes` (cache size), not with the eligible-node
count (fixed 50) and not with EIP count: ≈ **20 µs** @ 50, ≈ **26 µs** @ 120, ≈
**34 µs** @ 250 total nodes. Allocations are constant at ~200/op (they come from the
50 probes, which are capped). This is the baseline the feature is compared against.

Full sweep below. Each row is one scenario (a node count × an EgressIP-object
count); the value in each column is the mean time for **one** health-check poll
(`checkEgressNodesReachabilityIterate`) in that scenario, in microseconds
(µs = 10⁻⁶ s; 1000 µs = 1 ms). Columns:

- **master µs** — one poll on **master code** (no `egressNodeSelector` feature), from
  the baseline PR [openshift/ovn-kubernetes#3563](https://github.com/openshift/ovn-kubernetes/pull/3563).
  Flat down each node group because master's loop never lists EgressIPs, so EIP
  count doesn't affect it.
- **PR custom µs** — one poll on the **feature code** (feature PR
  [openshift/ovn-kubernetes#3564](https://github.com/openshift/ovn-kubernetes/pull/3564))
  where every EgressIP has its own distinct custom selector. This is the **worst
  case**: a node that matches none of them must test *all* selectors before giving up
  (the full `O(nodes × EIPs)`).
- **PR default µs** — one poll on the **feature code** (same feature PR
  [#3564](https://github.com/openshift/ovn-kubernetes/pull/3564)) where EgressIPs use
  the *default* selector (`k8s.ovn.org/egress-assignable`), i.e. the same probe set as
  master. Represents the common/backward-compatible case.
- **(allocs)** — heap allocations per poll (see the caveat below on why the PR's are
  inflated by the test fake client).

`eligible nodes` = labeled egress-assignable nodes (capped at 50), constant across
rows; `total nodes` varies. "Eligible" is not "probed": master probes all 50 at every
EIP count (including 0); the feature probes only selector-matched eligible nodes (none
at `EIPs = 0`).

| total nodes | eligible nodes | EIPs | master µs | PR custom µs (allocs) | PR default µs (allocs) |
|------:|------:|-----:|----------:|----------------------:|-----------------------:|
| 50  | 50 | 0   | ~20 | 9.7 (39)    | 7.8 (39)    |
| 50  | 50 | 10  | ~20 | 67.2 (406)  | 53.6 (376)  |
| 50  | 50 | 50  | ~20 | 146.1 (972) | 105.4 (822) |
| 50  | 50 | 100 | ~20 | 224.3 (1675)| 198.2 (1375)|
| 50  | 50 | 250 | ~20 | 462.0 (3779)| 425.7 (3029)|
| 120 | 50 | 0   | ~26 | 9.8 (39)    | 9.7 (39)    |
| 120 | 50 | 10  | ~26 | 63.8 (406)  | 56.7 (376)  |
| 120 | 50 | 50  | ~26 | 158.6 (972) | 154.4 (822) |
| 120 | 50 | 100 | ~26 | 255.3 (1675)| 262.1 (1375)|
| 120 | 50 | 250 | ~26 | 559.5 (3779)| 590.2 (3029)|
| 250 | 50 | 0   | ~34 | 14.8 (39)   | 13.7 (39)   |
| 250 | 50 | 10  | ~34 | 74.3 (406)  | 74.6 (376)  |
| 250 | 50 | 50  | ~34 | 190.4 (972) | 186.7 (822) |
| 250 | 50 | 100 | ~34 | 345.7 (1675)| 357.7 (1375)|
| 250 | 50 | 250 | ~34 | 786.8 (3779)| 867.8 (3029)|

Reading the sweep:
- At 0 EIPs the feature is faster than master (9.8 µs vs 26 µs at 120 total nodes):
  no node matches a selector, so none are probed, whereas master probes all 50
  eligible nodes.
- Per-poll time has two EIP-dependent parts: the `O(EIPs)` EgressIP list + selector
  compile (paid on every poll regardless of node count — this is why the 50-node rows,
  which have no non-matching nodes, still grow with EIP count), plus
  `(total nodes − 50) × EIPs` selector checks on non-matching nodes. At `120 | 250` it
  is 559.5 µs (custom) / 590.2 µs (default) = 0.56–0.59 ms; at `250 | 250`, 786.8 /
  867.8 µs = 0.79–0.87 ms. The probe interval is 5 s. (1000 µs = 1 ms; the table is in
  µs.)
- The cost the feature adds per poll is the master→PR delta: +533 µs at `120 | 250`
  (26 → 559) and +753 µs at `250 | 250` (34 → 787).
- custom ≈ default per row, so selector matching itself is cheap; the per-poll EgressIP
  list + selector compile account for most of the growth and most of the allocations
  (see the caveat below).

> **Caveat on the allocation numbers.** The PR benchmark's `B/op` and `allocs/op` are
> inflated by the **fake clientset deep-copying every EgressIP on each `List`** (that
> is most of the reported bytes/allocs, and why they scale so steeply with EIP count).
> On a real cluster that list is served from the apiserver **watch cache**
> (`List(ResourceVersion:"0")`), with a different, cheaper allocation profile. So the
> **CPU (`ns/op`) is the trustworthy comparative signal**, not the raw allocation
> counts — and even on `ns/op` the worst case stays sub-millisecond.

Reproduce the master-vs-PR diff with `benchstat` (master's loop lacks the
compile/match step, so the diff *is* the added cost):
```bash
go install golang.org/x/perf/cmd/benchstat@latest

# master baseline: on a branch off master, cherry-pick the benchmark and adapt it to
# master's API (drop the labels/egressNodeSelector fields master doesn't have), then:
go test ./pkg/clustermanager/ -run=NONE -bench=BenchmarkCheckEgressNodesReachabilityIterate \
  -benchmem -benchtime=100x -count=6 | tee /tmp/master.txt
# feature branch:
go test ./pkg/clustermanager/ -run=NONE -bench=BenchmarkCheckEgressNodesReachabilityIterate \
  -benchmem -benchtime=100x -count=6 | tee /tmp/pr.txt

benchstat /tmp/master.txt /tmp/pr.txt
```

> **NOTE:** The benchmark PRs #3563 (baseline) and #3564 (feature) are not planned to
> be merged. No CI lane runs benchmarks — Go runs `Benchmark*` only under
> `go test -bench`, which no lane invokes — so the table above was produced by running
> both locally and diffing with `benchstat`. The PRs only host the two variants for
> reference. The feature-variant benchmark itself can be kept long-term by landing it
> in the upstream feature PR, if the reviewers find it useful. Note, however, that
> without a stored baseline or an automated comparison on stable hardware, a retained
> benchmark cannot catch regressions on its own — it is a one-time analysis and an
> on-demand before/after harness, not a regression guard.

#### 6.1.4 Why the benchmark is enough — no elaborate perf/scale run needed

The added code is **pure, in-memory control-plane CPU**. The thing that dominates
the loop's wall-clock on a real cluster is the reachability **probe to each node
across the underlay network** — a gRPC round-trip that is ~hundreds of µs to several
ms *per node*. The benchmark shows the entire selector compile+match for 120 nodes ×
250 EIPs is ~0.59 ms *total*. So on a real cluster the added work is **smaller than
the jitter on a single probe**, and the probe itself is **unchanged** by this PR
(identical set for the default selector, only smaller for custom selectors).

That means a large-scale cluster run cannot usefully measure this change: the signal
we care about is buried under the underlay probe time and its variance — "the probe
takes up too much to do anything measurable." A 120-node cluster would cost real
money and a perf-team intake to produce a master-vs-PR number that is within
measurement noise. The benchmark removes the probe from the equation and answers the
exact question the PR review raised, deterministically and for free.

#### 6.1.5 Does the benchmark need log statements?

**No.** Earlier we considered patching `checkEgressNodesReachabilityIterate` with
temporary `klog` timing to read poll duration from cluster-manager logs — that is
only needed when timing on a live cluster, where you can't instrument the call
directly. The benchmark measures the function call directly and `go test -bench`
reports ns/op itself, so no log statements, no metrics wiring, and no cluster are
required. The `benchstat` output is the artifact.
