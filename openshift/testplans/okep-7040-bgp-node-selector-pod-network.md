<!--
SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
SPDX-License-Identifier: Apache-2.0
-->

# Test Plan: OKEP-7040 BGP NodeSelector for PodNetwork RouteAdvertisements

## 1. Metadata

| Field | Value |
|-------|-------|
| Feature | BGP `RouteAdvertisements.spec.nodeSelector` with `PodNetwork` — selective pod-subnet advertisement via gateway nodes |
| Epic | [CORENET-5911](https://redhat.atlassian.net/browse/CORENET-5911) |
| OKEP | [OKEP-7040: BGP nodeSelector for PodNetwork](https://github.com/ovn-kubernetes/ovn-kubernetes/blob/master/docs/okeps/okep-7040-bgp-node-selector-for-pod-network.md) |
| Upstream PR | [ovn-kubernetes/ovn-kubernetes#7204](https://github.com/ovn-kubernetes/ovn-kubernetes/pull/7204) |
| Upstream OKEP PR | [ovn-kubernetes/ovn-kubernetes#7041](https://github.com/ovn-kubernetes/ovn-kubernetes/pull/7041) |
| Downstream feature gate | _TBD — update when [openshift/api](https://github.com/openshift/api) PR exists_ |
| Components impacted | `ovnkube-cluster-manager` (`routeadvertisements` controller + pod watch), `networkmanager` (`podAdvertisements` / SNAT scope), `ovnkube-node` (breth0 ingress steering) |
| Data plane impact | Yes — gateway breth0 cluster-CIDR flows for ingress; SNAT disabled on RA-selected nodes when RA `nodeSelector` + `PodNetwork` is active |


## 2. Introduction

Today, `RouteAdvertisements` with `PodNetwork` in `advertisements` is rejected at the
CRD level (CEL) and at runtime unless `nodeSelector` is empty, requiring every node to
participate in pod-network BGP advertisement. This feature removes that restriction for
overlay BGP (through Geneve) on the default cluster network and primary Layer 2
and Layer 3 cluster user-defined networks (CUDNs).

Two independent selectors compose to describe the desired state:
`FRRConfiguration.spec.nodeSelector` controls which nodes peer with external BGP routers;
`RouteAdvertisements.spec.nodeSelector` controls whose pod subnets (L3) or pod IPs (L2)
are advertised externally. When RA `nodeSelector` is non-empty and `PodNetwork` is
advertised, the BGP gateway nodes peer with external routers and advertise pod routes
for all RA-selected nodes — not only their own subnet.

When RA `nodeSelector` is empty, behavior is unchanged from today (each BGP node
advertises only its own subnet). `NoOverlay` transport with a non-empty RA `nodeSelector`
+ `PodNetwork` is rejected at runtime.

Three code paths changed:

- **RA controller** (FRR prefix generation): L3 gateways now collect all RA-selected
  nodes' individual host subnets (`/24`/`/64`); L2 gateways with a non-empty RA
  `nodeSelector` advertise **only** per-pod `/32`/`/128` routes for Running pods on
  RA-selected nodes. Eligibility uses **`pod.status.phase == Running`**, **`spec.hostNetwork == false`**, pod on an
  RA-selected node, and a valid pod-network IP from the OVN pod annotation at reconcile time — not container
  waiting/restart state (the shared pod informer clears `status.containerStatuses`; see
  `go-controller/pkg/factory/factory.go`). Pods in `CrashLoopBackOff` keep `phase: Running`, so their `/32`/`/128`
  remains advertised until phase leaves `Running` or the pod is deleted. With an empty RA `nodeSelector`, L2
  `PodNetwork` advertisement is unchanged from today. A new pod informer triggers RA reconcile on pod phase or
  OVN IP annotation changes (`podNeedsUpdate` in `routeadvertisements/controller.go`), so L2 `/32` prefixes track
  the live pod set.
- **Network manager** (`podAdvertisements` / SNAT scope): pods on nodes selected by the
  RA `nodeSelector` egress with their own pod IP as the source address (SNAT —
  node-IP masquerade — is disabled on those nodes). This is required because the external
  network has BGP-learned routes for pod IPs and must be able to route return traffic back
  to them.
- **Node bridge config** (breth0 ingress steering): gateway nodes receive a priority-290
  flow matching the cluster supernet (`/16`), steering all pod traffic for RA-selected
  nodes into the overlay. This sits below the gateway's own host-subnet flow at
  priority-300 — local pod traffic (destined for `ovn-worker3`'s own `/24`) continues
  to hit priority-300 first and is delivered directly; remote pod traffic (destined for
  `ovn-worker`'s `/24`) falls through to priority-290 and is Geneve-forwarded.


## 3. Test Topology

The Kind BGP test topology for the nodeSelector feature extends the existing BGP suite
to introduce a split between a BGP gateway node and non-gateway worker nodes. All unit
tests in §4 and E2E tests in §5 refer to the node names defined here.

```
                                                           ingress (return traffic):
                                                    external → FRR → ovn-worker3 → Geneve → pod
  -----------------     ----------------     -------------------------------------------------
  |               |     |              |     |                KIND cluster                   |
  |   external    |<----|  FRR router  |---->+                                               |
  |    server     |     |  (bgpnet)    |     |  ---------------------                        |
  -----------------     ----------------     |  | ovn-control-plane |                        |
        |                     ^              |  ---------------------                        |
        |  egress (pod A IP,  |  BGP session |                                               |
        |  via ovn-worker     |  (iBGP/eBGP) |  +---------------------------+                |
        |  host default route, +-------------|  | ovn-worker3 (role=gateway)|                |
        |  bypasses ovn-worker3)             |  | FRR nodeSelector match    | BGP gateway    |
        |                                    |  | RA nodeSelector match     | node           |
        |                                    |  | pod C (local to gateway)  |                |
        |                                    |  +---------------------------+                |
        |                                    |         |         |                           |
        |                                    |     Geneve    Geneve  (ingress overlay)       |
        |                                    |         |         |                           |
        +------------------------------------+  +------+--+    +----+---------+              |
                                             |  | ovn-    |    | ovn-worker2  |              |
                                             |  | worker  |    | (no FRR match|              |
                                             |  | RA match|    | no RA match) |              |
                                             |  | pod A   |    |  pod B       |              |
                                             |  +---------+    +--------------+              |
                                              -------------------------------------------------
```

Key properties:

- **`ovn-worker3`** is the BGP gateway node: matched by **both** `FRRConfiguration.nodeSelector`
  (`role=gateway`) and `RouteAdvertisements.spec.nodeSelector`. It peers with the external
  FRR router and also has its own pod subnet included in the advertisement. FRR ∩ RA =
  `{ovn-worker3}` — the non-empty intersection required for `Accepted=True`.
- **`ovn-worker`** is matched by `RouteAdvertisements.spec.nodeSelector` only: no FRR
  peering; its pod subnet (L3) or pod IPs (L2) are advertised externally *by `ovn-worker3`
  on its behalf* — this proxy advertisement is the core new behaviour under test.
- **`ovn-worker2`** is matched by **neither** selector: no FRR peering, not RA-selected.
  Its pods are **not** reachable from external. It serves as the concrete negative-assertion
  node throughout the test plan.
- **Ingress:** both ingress paths are steered by breth0 table-0 flows on `ovn-worker3`,
  but at different priorities:
  - **Priority-300** (pre-existing): matches `ovn-worker3`'s **own** pod subnet (`/24`).
    Traffic destined for pod C (local to `ovn-worker3`) hits this flow first and is
    delivered locally — no Geneve hop.
  - **Priority-290** (new, added by this feature): matches the **cluster CIDR** (`/16`).
    Traffic destined for pod A (on `ovn-worker`, a different `/24`) does not match
    priority-300, falls through to priority-290, and is forwarded into the Geneve
    overlay toward `ovn-worker`. This is the key new breth0 flow introduced by the
    BGP nodeSelector feature.
- **Egress:** pods on `ovn-worker` send traffic directly via the node's default gateway
  (no OVN rerouting through `ovn-worker3`); the external router's BGP-learned routes send
  return traffic back through `ovn-worker3`.


## 4. Unit Tests

### 4.1 RouteAdvertisements controller

File: `go-controller/pkg/clustermanager/routeadvertisements/controller_test.go`,
suite `OVN Route Advertisements` — existing table-driven reconcile tests using
`testRA` / `testFRRConfig` / `testNode` helpers.

**Existing test to update:** `"fails to reconcile pod network if node selector is not empty"` expects `Accepted=False`; must be removed or converted to an acceptance case.

| Sub-context | Representative `It` / table rows | Code path |
|-------------|----------------------------------|-----------|
| Non-gateway nodes excluded from generated `FRRConfiguration` | In the standard topology (FRR = `{ovn-worker3}`, RA = `{ovn-worker3, ovn-worker}`): the RA controller generates an `FRRConfiguration` **only for `ovn-worker3`**; no `FRRConfiguration` is generated for `ovn-worker` or `ovn-worker2` — neither is FRR-selected, so they must not peer with external routers. Assert the total count of generated `FRRConfiguration` objects equals exactly the number of FRR-selected nodes (one: `ovn-worker3`). | `generateFRRConfigurations` |
| CDN / L3 CUDN + empty RA `nodeSelector` | Each BGP node advertises only its own host subnet — default cluster network and primary L3 CUDN (backward compatibility) | Regression |
| CDN / L3 CUDN + non-empty RA `nodeSelector` | `ovn-worker3` (gateway) generates FRR prefixes containing the host subnets of **every** RA-selected node — `ovn-worker3` itself and `ovn-worker`; `ovn-worker2` (not RA-selected) subnet must **not** appear; nodes missing subnet annotation are skipped without error. | `generateFRRConfigurations` |
| L2 + empty RA `nodeSelector` | Full L2 network subnet(s) advertised as today | Regression |
| L2 + non-empty RA `nodeSelector` | `ovn-worker3` FRR prefixes include per-pod `/32` (IPv4) or `/128` (IPv6) for pods with `status.phase == Running`, `spec.hostNetwork == false`, on `ovn-worker3` and `ovn-worker` only; pods on `ovn-worker2` (not RA-selected) must **not** generate `/32`/`/128` entries | `generateFRRConfigurations` |
| FRR selects superset of RA (FRR ⊃ RA) | FRR `nodeSelector` = `{ovn-worker3, ovn-worker2}`, RA `nodeSelector` = `{ovn-worker3, ovn-worker}`: `ovn-worker3` is the gateway (FRR ∩ RA) and generates FRRConfig with subnets of `ovn-worker3` and `ovn-worker` (all RA-selected); `ovn-worker2` is FRR-selected but **not** RA-selected — its subnet must **not** appear as a prefix and no FRRConfig is generated for it; `Accepted=True`. Verifies that the skip guard in `go-controller/pkg/clustermanager/routeadvertisements/controller.go` (`if _, selected := nodeToFRRConfig[node.Name]; !selected { continue }`) correctly excludes FRR-selected nodes that are not RA-selected from the `nodeToFRRConfig` map, so they contribute no prefixes. | `generateFRRConfigurations` |
| Pod watch → reconcile (L2) | `status.phase` transitions to `Running` with valid OVN pod-network IP annotation on a pod on `ovn-worker` → new `/32` (IPv4) or `/128` (IPv6) in `ovn-worker3`'s generated FRR config; pod delete, or phase leaving `Running` (e.g. `Failed`, `Succeeded`) → prefix withdrawn | `podController` + `podNeedsUpdate` |
| Pod lifecycle edge cases (L2) | `hostNetwork: true` pod on `ovn-worker` → no `/32`/`/128`; `Pending` (phase not `Running`) or missing IP annotation → skipped without panic or zero-IP route; **`CrashLoopBackOff` with `phase: Running`** → `/32`/`/128` route **still advertised** (same eligibility as a healthy Running pod); `CrashLoopBackoff` with `phase: Failed` → route withdrawn; pod with `deletionTimestamp` set while phase remains `Running` → prefix withdrawn on pod delete (reconcile via delete event); document observed behavior if phase changes before delete | `podNeedsUpdate` + prefix generation in `generateFRRConfigurations` |
| NoOverlay reject | Non-empty `nodeSelector` + `PodNetwork` on NoOverlay transport → `Accepted=False` (replaces old "must select all nodes" guard) | `generateFRRConfigurations` |
| EVPN transport reject | Non-empty `nodeSelector` + `PodNetwork` on EVPN transport → `Accepted=False`; EVPN uses MAC/IP advertisement rather than IP-prefix proxy routing, so the proxy-advertisement model does not apply; status condition must surface a clear rejection reason | `generateFRRConfigurations` |
| Dynamic UDN allocation reject | Non-empty `nodeSelector` + `PodNetwork` when dynamic UDN allocation is enabled → `Accepted=False`; dynamic UDN allocation is incompatible with the proxy-advertisement model because pod subnet assignments are not stable at reconcile time; status condition must surface a clear rejection reason | `generateFRRConfigurations` |
| No gateway intersection (FRR ∩ RA = ∅) | No node is matched by **both** the RA `nodeSelector` and any `FRRConfiguration.nodeSelector` — meaning there is no gateway node that can peer with external routers and advertise on behalf of the RA-selected workers → `Accepted=False`. Construct by setting FRR `nodeSelector` = `{ovn-worker3}` and RA `nodeSelector` = `{ovn-worker, ovn-worker2}` (deliberately excluding `ovn-worker3` from RA so the intersection is empty). Extends the existing test `"fails to reconcile if no FRRConfiguration is selected for selected node"`| `generateFRRConfigurations` |

**Run:**
```bash
cd go-controller/
make test WHAT=pkg/clustermanager/routeadvertisements
```

### 4.2 Network manager (SNAT / `podAdvertisements`)

File: `go-controller/pkg/networkmanager/network_controller_test.go` (`setAdvertisements`
/ sync path).

| Sub-context | Representative `It` / table rows | Code path |
|-------------|----------------------------------|-----------|
| Empty RA `nodeSelector` | When `nodeSelector` is empty it matches all nodes, so `podAdvertisements` (SNAT disable) is set for every node — same behavior as today | Regression |
| Non-empty RA `nodeSelector` + `PodNetwork` | `syncRouteAdvertisements` populates `podAdvertisements` (SNAT disable) **only** for RA-selected nodes (`ovn-worker3` and `ovn-worker`); `ovn-worker2` (not RA-selected) must **not** have SNAT disabled — this applies whether `ovn-worker2` is completely unselected (standard topology) or FRR-selected but not RA-selected | `syncRouteAdvertisements` → `setAdvertisements` |
| `eipAdvertisements` unaffected by this feature | `eipAdvertisements` — which controls which nodes advertise EgressIP addresses via BGP — must be unchanged by the nodeSelector + PodNetwork change; verify it is neither widened nor narrowed relative to its pre-existing scope (regression guard against accidental side-effects in `setAdvertisements`) | `syncRouteAdvertisements` → `setAdvertisements` |
| RA `nodeSelector` shrinks (node removed from selection) | Update RA `nodeSelector` from `{ovn-worker3, ovn-worker}` to `{ovn-worker3}` only; `syncRouteAdvertisements` must remove `ovn-worker` from `podAdvertisements` — `ovn-worker` must not retain a stale SNAT-disable entry after the selector change | `syncRouteAdvertisements` → `setAdvertisements` |
| RA deleted mid-test / `PodNetwork` removed from advertisements | After an existing `RouteAdvertisements` is deleted or `PodNetwork` is removed from its `advertisements` list, `podAdvertisements` must be cleared — no node should retain a stale SNAT-disable entry | `syncRouteAdvertisements` → `setAdvertisements` |

**Run:**
```bash
cd go-controller/
make test WHAT=pkg/networkmanager
```

### 4.3 Gateway ingress bridge flows

File: `go-controller/pkg/node/bridgeconfig/bridgeflows_test.go` (`commonFlows`
with `netConfig.Advertised` set).

| Sub-context | Representative `It` / table rows | Code path |
|-------------|----------------------------------|-----------|
| L3: cluster supernet ingress flow added on gateway | On `ovn-worker3`, table-0 flow added: `priority=290`, `nw_dst=<cluster CIDR>`, `actions=output:<patch/phys>` — one flow per address family; sits **below** the existing own-subnet flow at priority 300, so traffic to pod C (local to `ovn-worker3`) still hits priority-300 first and is delivered locally without Geneve; traffic to pod A (`ovn-worker`) falls through to priority-290 and is Geneve-forwarded to the overlay. _(Note: OKEP specifies a single cluster-supernet flow; verify against PR #7204 — if the implementation installs per-node `/24` flows instead, update assertion accordingly and file a follow-up for the supernet flow.)_ | `commonFlows` |
| L2: no new breth0 flows on gateway | For an L2 advertised network on `ovn-worker3`, assert that **no new** breth0 table-0 flows are added beyond what already exists for the L2 network subnet; existing network subnet flows handle ingress for L2 — the gateway does not need cluster-CIDR steering flows because L2 uses a flat subnet visible to all nodes | `commonFlows` (L2 path) |
| Ingress flow absent on non-gateway nodes | `ovn-worker` and `ovn-worker2` are not FRR-selected gateway nodes; the priority-290 cluster-CIDR ingress flow must **not** appear on either — only `ovn-worker3` installs it | Regression |
| SGW vs LGW | `output` port in the priority-290 flow matches each gateway mode's egress port (patch port for SGW, physical port for LGW) | Table both modes |

**Run:**
```bash
cd go-controller/
make test WHAT=pkg/node/bridgeconfig
```

### 4.4 CRD integration

`test/crd-integration/` — after CRD regen from #7204:

| What to verify |
|----------------|
| `RouteAdvertisements` with `advertisements: [PodNetwork]` + non-empty `nodeSelector` is accepted by the API server |
| Removed CEL rule (`"nodeSelector can't be specified … needs to be advertised on all nodes"`) no longer appears as a validation error |
| Remaining `RouteAdvertisements` CEL rules are unchanged |

**Run:**
```bash
cd test/
make test-crd
```


## 5. E2E Tests

### 5.1 Upstream

File: `test/e2e/route_advertisements.go` — extend the existing
`"BGP: Pod to external server when CUDN network is advertised"` `Describe` block
with new `DescribeTable` / `It` entries for the nodeSelector cases. Reuse Kind BGP scaffolding
(`ENABLE_ROUTE_ADVERTISEMENTS`, external `bgpserver` / `frr`, `network-segmentation`
flag). Use `feature.RouteAdvertisements` and `feature.NetworkSegmentation` labels;
`ginkgo.Serial` when cordoning gateway nodes or mutating node labels.

| `It` block | Validates | Gateway mode | Networks |
|------------|-----------|--------------|----------|
| `[BGP nodeSelector] L3 CUDN gateway advertises RA-selected nodes' host subnets` | External RIB shows individual `/24` host subnets for `ovn-worker3` and `ovn-worker` (the two RA-selected nodes); `ovn-worker2` subnet is **not** in RIB (negative assertion); curl from external server reaches pod C (`ovn-worker3`) directly and pod A (`ovn-worker`) via Geneve; pod B (`ovn-worker2`) is unreachable from external | SGW + LGW | Primary L3 CUDN |
| `[BGP nodeSelector] L3 CUDN ingress: local pod direct, remote pod via Geneve` | Traffic destined for pod C (on `ovn-worker3`) is delivered locally via priority-300 own-subnet flow — no Geneve; traffic destined for pod A (on `ovn-worker`) does not match priority-300, falls through to the priority-290 cluster-supernet flow, and is Geneve-encapsulated by `ovn-worker3` to `ovn-worker` — verify with `ovs-ofctl dump-flows br-ex` (confirm the cluster-supernet `/16` flow at priority-290 is present) and `tcpdump` on `ovn-worker3`'s uplink (confirm Geneve encapsulation), no drops or loops | SGW + LGW | Primary L3 CUDN |
| `[BGP nodeSelector] L3 CUDN selective advertisement: non-RA node unreachable` | Using the standard topology (RA selects `{ovn-worker3, ovn-worker}`): external server reaches pod on `ovn-worker` via `ovn-worker3`; pod on `ovn-worker2` is **not** reachable (negative assertion — `ovn-worker2` not RA-selected, subnet not advertised); add `ovn-worker2` to RA `nodeSelector` and verify it becomes reachable | SGW | Primary L3 CUDN, CDN |
| `[BGP nodeSelector] L2 CUDN gateway advertises per-pod /32 (/128) for RA-selected nodes` | External RIB contains a `/32` (IPv4) or `/128` (IPv6) per running pod on `ovn-worker3` and `ovn-worker` (RA-selected); pods on `ovn-worker2` (not RA-selected) must **not** appear as `/32`/`/128` prefixes; curl from external server reaches RA-selected pods via host routes; pod B (`ovn-worker2`) is unreachable from external | SGW | Primary L2 CUDN |
| `[BGP nodeSelector] L2 CUDN /32 (/128) advertised on pod create` | With RA already active, create a new pod on `ovn-worker`; within the convergence window its `/32` (IPv4) or `/128` (IPv6) prefix appears in the external RIB and the pod is reachable from the external server; verifies the pod informer triggers reconcile on pod IP annotation becoming available | SGW | Primary L2 CUDN |
| `[BGP nodeSelector] L2 CUDN /32 (/128) withdrawn on pod delete` | Delete pod on `ovn-worker` → its `/32` (IPv4) or `/128` (IPv6) prefix removed from external RIB within convergence window; remaining `/32`/`/128` routes for other RA-selected pods stay; `ovn-worker2` has no host route entries at any point (not RA-selected) | SGW | Primary L2 CUDN |
| `[BGP nodeSelector] patch RA nodeSelector updates RIB and connectivity` | Start with the standard topology RA = `{ovn-worker3, ovn-worker}`; expand the RA nodeSelector's selection to `{ovn-worker3, ovn-worker, ovn-worker2}`, then `ovn-worker2`'s subnet/pods appear in RIB and `ovn-worker2` becomes externally reachable; shrink RA nodeSelector's selection back to `{ovn-worker3, ovn-worker}` — `ovn-worker2` routes withdrawn with no stale entries | SGW | CDN |
| `[BGP nodeSelector] non-BGP node egress uses pod IP with asymmetric return` | Pod on `ovn-worker` curls external server; source IP in server echo is pod IP (SNAT off, not `ovn-worker`'s node IP); return traffic enters cluster via `ovn-worker3`, crosses Geneve overlay to `ovn-worker` | SGW + LGW | Primary L3 CUDN |
| `[BGP nodeSelector] gateway HA: failover to second gateway` | **Step 0 (FRR ⊃ RA checkpoint):** add `ovn-worker2` to the `FRRConfiguration.nodeSelector` (FRR-selected) but keep the RA `nodeSelector` as `{ovn-worker3, ovn-worker}`; verify `ovn-worker2`'s subnet is **not** in the external RIB and its pod B is unreachable — confirms a FRR-selected node that is not RA-selected is silently excluded from prefix generation. **Step 1:** also add `ovn-worker2` to the RA `nodeSelector` (now both FRR- and RA-selected); verify its subnet enters the RIB. **Step 2:** take `ovn-worker3` down; external ingress to pods on `ovn-worker` continues via `ovn-worker2` (HA failover). | SGW | CDN |
| `[BGP nodeSelector] zero gateway match: RA degrades cleanly` | RA `nodeSelector` matches `ovn-worker` and `ovn-worker2` but no `FRRConfiguration` peers those nodes (`ovn-worker3` is the only FRR peer but is not in the RA selector) — RA `Accepted=False`; status condition surfaces clear reason; no panic or stale FRR configs | n/a | Primary L3 CUDN |
| `[BGP nodeSelector] rejects NoOverlay transport` | RA with non-empty `nodeSelector` + `PodNetwork` on a NoOverlay network → RA `Accepted=False` | n/a | Negative |
| `[BGP nodeSelector] rejects EVPN transport` | RA with non-empty `nodeSelector` + `PodNetwork` on a primary EVPN CUDN with `transport: EVPN` → RA `Accepted=False`; status condition surfaces a clear rejection reason (EVPN uses MAC/IP advertisement, not IP-prefix proxy routing). Label `feature.EVPN` (and `feature.RouteAdvertisements`) so the spec is selected on the `evpn` CI lane (`make -C test control-plane WHAT="EVPN"`) | n/a | Negative (EVPN CUDN) |

Tests for L3 CUDN and CDN run on SGW and LGW via a table. L2 CUDN tests run SGW
only (LGW coverage deferred pending further design). Negative transport rejection
specs: NoOverlay on the `bgp-no-overlay` lane; EVPN on the `evpn` lane (§4.1 unit
coverage mirrors both rejections).

**Run (Kind — after specs land):**
```bash
cd test/
make -C e2e WHAT=bgp GINKGO_FOCUS="BGP nodeSelector"
```

**Upstream CI:** no new matrix entries needed. The existing lanes in
`.github/workflows/test.yml` already carry the required flags:
- `target: bgp` (SGW + LGW, dual-stack, `routeadvertisements: advertise-default`,
  `network-segmentation: enable-network-segmentation`) picks up all nodeSelector specs
  automatically via `feature.RouteAdvertisements` label selection.
- `target: bgp-no-overlay` picks up the NoOverlay rejection spec.
- `target: evpn` (`WHAT="EVPN"`) picks up the EVPN rejection spec when labeled
  `feature.EVPN` (see table row above; not covered by existing EVPN specs today).

Confirm each new spec is selected by at least one lane after wiring CI.

### 5.2 Downstream (OpenShift / OTE)

The same upstream `test/e2e` specs run downstream via the openshift-tests-extension
(OTE) binary built from `openshift/`.

- **Feature gate:** if OpenShift introduces a feature gate for selective PodNetwork
  advertisement, tag specs with `[FeatureGate:<gate>]` so the origin test selector
  runs them only on TechPreview-enabled clusters until GA. While the feature is
  TechPreview (pre-GA), add a **`core-networking-serial-ote-techpreview`** lane so
  these gated specs actually execute. Post-GA they run unconditionally in the
  core-networking serial OTE lanes.
- **CI lanes:** all `[Feature:RouteAdvertisements]` specs require a BGP-enabled cluster
  and belong in the **core-networking serial OTE** lanes — BGP is only available there.
  Tag all nodeSelector specs `[Serial]`: they share the same gateway node (`ovn-worker3`)
  and FRR configuration, so concurrent execution would cause interference regardless of
  whether an individual spec mutates cluster state. Planned lanes:
  - `pull-ci-openshift-ovn-kubernetes-main-e2e-aws-core-networking-serial-ote`
  - `pull-ci-openshift-ovn-kubernetes-main-e2e-azure-core-networking-serial-ote`
  - `pull-ci-openshift-ovn-kubernetes-main-e2e-gcp-core-networking-serial-ote`
  - `pull-ci-openshift-ovn-kubernetes-main-e2e-metal-ipi-core-networking-dualstack-serial-ote`
- **Regenerate the test list** after specs land upstream and are vendored:
  ```bash
  make -C openshift update   # refreshes zz_generated.annotations.go / tests.go
  ```
  Confirm new specs appear with the expected
  `[Feature:RouteAdvertisements][Serial][Suite:...]` annotations (plus
  `[FeatureGate:…]` if applicable).
- **Periodics & graduation:** hook into TechPreview periodics first; once passing at
  sufficient rate, graduate to the GA core-networking serial OTE periodics and
  promote the feature gate from TechPreview to Default.

### 5.3 Upgrade Testing (Downstream)

This feature removes a CEL validation rule and introduces new control-plane and
data-plane behavior, so upgrade continuity must be verified explicitly.

| Scenario | What to verify | How |
|----------|----------------|-----|
| **Existing RA survives upgrade** | A cluster with a pre-existing `RouteAdvertisements` using empty `nodeSelector` + `PodNetwork` (the current valid configuration) upgrades to the new version; pod-to-external connectivity is uninterrupted throughout the rolling upgrade window | OTE upgrade lane — reuse the existing `BGP: When default podNetwork is advertised` spec; assert connectivity before, during, and after upgrade |

**CI lane:** route these specs through the OpenShift upgrade lane that has BGP /
RouteAdvertisements enabled (e.g., a variant of
`pull-ci-openshift-ovn-kubernetes-main-e2e-aws-upgrade` with
`ENABLE_ROUTE_ADVERTISEMENTS=true`). If no such lane exists yet, file a follow-up
to add one as part of the GA graduation checklist.


## 6. Cross-Feature Tests

These confirm the selective nodeSelector composes with adjacent BGP and networking
features. The selector affects control-plane FRR generation and SNAT scope; the
underlying OVN datapath for east-west traffic is unchanged.

| Interaction | What to verify | Notes |
|-------------|----------------|-------|
| **EgressIP** | EgressIP assignment and SNAT/redirect work correctly on both `ovn-worker3` (BGP gateway) and `ovn-worker` / `ovn-worker2` (non-BGP nodes) when RA `nodeSelector` + `PodNetwork` is active | OKEP goal; `eipAdvertisements` still scoped to RA-selected nodes (§4.2) |
| **Dual-stack / IPv6** | Selective advertisement, ingress steering, and pod-IP egress work for IPv4, IPv6, and dual-stack CUDNs; `/32` and `/128` prefixes both appear in RIB | metal-ipi dual-stack serial OTE lane |
| **KubeVirt live migration (L2)** | With the standard topology (single BGP gateway: FRR ∩ RA = `{ovn-worker3}`), live-migrate a VM between two RA-selected workers (e.g. `ovn-worker` → `ovn-worker3`): the **same** gateway (`ovn-worker3`) updates its generated FRR prefixes — the VM's old `/32`/`/128` is withdrawn and the post-migration pod IP is advertised within the convergence window; the external BGP session does not move to another node. A **gateway handoff** (withdraw on one FRR peer, advertise on another) applies only when multiple nodes are in FRR ∩ RA (e.g. HA after `ovn-worker2` is added to both selectors); state that topology and condition explicitly in a separate spec | Existing KubeVirt suite patterns in `test/e2e/kubevirt.go` |
| **SNAT scope isolation across networks** | When RA with non-empty `nodeSelector` is active on one network (e.g. a primary L3 CUDN), it disables SNAT only for pods on **that specific network** on `ovn-worker3` and `ovn-worker`; pods on other networks on those same nodes (e.g. the CDN or another primary CUDN) must continue to egress with the node IP (SNAT still active) — verify `podAdvertisements` is scoped per-network and does not accidentally affect co-located pods on non-advertised networks | SNAT-scope regression |
| **NoOverlay** | Non-empty RA `nodeSelector` + `PodNetwork` is rejected at runtime for NoOverlay transport → `Accepted=False` | Negative — `bgp-no-overlay` lane |
| **EVPN** | EVPN transport behavior is unchanged by this feature; existing EVPN advertisement and MAC/IP routes are unaffected when RA `nodeSelector` is introduced on a non-EVPN network in the same cluster | Regression — `evpn` lane |
| **Dynamic UDN allocation** | Rejection at runtime (upstream only; unsupported on OpenShift) | Upstream `Feature:RouteAdvertisementsDynamicUDN` lane |

## 7. Scale Testing

Scale testing is **out of scope** for this test plan. A dedicated scale test plan
should be created by the PerfScale team covering areas such as FRR prefix count growth
(L3 host subnets, L2 per-pod `/32` churn), RA reconcile latency under selector
expansion, and cloud provider BGP session route limits.
