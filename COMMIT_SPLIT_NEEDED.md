# Commit Split Required: Chassis-ID vs Pod Batching

## Issue

This PR (fix-OCPBUGS-61550) currently contains commits for **TWO UNRELATED** bugs:

1. **OCPBUGS-61550** - Pod batching for high-density nodes  
2. **OCPBUGS-80960** - Chassis-ID initialization timing (see util.go:242 comment)

These should be in **separate PRs** for easier review, bisect, and backport.

---

## Commits by Category

### ✅ Pod Batching (OCPBUGS-61550) - Should stay in this PR

| Commit | Description |
|--------|-------------|
| `da26bc640` | feat(ovn): Add pod batch processing for high-density nodes |
| `7e0e827cd` | fix: apply critical fixes to pod batching implementation |
| `e108d5cea` | docs: clarify batch processor runs by default but pods not routed yet |
| `290fc5fc1` | docs: fix namespace lock examples to show correct pattern |
| `736673254` | fix: prevent goroutine leak in ConnectionPool cleanup |
| `592ca7ed0` | fix: make ConnectionPool.Close idempotent and GetClient report closed state |
| `b26d8a527` | fix: correct shutdown order to prevent batch processor race |
| `7157994a6` | fix: correct imports in pod_batch_ops.go |
| `bb3735675` | fix: make batch fallback synchronous to prevent race conditions |
| `b16aa1c53` | fix: prevent double-close panic by making one layer own result delivery |
| `4d055b26e` | fix: drain entire podQueue on shutdown, not just current batch |
| `b3c0d2c5e` | fix: correct misleading comment about batching defaults |
| `46bbe1a6e` | test: add validation tests for critical OCPBUGS-61550 fixes |
| `3a91df00a` | fix: prevent timer goroutine leaks in AddPod hot path |

**Files:**
- `go-controller/pkg/ovn/pod_batch_processor.go` (new)
- `go-controller/pkg/ovn/pod_batch_ops.go` (new)
- `go-controller/pkg/ovn/pod_batch_processor_shutdown_test.go` (new)
- `go-controller/pkg/ovn/default_network_controller.go` (modified)
- `go-controller/pkg/ovn/pods.go` (modified)
- `go-controller/pkg/libovsdb/connection_pool.go` (modified)
- `go-controller/pkg/metrics/ovnkube_controller.go` (modified)
- Documentation: `CHANGES_SUMMARY.md`, `FIXES.md`, `NON_TECHNICAL_SUMMARY.md`, `SHUTDOWN_ORDER_FIX.md`, `CONNECTION_POOL_FIX.md`, `TIMER_LEAK_FIX.md`, `VALIDATION_TESTS.md`

---

### ⚠️ Chassis-ID (OCPBUGS-80960) - Should be split to separate PR

| Commit | Description |
|--------|-------------|
| `6063a9165` | feat(node): use node annotation as source of truth for chassis-id |
| `6d7849a58` | feat(node): update gateway initialization to use annotation-first chassis-id |
| `e477a83eb` | test: add unit tests for GetNodeChassisIDWithFallback |
| `25e8e53af` | fix(node): address code review issues in chassis-id implementation |
| `1797f7e5c` | fix: align chassis-ID test cases with actual implementation |
| `b96fd5197` | fix: fail fast when chassis-ID cannot be synced to OVS |

**Files:**
- `go-controller/pkg/util/util.go` - GetNodeChassisIDWithFallback() function
- `go-controller/pkg/util/util_unit_test.go` - TestGetNodeChassisIDWithFallback()
- `go-controller/pkg/util/chassis_id_sync_validation_test.go` (new)
- `go-controller/pkg/node/gateway.go` (modified)
- `go-controller/pkg/node/gateway_init.go` (modified)
- `go-controller/pkg/node/gateway_shared_intf.go` (modified)
- Partial: `CHANGES_SUMMARY.md` (Fix #6), `FIXES.md` (Fix #6)

**Call sites:** `go-controller/pkg/node/gateway*.go` (gateway code, NOT pod batching)

**Reference:** Line 242 in util.go has comment `// See: OCPBUGS-80960`

---

## Why This Matters

| Aspect | With Mixed Commits | With Split PRs |
|--------|-------------------|----------------|
| **Review** | Reviewers must understand TWO unrelated features | Each PR focused on ONE feature |
| **Bisect** | If something breaks, which change caused it? | Clear isolation of changes |
| **Backport** | May want to backport one but not the other | Can backport independently |
| **Jira bot** | Red warning (PR says 61550, code has 80960 comment) | Clean, aligned |
| **Merge conflicts** | Changes from two unrelated areas | Isolated changes |

---

## Recommended Action

### Option 1: Split Now (Cleanest)

1. Create new branch `fix-OCPBUGS-80960-chassis-id` from `main`
2. Cherry-pick chassis-ID commits: `6063a9165`, `6d7849a58`, `e477a83eb`, `25e8e53af`, `1797f7e5c`, `b96fd5197`
3. Resolve any conflicts (node/gateway files may have diverged)
4. Create separate PR for chassis-ID referencing OCPBUGS-80960
5. Remove chassis-ID commits from current PR:
   - Revert changes to `go-controller/pkg/util/util.go`
   - Revert changes to `go-controller/pkg/util/util_unit_test.go`
   - Delete `go-controller/pkg/util/chassis_id_sync_validation_test.go`
   - Revert changes to `go-controller/pkg/node/gateway*.go`
   - Remove Fix #6 from `CHANGES_SUMMARY.md` and `FIXES.md`

### Option 2: Document and Proceed

1. Add note to PR description:
   ```
   Note: This PR contains chassis-ID fixes (OCPBUGS-80960) which should 
   be split to a separate PR. Chassis-ID changes are in:
   - go-controller/pkg/util/util.go
   - go-controller/pkg/node/gateway*.go
   ```
2. Proceed with review, split later if needed

### Option 3: I Can Do the Split

If you want me to handle the split:

1. I'll create a clean pod-batching-only branch
2. Cherry-pick only pod-batching commits
3. Create a separate chassis-ID branch
4. Manually apply chassis-ID changes (avoiding merge conflicts)
5. Push both branches
6. You create two separate PRs

---

## File Ownership Breakdown

### Pod Batching ONLY
- All `pkg/ovn/pod_batch_*` files ✓
- `pkg/ovn/default_network_controller.go` (batch processor init/stop) ✓
- `pkg/ovn/pods.go` (batching comment) ✓
- `pkg/libovsdb/connection_pool.go` (used by batch processor) ✓
- `pkg/metrics/ovnkube_controller.go` (batch metrics) ✓

### Chassis-ID ONLY
- `pkg/util/util.go` (GetNodeChassisIDWithFallback) ⚠️
- `pkg/util/*_test.go` (chassis-ID tests) ⚠️
- `pkg/node/gateway*.go` (gateway initialization) ⚠️

### Mixed (need cleanup)
- `CHANGES_SUMMARY.md` - has both (Fix #6 = chassis-ID, rest = batching)
- `FIXES.md` - has both (Fix #6 = chassis-ID, rest = batching)

---

## Impact of Not Splitting

- PR review delayed (reviewers must understand two features)
- Jira bot keeps warning about mismatched bug numbers
- Harder to backport selectively
- Harder to bisect regressions
- Violates single-responsibility principle for PRs

---

## Your Choice

Which option would you like to proceed with?

1. **I'll split it** - Tell me to create the separate branches
2. **Document and proceed** - I'll add a note to PR description
3. **You'll handle it** - You'll manually split the commits later

Let me know how you'd like to proceed.
