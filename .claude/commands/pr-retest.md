---
description: Find and retest failed e2e CI jobs on a PR
argument-hint: <pr-number>
---

## Name
pr-retest

## Synopsis
```
/pr-retest <pr-number>
```

## Description
Analyzes a pull request in the openshift/ovn-kubernetes repository to find all failed e2e CI jobs and payload jobs,
providing detailed failure statistics and interactive options to retest them. The command:
1. Identifies standard e2e jobs from PR status checks with consecutive failure counts
2. Identifies payload jobs from the most recent /payload run with consecutive failure tracking
3. Presents interactive retest options for both job types

## Implementation

IMPORTANT: Execute this command immediately without asking for permission or confirmation first.

## PART 1: E2E JOBS

### Step 1: Analyze e2e job failures

1. Fetch the PR's status checks using `gh pr view --json statusCheckRollup`
2. Filter for jobs matching `ci/prow/.*e2e.*` with state "FAILURE" or "ERROR"
3. **IMPORTANT**: Also check for jobs with state "PENDING" - these are currently running and should NOT be included in the failed jobs list
4. Fetch prow history page: `https://prow.ci.openshift.org/pr-history?org=openshift&repo=ovn-kubernetes&pr=<pr-number>`
5. Parse the HTML to find each failed e2e job (excluding PENDING ones) and count:
   - Consecutive failures (from newest to oldest)
   - Total failures, passes, aborted runs
6. Display results with format:
   ```
   ❌ e2e-aws-ovn-edge-zones
      Consecutive failures: 3
      Total: 3 fail / 0 pass / 1 aborted
   ```
7. If there are PENDING jobs, optionally show them separately:
   ```
   ⏳ Currently running: e2e-aws-ovn-edge-zones (will not retest)
   ```

### Step 2: Present e2e retest options

If failed e2e jobs are found, use the AskUserQuestion tool to present these options:

1. **Retest selected** - Provide a space-separated list of job names to retest
2. **Retest all failed** - Automatically retest ALL currently failing e2e jobs with individual `/test` commands
3. **Use /retest** - Post a single `/retest` comment to rerun all failed tests
4. **Just show list** - Display the failed jobs without taking action

### Step 3: Execute e2e retest choice

Based on the selected option:

**Option 1 - Retest selected:**
- Ask user to provide a space-separated list of job names (e.g., "e2e-aws-ovn e2e-gcp-ovn")
- Parse the input and split by whitespace to get individual job names
- Create a comment body with one `/test <job>` line per selected job
- Post the single comment to the PR using `gh pr comment`

Example: If user provides "e2e-aws-ovn e2e-gcp-ovn", post comment:
```
/test e2e-aws-ovn
/test e2e-gcp-ovn
```

**Option 2 - Retest all failed:**
- Automatically create a comment with `/test <job>` for each currently failing e2e job
- Post the single comment to the PR using `gh pr comment`

Example: If e2e-aws-ovn-edge-zones and e2e-gcp-ovn are failing, post comment:
```
/test e2e-aws-ovn-edge-zones
/test e2e-gcp-ovn
```

**Option 3 - Use /retest:**
- Post a comment containing just `/retest`

**Option 4 - Just show list:**
- No further action, continue to payload jobs

## PART 2: PAYLOAD JOBS

### Step 4: Analyze payload job failures

1. Parse all PR comments to find those containing `pr-payload-tests.ci.openshift.org` URLs
2. **CRITICAL**: Sort chronologically by comment creation timestamp (not lexicographically by URL) and extract all payload run URLs in chronological order. The most recent URL should be last.
3. Fetch the MOST RECENT payload run page and parse ALL jobs:
   - Jobs with `<span class="text-success">` (PASS) - green/passed jobs
   - Jobs with `<span class="text-danger">` (FAIL) - red/failed jobs
   - Jobs with `<span class="">` (no color class) - black text/currently RUNNING jobs
4. **CRITICAL LOGIC**: A job should ONLY be considered "failed and needing retest" if:
   - It does NOT appear in the latest run at all (not running, not passed, not failed), AND
   - It failed in a previous run
   - **OR** It appears with text-danger (red/FAIL) in the latest run
5. Jobs that appear in the latest run with black text (running) should be EXCLUDED from the retest list because they are already being retested
6. For each job that qualifies as "failed and needing retest":
   - Check previous payload runs to count consecutive failures
   - **IMPORTANT**: Skip runs where the job doesn't exist (e.g., a ci job won't be in a nightly run)
   - Keep searching backwards through runs until you find the job and check if it passed or failed
7. Display results with format:
   ```
   ❌ periodic-ci-openshift-release-master-ci-4.21-e2e-gcp-ovn-upgrade
      Consecutive failures: 2
   ```
8. If jobs are currently running in the latest run, show them separately:
   ```
   ⏳ Currently running: 7 payload jobs (already being retested)
   ```

### Step 5: Present payload retest options

If failed payload jobs are found, use the AskUserQuestion tool to present these options:

1. **Retest selected** - Provide a space-separated list of payload job names to retest
2. **Retest all failed** - Automatically retest ALL currently failing payload jobs with individual `/payload-job` commands
3. **Just show list** - Display the failed payload jobs without taking action

### Step 6: Execute payload retest choice

Based on the selected option:

**Option 1 - Retest selected:**
- Ask user to provide a space-separated list of full job names
- Parse the input and split by whitespace to get individual job names
- Create a comment body with one `/payload-job <job>` line per selected job
- Post the single comment to the PR using `gh pr comment`

Example: If user provides two jobs, post comment:
```
/payload-job periodic-ci-openshift-release-master-ci-4.21-e2e-gcp-ovn-upgrade
/payload-job periodic-ci-openshift-release-master-ci-4.21-e2e-aws-upgrade-ovn-single-node
```

**Option 2 - Retest all failed:**
- Automatically create a comment with `/payload-job <job>` for each currently failing payload job
- Post the single comment to the PR using `gh pr comment`

Example: If 7 payload jobs are failing, post comment with all 7:
```
/payload-job periodic-ci-openshift-release-master-ci-4.21-e2e-gcp-ovn-upgrade
/payload-job periodic-ci-openshift-release-master-ci-4.21-e2e-aws-upgrade-ovn-single-node
/payload-job periodic-ci-openshift-release-master-ci-4.21-e2e-azure-ovn-upgrade
/payload-job periodic-ci-openshift-release-master-ci-4.21-e2e-aws-ovn-techpreview
/payload-job periodic-ci-openshift-release-master-ci-4.21-e2e-aws-ovn-techpreview-serial-1of3
/payload-job periodic-ci-openshift-release-master-nightly-4.21-e2e-metal-ipi-ovn-bm
/payload-job periodic-ci-openshift-release-master-nightly-4.21-e2e-metal-ipi-ovn-ipv6
```

**Option 3 - Just show list:**
- No further action, command complete

## Example Commands

### E2E Jobs

Fetch currently failing e2e jobs (excluding running ones):
```bash
# Get failed jobs (excluding PENDING)
gh pr view <pr-number> --repo openshift/ovn-kubernetes --json statusCheckRollup | \
  jq -r '.statusCheckRollup[] |
    select(.state == "FAILURE" or .state == "ERROR") |
    select(.context | test("ci/prow/.*e2e")) |
    .context | sub("ci/prow/"; "")'

# Get currently running jobs
gh pr view <pr-number> --repo openshift/ovn-kubernetes --json statusCheckRollup | \
  jq -r '.statusCheckRollup[] |
    select(.state == "PENDING") |
    select(.context | test("ci/prow/.*e2e")) |
    .context | sub("ci/prow/"; "")'
```

Parse prow history for consecutive failures:
```bash
curl -sL 'https://prow.ci.openshift.org/pr-history?org=openshift&repo=ovn-kubernetes&pr=<pr-number>' | \
  grep -E 'job-history.*e2e|run-(success|failure|aborted)'
```

Post e2e retest comment:
```bash
gh pr comment <pr-number> --repo openshift/ovn-kubernetes --body "/test <job-name>"
```

### Payload Jobs

Extract payload run URLs from comments (sorted chronologically by timestamp):
```bash
# CORRECT: Sort by comment timestamp, then extract URLs
gh pr view <pr-number> --repo openshift/ovn-kubernetes --json comments | \
  jq -r '.comments[] | select(.body | contains("pr-payload-tests.ci.openshift.org")) |
    "\(.createdAt)|\(.body)"' | \
  sort | \
  grep -oE 'https://pr-payload-tests[^ )]+'

# Get most recent URL only:
gh pr view <pr-number> --repo openshift/ovn-kubernetes --json comments | \
  jq -r '.comments[] | select(.body | contains("pr-payload-tests.ci.openshift.org")) |
    "\(.createdAt)|\(.body)"' | \
  sort | \
  tail -1 | \
  grep -oE 'https://pr-payload-tests[^ )]+'
```

Parse payload run results (only completed jobs with success/danger classes):
```bash
# This grep filters for only text-success and text-danger, automatically excluding running jobs (plain text)
curl -sL '<payload-run-url>' | \
  grep -E 'text-(success|danger)' | \
  sed -E 's/.*<span class="text-(success|danger)">(.*)<\/span>.*/\2|\1/'
```

Post payload retest comment:
```bash
gh pr comment <pr-number> --repo openshift/ovn-kubernetes --body "/payload-job <full-job-name>"
```

## Arguments
- $1: Pull request number (required)
  - Example: 2838
