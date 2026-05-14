#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
# SPDX-License-Identifier: Apache-2.0

# Full end-to-end test of the performance report workflow
# Usage: ./test-full-workflow.sh <workflow_run_id>

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <workflow_run_id>"
  echo ""
  echo "Example: $0 12345678"
  echo ""
  echo "Get a run ID from: gh run list --workflow performance-test.yml"
  exit 1
fi

RUN_ID=$1

if [ -z "$GITHUB_TOKEN" ]; then
  echo "Error: GITHUB_TOKEN environment variable not set"
  exit 1
fi

echo " Testing Performance Report Workflow"
echo "======================================="
echo "Run ID: $RUN_ID"
echo ""

# Clean up previous test runs
rm -rf test-workflow
mkdir -p test-workflow
cd test-workflow

echo "- Step 1: Getting PR information..."
PR_INFO=$(python ../get-pr-info.py --run-id $RUN_ID --format json)
echo "Found PRs: $PR_INFO"

echo "- Step 2: Getting baseline run..."
BASELINE=$(python ../get-baseline-run.py --output json)
BASELINE_ID=$(echo "$BASELINE" | python -c "import sys, json; print(json.load(sys.stdin)['id'])")
BASELINE_URL=$(echo "$BASELINE" | python -c "import sys, json; print(json.load(sys.stdin)['url'])")
echo "Baseline Run ID: $BASELINE_ID"
echo "Baseline URL: $BASELINE_URL"

echo "- Step 3: Downloading current run test data artifacts..."
python ../download-artifacts.py \
  --run-id $RUN_ID \
  --filter "performance-test-data" \
  --output-dir current-artifacts \
  --extract

echo "- Step 4: Downloading baseline test data artifacts..."
python ../download-artifacts.py \
  --run-id $BASELINE_ID \
  --filter "performance-test-data" \
  --output-dir baseline-artifacts \
  --extract

echo "- Step 5: Generating JSON data from raw metrics..."
mkdir -p reports baseline-reports

# Process current run artifacts
for dir in current-artifacts/*performance-test-data*; do
  if [ -d "$dir" ]; then
    workload=$(basename "$dir" | sed 's/-performance-test-data-.*//')
    mkdir -p "reports/$workload"

    if [ -d "$dir/perf/metrics" ]; then
      echo "  Generating data for: $workload (current)"
      python ../generate_perf_report.py \
        --workload "$workload" \
        --metrics-dir "$dir/perf/metrics" \
        --json-output "reports/$workload/performance_data.json" \
        --output "reports/$workload/performance_report.md"
    fi
  fi
done

# Process baseline artifacts
for dir in baseline-artifacts/*performance-test-data*; do
  if [ -d "$dir" ]; then
    workload=$(basename "$dir" | sed 's/-performance-test-data-.*//')
    mkdir -p "baseline-reports/$workload"

    if [ -d "$dir/perf/metrics" ]; then
      echo "  Generating data for: $workload (baseline)"
      python ../generate_perf_report.py \
        --workload "$workload" \
        --metrics-dir "$dir/perf/metrics" \
        --json-output "baseline-reports/$workload/performance_data.json" \
        --output "baseline-reports/$workload/performance_report.md"
    fi
  fi
done

echo ""
echo "- Step 6: Comparing data with JSON..."
mkdir -p enhanced-reports

for workload_dir in reports/*/; do
  if [ -d "$workload_dir" ]; then
    workload=$(basename "$workload_dir")
    current_json="$workload_dir/performance_data.json"
    baseline_json="baseline-reports/$workload/performance_data.json"
    enhanced_report="enhanced-reports/$workload/performance_report.md"

    if [ -f "$current_json" ]; then
      echo "  Comparing: $workload"
      mkdir -p "enhanced-reports/$workload"

      if [ -f "$baseline_json" ]; then
        ../compare-reports.py \
          --current "$current_json" \
          --baseline "$baseline_json" \
          --baseline-url "$BASELINE_URL" \
          --output "$enhanced_report"
      else
        echo "      No baseline found, using current data as-is"
        ../compare-reports.py \
          --current "$current_json" \
          --output "$enhanced_report"
      fi
    else
      echo "  Warning: No JSON data found for $workload"
    fi
  fi
done

echo "- View enhanced reports:"
for report in enhanced-reports/*/performance_report.md; do
  if [ -f "$report" ]; then
    workload=$(basename $(dirname "$report"))
    echo "  cat test-workflow/enhanced-reports/$workload/performance_report.md"
  fi
done
echo ""
echo " To test PR commenting (will actually post!):"
echo "  python post-pr-comment.py \\"
echo "    --pr <PR_NUMBER> \\"
echo "    --reports-dir test-workflow/enhanced-reports \\"
echo "    --run-id $RUN_ID \\"
echo "    --run-url https://github.com/ovn-org/ovn-kubernetes/actions/runs/$RUN_ID \\"
echo "    --status success \\"
echo "    --baseline-id $BASELINE_ID \\"
echo "    --baseline-url $BASELINE_URL"
