#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Compare performance reports between current PR run and baseline.

This script parses performance report markdown files and generates
comparison tables showing deltas for:
- Pod Ready Latency metrics
- CPU usage per container type
- Memory usage per container type

Usage:
    python compare-reports.py --current report.md --baseline baseline.md --output enhanced.md
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, Optional


def calc_delta(current: Optional[float], baseline: Optional[float], decimals: int = 1) -> str:
    """
    Calculate delta and percentage change with safe division.

    Returns 'N/A' if baseline is zero or either value is None.
    """
    if current is None or baseline is None or baseline == 0:
        return 'N/A'

    delta = current - baseline
    percent = (delta / baseline) * 100

    sign = '+' if delta > 0 else ''
    percent_sign = '+' if percent > 0 else ''

    return f"{sign}{delta:.{decimals}f} ({percent_sign}{percent:.1f}%)"


def parse_latency_metrics(content: str) -> Dict[str, Optional[float]]:
    """Parse pod ready latency metrics from markdown content."""
    avg_match = re.search(r'\| Average Latency \| \*\*([0-9.]+) ms\*\*', content)
    max_match = re.search(r'\| Max Latency \| \*\*([0-9.]+) ms\*\*', content)
    min_match = re.search(r'\| Min Latency \| \*\*([0-9.]+) ms\*\*', content)
    total_match = re.search(r'\| Total Pods \| \*\*([0-9]+)\*\*', content)

    return {
        'avg': float(avg_match.group(1)) if avg_match else None,
        'max': float(max_match.group(1)) if max_match else None,
        'min': float(min_match.group(1)) if min_match else None,
        'total': int(total_match.group(1)) if total_match else None
    }


def parse_cpu_table(content: str) -> Dict[str, Dict[str, float]]:
    """Parse CPU usage table from markdown content."""
    # More specific regex: match exact separator line structure for 4-column table
    pattern = r'### CPU Usage Summary\n\| Container Type \| Avg CPU \(%\) \| Max CPU \(%\) \| Data Points \|\n\|[-]+\|[-]+\|[-]+\|[-]+\|\n([\s\S]*?)(?=\n\n|$)'
    match = re.search(pattern, content)

    if not match:
        return {}

    data = {}
    rows = match.group(1).strip().split('\n')

    for row in rows:
        parts = [s.strip() for s in row.split('|') if s.strip()]
        if len(parts) >= 4:
            container_type = parts[0]
            try:
                data[container_type] = {
                    'avg': float(parts[1].replace('%', '')),
                    'max': float(parts[2].replace('%', '')),
                    'data_points': int(parts[3])
                }
            except (ValueError, IndexError):
                # Skip malformed rows
                continue

    return data


def parse_memory_table(content: str) -> Dict[str, Dict[str, float]]:
    """Parse Memory usage table from markdown content."""
    # More specific regex: match exact separator line structure for 4-column table
    pattern = r'### Memory Usage Summary\n\| Container Type \| Avg Memory \(MB\) \| Max Memory \(MB\) \| Data Points \|\n\|[-]+\|[-]+\|[-]+\|[-]+\|\n([\s\S]*?)(?=\n\n|$)'
    match = re.search(pattern, content)

    if not match:
        return {}

    data = {}
    rows = match.group(1).strip().split('\n')

    for row in rows:
        parts = [s.strip() for s in row.split('|') if s.strip()]
        if len(parts) >= 4:
            container_type = parts[0]
            try:
                data[container_type] = {
                    'avg': float(parts[1].replace(' MB', '')),
                    'max': float(parts[2].replace(' MB', '')),
                    'data_points': int(parts[3])
                }
            except (ValueError, IndexError):
                # Skip malformed rows
                continue

    return data


def create_latency_comparison_table(current: Dict, baseline: Dict) -> str:
    """Create comparison table for latency metrics."""
    rows = [
        '| Metric | Current | Baseline | Change |',
        '|--------|---------|----------|--------|'
    ]

    if current['avg'] is not None and baseline['avg'] is not None:
        rows.append(
            f"| Average Latency | **{current['avg']:.1f} ms** | "
            f"{baseline['avg']:.1f} ms | {calc_delta(current['avg'], baseline['avg'])} |"
        )

    if current['max'] is not None and baseline['max'] is not None:
        rows.append(
            f"| Max Latency | **{current['max']:.0f} ms** | "
            f"{baseline['max']:.0f} ms | {calc_delta(current['max'], baseline['max'], 0)} |"
        )

    if current['min'] is not None and baseline['min'] is not None:
        rows.append(
            f"| Min Latency | **{current['min']:.0f} ms** | "
            f"{baseline['min']:.0f} ms | {calc_delta(current['min'], baseline['min'], 0)} |"
        )

    if current['total'] is not None and baseline['total'] is not None:
        total_delta = current['total'] - baseline['total']
        sign = '+' if total_delta > 0 else ''
        rows.append(
            f"| Total Pods | **{current['total']}** | "
            f"{baseline['total']} | {sign}{total_delta} |"
        )
    elif current['total'] is not None:
        rows.append(f"| Total Pods | **{current['total']}** | - | - |")

    return '\n'.join(rows) + '\n\n'


def create_cpu_comparison_table(current: Dict, baseline: Dict) -> str:
    """Create comparison table for CPU metrics."""
    rows = [
        '| Container Type | Avg CPU (Current) | Avg CPU (Baseline) | Change | Max CPU (Current) | Max CPU (Baseline) | Change |',
        '|----------------|-------------------|-------------------|--------|-------------------|-------------------|--------|'
    ]

    for container_type, curr_data in current.items():
        base_data = baseline.get(container_type)

        if base_data:
            avg_change = calc_delta(curr_data['avg'], base_data['avg'], 2)
            max_change = calc_delta(curr_data['max'], base_data['max'], 2)
            rows.append(
                f"| {container_type} | **{curr_data['avg']:.2f}%** | "
                f"{base_data['avg']:.2f}% | {avg_change} | "
                f"**{curr_data['max']:.2f}%** | {base_data['max']:.2f}% | {max_change} |"
            )
        else:
            rows.append(
                f"| {container_type} | **{curr_data['avg']:.2f}%** | - | - | "
                f"**{curr_data['max']:.2f}%** | - | - |"
            )

    return '\n'.join(rows) + '\n\n'


def create_memory_comparison_table(current: Dict, baseline: Dict) -> str:
    """Create comparison table for Memory metrics."""
    rows = [
        '| Container Type | Avg Memory (Current) | Avg Memory (Baseline) | Change | Max Memory (Current) | Max Memory (Baseline) | Change |',
        '|----------------|----------------------|-----------------------|--------|----------------------|-----------------------|--------|'
    ]

    for container_type, curr_data in current.items():
        base_data = baseline.get(container_type)

        if base_data:
            avg_change = calc_delta(curr_data['avg'], base_data['avg'], 2)
            max_change = calc_delta(curr_data['max'], base_data['max'], 2)
            rows.append(
                f"| {container_type} | **{curr_data['avg']:.2f} MB** | "
                f"{base_data['avg']:.2f} MB | {avg_change} | "
                f"**{curr_data['max']:.2f} MB** | {base_data['max']:.2f} MB | {max_change} |"
            )
        else:
            rows.append(
                f"| {container_type} | **{curr_data['avg']:.2f} MB** | - | - | "
                f"**{curr_data['max']:.2f} MB** | - | - |"
            )

    return '\n'.join(rows) + '\n\n'


def add_baseline_comparison(current_content: str, baseline_content: str, baseline_url: str = None) -> str:
    """
    Add baseline comparison to performance report.

    Args:
        current_content: Current PR performance report markdown
        baseline_content: Baseline performance report markdown
        baseline_url: Optional URL to baseline workflow run

    Returns:
        Enhanced markdown with comparison tables
    """
    if not baseline_content:
        return current_content + '\n\n> ℹ️ **No baseline data available for comparison**\n'

    enhanced = current_content

    # Compare Pod Latency metrics FIRST (before adding baseline header)
    current_latency = parse_latency_metrics(current_content)
    baseline_latency = parse_latency_metrics(baseline_content)

    if current_latency['avg'] is not None and baseline_latency['avg'] is not None:
        latency_table = create_latency_comparison_table(current_latency, baseline_latency)
        # Match from the Pod Latency header through the table until the next ## section
        # Use a non-greedy match to capture everything up to the next section
        latency_section_regex = r'(## 🎯 Pod Ready Latency \(Main KPI\)\n)(.*?)(?=\n## |\Z)'

        def replace_latency_section(match):
            # Replace the entire section content with just the comparison table
            return match.group(1) + latency_table

        # Check if pattern exists before replacing
        if re.search(latency_section_regex, enhanced, re.DOTALL):
            enhanced = re.sub(
                latency_section_regex,
                replace_latency_section,
                enhanced,
                count=1,
                flags=re.DOTALL
            )

    # Add baseline info header AFTER table replacement
    baseline_ref = f'[workflow]({baseline_url})' if baseline_url else 'N/A'
    enhanced = re.sub(
        r'## 🎯 Pod Ready Latency \(Main KPI\)',
        f'> 📊 **Baseline:** Daily run from {baseline_ref}\n\n## 🎯 Pod Ready Latency (Main KPI)',
        enhanced,
        count=1
    )

    # Compare CPU metrics - only if BOTH current and baseline have the data
    current_cpu = parse_cpu_table(current_content)
    baseline_cpu = parse_cpu_table(baseline_content)

    if current_cpu and baseline_cpu:
        cpu_table = create_cpu_comparison_table(current_cpu, baseline_cpu)
        # More strict regex: match exact separator line structure for 4-column table
        cpu_table_regex = r'### CPU Usage Summary\n\| Container Type \| Avg CPU \(%\) \| Max CPU \(%\) \| Data Points \|\n\|[-]+\|[-]+\|[-]+\|[-]+\|\n((?:\|[^\n]+\|\n)+)'

        # Check if pattern exists before replacing
        if re.search(cpu_table_regex, current_content):
            enhanced = re.sub(
                cpu_table_regex,
                f'### CPU Usage Summary\n{cpu_table}',
                enhanced,
                count=1
            )

    # Compare Memory metrics - only if BOTH current and baseline have the data
    current_memory = parse_memory_table(current_content)
    baseline_memory = parse_memory_table(baseline_content)

    if current_memory and baseline_memory:
        memory_table = create_memory_comparison_table(current_memory, baseline_memory)
        # More strict regex: match exact separator line structure for 4-column table
        memory_table_regex = r'### Memory Usage Summary\n\| Container Type \| Avg Memory \(MB\) \| Max Memory \(MB\) \| Data Points \|\n\|[-]+\|[-]+\|[-]+\|[-]+\|\n((?:\|[^\n]+\|\n)+)'

        # Check if pattern exists before replacing
        if re.search(memory_table_regex, current_content):
            enhanced = re.sub(
                memory_table_regex,
                f'### Memory Usage Summary\n{memory_table}',
                enhanced,
                count=1
            )

    return enhanced


def main():
    parser = argparse.ArgumentParser(
        description='Compare performance reports and generate comparison tables'
    )
    parser.add_argument(
        '--current',
        required=True,
        type=Path,
        help='Path to current performance report markdown file'
    )
    parser.add_argument(
        '--baseline',
        type=Path,
        help='Path to baseline performance report markdown file'
    )
    parser.add_argument(
        '--baseline-url',
        help='URL to baseline workflow run'
    )
    parser.add_argument(
        '--output',
        type=Path,
        help='Output path for enhanced report (default: stdout)'
    )

    args = parser.parse_args()

    # Read current report
    if not args.current.exists():
        print(f"Error: Current report not found: {args.current}", file=sys.stderr)
        sys.exit(1)

    current_content = args.current.read_text()

    # Read baseline report if provided
    baseline_content = None
    if args.baseline:
        if not args.baseline.exists():
            print(f"Warning: Baseline report not found: {args.baseline}", file=sys.stderr)
        else:
            baseline_content = args.baseline.read_text()

    # Generate enhanced report
    enhanced = add_baseline_comparison(current_content, baseline_content, args.baseline_url)

    # Write output
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(enhanced)
        print(f"Enhanced report written to: {args.output}", file=sys.stderr)
    else:
        print(enhanced)

    return 0


if __name__ == '__main__':
    sys.exit(main())
