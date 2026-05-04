#!/usr/bin/env python3
"""
perf-stats.py — compute distributional statistics from perf-sample.sh JSONL.

Each input row has:
  {"iteration": 1, "metrics": {"registration_ops_sec": 18727, ...}, ...}

For every metric present in any sample, compute:
  - n (sample count)
  - min / max / range
  - mean
  - median
  - mode (binned for floats — bin width = max(1, range/30))
  - sample standard deviation (n-1 denominator)
  - coefficient of variation (std / mean)
  - sample skewness (Fisher–Pearson, bias-corrected)
  - sample excess kurtosis (Fisher, bias-corrected)
  - distinct-value count (rough proxy for resolution / quantization)

Output:
  - Markdown-ish table to stdout
  - Optional JSON dump via --output-json

Higher moments (skewness, kurtosis) require N >> 30 to be reliable; this
script computes them at any N but flags the SE so callers can judge.

Usage:
  python3 scripts/test/perf-stats.py /tmp/perf-samples.jsonl
  python3 scripts/test/perf-stats.py /tmp/perf-samples.jsonl --output-json provenance.json
"""

import argparse
import collections
import json
import math
import statistics
import sys


def fisher_pearson_skew(xs):
    """Sample skewness, bias-corrected (Fisher–Pearson, same as pandas/scipy bias=False)."""
    n = len(xs)
    if n < 3:
        return None
    m = statistics.fmean(xs)
    s = statistics.stdev(xs)
    if s == 0:
        return 0.0
    g1 = sum((x - m) ** 3 for x in xs) / n / (s ** 3)
    # bias correction factor
    return math.sqrt(n * (n - 1)) / (n - 2) * g1


def fisher_excess_kurt(xs):
    """Sample excess kurtosis, bias-corrected (same as pandas/scipy bias=False)."""
    n = len(xs)
    if n < 4:
        return None
    m = statistics.fmean(xs)
    s = statistics.stdev(xs)
    if s == 0:
        return 0.0
    g2 = sum((x - m) ** 4 for x in xs) / n / (s ** 4) - 3.0
    # bias correction factor (matches numpy/pandas/scipy bias=False)
    return ((n + 1) * g2 + 6) * (n - 1) / ((n - 2) * (n - 3))


def binned_mode(xs, bin_count=30):
    """Return the centre of the most-populated bin. Useful for floats where
    no two samples share an exact value."""
    if not xs:
        return None
    lo, hi = min(xs), max(xs)
    if lo == hi:
        return lo
    width = (hi - lo) / bin_count
    if width == 0:
        return lo
    counts = collections.Counter(int((x - lo) / width) for x in xs)
    bin_idx, _ = counts.most_common(1)[0]
    return lo + (bin_idx + 0.5) * width


def standard_error_skew(n):
    """Approximate SE of sample skewness for a normal distribution."""
    if n < 3:
        return float('inf')
    return math.sqrt(6.0 * n * (n - 1) / ((n - 2) * (n + 1) * (n + 3)))


def standard_error_kurt(n):
    """Approximate SE of sample excess kurtosis for a normal distribution."""
    if n < 4:
        return float('inf')
    return 2.0 * standard_error_skew(n) * math.sqrt((n * n - 1) / ((n - 3) * (n + 5)))


def collect_metrics(jsonl_path):
    """Return dict[metric_name] -> list[float], plus run-level metadata list."""
    by_metric = collections.defaultdict(list)
    runs = []
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            runs.append(row)
            for k, v in row.get("metrics", {}).items():
                if isinstance(v, (int, float)):
                    by_metric[k].append(float(v))
    return by_metric, runs


def stats_for(values):
    n = len(values)
    if n == 0:
        return None
    out = {
        "n": n,
        "min": min(values),
        "max": max(values),
        "range": max(values) - min(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "mode_binned": binned_mode(values),
        "stdev": statistics.stdev(values) if n >= 2 else 0.0,
        "distinct": len(set(values)),
    }
    out["cv_pct"] = (out["stdev"] / out["mean"] * 100.0) if out["mean"] else 0.0
    out["skew"] = fisher_pearson_skew(values)
    out["kurtosis_excess"] = fisher_excess_kurt(values)
    out["se_skew"] = standard_error_skew(n)
    out["se_kurt"] = standard_error_kurt(n)
    return out


def fmt_num(x, width=14):
    if x is None:
        return f"{'—':>{width}}"
    if isinstance(x, int):
        return f"{x:>{width},}"
    if abs(x) >= 1e6:
        return f"{x:>{width},.1f}"
    if abs(x) < 0.01 and x != 0:
        return f"{x:>{width}.4g}"
    return f"{x:>{width},.3f}"


def render_table(per_metric):
    headers = [
        ("metric", 32, "<"),
        ("n", 4, ">"),
        ("mean", 14, ">"),
        ("median", 14, ">"),
        ("mode_bin", 14, ">"),
        ("stdev", 14, ">"),
        ("cv%", 8, ">"),
        ("skew (SE)", 18, ">"),
        ("kurt-3 (SE)", 18, ">"),
        ("distinct", 8, ">"),
        ("range", 14, ">"),
    ]
    line = "  ".join(f"{h:{a}{w}}" for h, w, a in headers)
    print(line)
    print("  ".join("-" * w for _, w, _ in headers))

    for name in sorted(per_metric):
        s = per_metric[name]
        if s is None:
            continue
        skew_str = f"{s['skew']:.3f} ({s['se_skew']:.2f})" if s['skew'] is not None else "—"
        kurt_str = f"{s['kurtosis_excess']:.3f} ({s['se_kurt']:.2f})" if s['kurtosis_excess'] is not None else "—"
        row = [
            f"{name:<32}",
            f"{s['n']:>4d}",
            fmt_num(s['mean']),
            fmt_num(s['median']),
            fmt_num(s['mode_binned']),
            fmt_num(s['stdev']),
            f"{s['cv_pct']:>7.2f}",
            f"{skew_str:>18}",
            f"{kurt_str:>18}",
            f"{s['distinct']:>8d}",
            fmt_num(s['range']),
        ]
        print("  ".join(row))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", help="path to perf-sample.sh JSONL output")
    ap.add_argument("--output-json", help="write a structured provenance JSON here")
    args = ap.parse_args()

    by_metric, runs = collect_metrics(args.jsonl)
    if not runs:
        print(f"perf-stats: no rows in {args.jsonl}", file=sys.stderr)
        return 2

    per_metric = {name: stats_for(values) for name, values in by_metric.items()}

    print(f"\nperf-stats: {len(runs)} samples from {args.jsonl}")
    print(f"           SE columns are estimated standard errors at this n,"
          f" assuming normality.\n")
    render_table(per_metric)

    if args.output_json:
        provenance = {
            "__schema": "perf-baseline-provenance/v1",
            "source_jsonl": args.jsonl,
            "n_samples": len(runs),
            "iterations_min": min(r["iteration"] for r in runs),
            "iterations_max": max(r["iteration"] for r in runs),
            "first_started_at": min(r["started_at"] for r in runs),
            "last_started_at": max(r["started_at"] for r in runs),
            "metrics": per_metric,
        }
        with open(args.output_json, "w") as f:
            json.dump(provenance, f, indent=2, sort_keys=True)
        print(f"\nperf-stats: wrote {args.output_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
