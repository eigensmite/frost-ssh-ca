#!/usr/bin/env python3
"""
analyze_checkpoint_log.py

Parses one or more checkpoint.h-style timing log files (see frost_common.h's
cp_id_t enum) and produces:

  - per-checkpoint-id statistics: count, total, mean, median, stdev, min,
    max, p90/p95/p99
  - a per-process breakdown, with role (coordinator / signer / unknown)
    inferred from *which* cp_ids that process emitted
  - an intrinsic-vs-contingent time breakdown, using an editable
    CLASSIFICATION table below -- this is a starting point for your
    capstone analysis, not an objective fact. Adjust it to match the
    argument you want to make, and justify your choices in the writeup.
  - CSV exports of both the raw parsed events and the per-id summary,
    for further analysis/plotting in pandas/Excel/R/whatever you use
    for the report

Usage:
    python3 analyze_checkpoint_log.py run.log
    python3 analyze_checkpoint_log.py coordinator.log signer1.log signer2.log
    python3 analyze_checkpoint_log.py run.log --events-csv ev.csv --summary-csv sum.csv
    python3 analyze_checkpoint_log.py run.log --no-csv
"""

import argparse
import csv
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# ── Log line formats (must match checkpoint.c's fprintf format) ─────
EVENT_RE = re.compile(
    r'^(?P<ts>\S+)\s+\[(?P<label>[^\]]+)\]\s+'
    r'(?P<cp_id>CP_[A-Za-z0-9_]+):\s+'
    r'(?P<ms>[0-9.]+)\s+ms\s+'
    r'\((?P<file>[^:()]+):(?P<line>\d+)\)\s*$'
)

WARNING_RE = re.compile(
    r'^(?P<ts>\S+)\s+\[(?P<label>[^\]]+)\]\s+WARNING:\s+(?P<msg>.+?)\s*$'
)

# ── Role inference: which cp_ids are exclusive to one binary ─────────
# Based on frost_common.h's cp_id_t comments. Anything not listed here
# (CP_SELECT_BLOCKING, CP_TLS_HANDSHAKE, CP_TLS_RECORD_RECV/SEND) runs
# on both coordinator and signer, so it isn't a reliable role signal.
COORD_ONLY_IDS = {
    "CP_TBS_BASH", "CP_TBS_PATCH_PUBKEY", "CP_ASSEMBLE_BASH",
    "CP_AGGREGATE_BASH", "CP_MINT_BASH", "CP_DKG_RELAY_R1",
    "CP_DKG_RELAY_R2", "CP_COMMIT_ROUTE", "CP_SHARE_ROUTE",
    "CP_ROAST_FORM_SESSION", "CP_SESSION_EXPIRE_SCAN",
    "CP_PUBKEYPKG_LOAD", "CP_PUBKEYPKG_WRITE",
}
SIGNER_ONLY_IDS = {
    "CP_KEYPKG_LOAD", "CP_KEYPKG_SAVE", "CP_PUBKEY_CACHE_INIT",
    "CP_VERIFY_IDENTITY", "CP_R2_DECRYPT",
}

# ── EDIT ME: intrinsic vs contingent classification ──────────────────
# "intrinsic"  = cost inherent to the FROST/ROAST protocol and its
#                cryptography -- required computation/IO that any correct
#                implementation of this design would also pay.
# "contingent" = overhead traceable to *this* implementation's specific
#                engineering choices (select() polling granularity, the
#                event-loop's fixed timeouts, retry/timeout tuning) --
#                not something the protocol itself demands, and something
#                a different implementation could plausibly reduce.
#
# This split is a judgment call, not an objective fact -- it's here as a
# starting point. Reclassify anything you disagree with and re-run.
CLASSIFICATION = {
    # Rust subprocess calls -- real cryptographic work, unavoidable cost
    "CP_TBS_BASH":            "intrinsic",
    "CP_TBS_PATCH_PUBKEY":    "intrinsic",
    "CP_MINT_BASH":           "intrinsic",
    "CP_ASSEMBLE_BASH":       "intrinsic",
    "CP_AGGREGATE_BASH":      "intrinsic",
    # Per-message crypto / identity verification
    "CP_R2_DECRYPT":          "intrinsic",
    "CP_FROST_COMMIT_BASH":   "intrinsic",
    "CP_FROST_SIGN_BASH":     "intrinsic",
    "CP_TLS_HANDSHAKE":       "intrinsic",
    "CP_PUBKEY_CACHE_INIT":   "intrinsic",
    "CP_VERIFY_IDENTITY":     "intrinsic",
    # Disk I/O for key/share persistence -- required by the design
    "CP_KEYPKG_LOAD":         "intrinsic",
    "CP_KEYPKG_SAVE":         "intrinsic",
    "CP_PUBKEYPKG_LOAD":      "intrinsic",
    "CP_PUBKEYPKG_WRITE":     "intrinsic",
    # Message routing / relay -- the protocol requires these round trips
    "CP_DKG_RELAY_R1":        "intrinsic",
    "CP_DKG_RELAY_R2":        "intrinsic",
    "CP_COMMIT_ROUTE":        "intrinsic",
    "CP_SHARE_ROUTE":         "intrinsic",
    "CP_ROAST_FORM_SESSION":  "intrinsic",

    # Event-loop/engineering overhead -- specific to this implementation
    "CP_SELECT_BLOCKING":     "contingent",
    "CP_SESSION_EXPIRE_SCAN": "contingent",
    "CP_TLS_RECORD_RECV":     "contingent",
    "CP_TLS_RECORD_SEND":     "contingent",
}


# ── Known nesting relationships ───────────────────────────────────────
# Some cp_ids wrap calls that themselves contain other check_in/check_out
# pairs (this mirrors the actual call structure in frost_coordinator.c):
#   CP_COMMIT_ROUTE        wraps roast_try_form_session(), which contains
#                          CP_ROAST_FORM_SESSION and (if a session forms)
#                          CP_ASSEMBLE_BASH
#   CP_SESSION_EXPIRE_SCAN also calls roast_try_form_session() on retry,
#                          so it can likewise contain CP_ROAST_FORM_SESSION
#                          and CP_ASSEMBLE_BASH
#   CP_SHARE_ROUTE         wraps roast_try_aggregate(), which contains
#                          CP_AGGREGATE_BASH and, on success, call_mint()
#                          (CP_MINT_BASH)
#
# This means per-id totals are NOT independent/additive -- summing every
# id's total_ms overcounts real wall-clock busy time by however much
# nesting occurred. The per-id table is still valid for "how much total
# cost is attributable to this code region across all its calls," but
# for a wall-clock-accurate "how busy was this process" figure, this
# script instead merges overlapping [start, end] intervals per process
# (reconstructing start = end_timestamp - duration) -- see busy_ms below.
NESTED_WITHIN = {
    "CP_ROAST_FORM_SESSION": {"CP_COMMIT_ROUTE", "CP_SESSION_EXPIRE_SCAN"},
    "CP_ASSEMBLE_BASH": {"CP_COMMIT_ROUTE", "CP_SESSION_EXPIRE_SCAN"},
    # "CP_AGGREGATE_BASH": {"CP_SHARE_ROUTE"},
    # "CP_MINT_BASH": {"CP_SHARE_ROUTE"},
    # "CP_TEMPFILE_WRITE": {"CP_SHARE_ROUTE"},

}


def merge_intervals(intervals):
    """intervals: list of (start_dt, end_dt). Returns merged non-overlapping
    intervals and their total duration in ms."""
    if not intervals:
        return [], 0.0
    ordered = sorted(intervals, key=lambda iv: iv[0])
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            if end > last_end:
                merged[-1] = (last_start, end)
        else:
            merged.append((start, end))
    total_ms = sum((e - s).total_seconds() * 1000.0 for s, e in merged)
    return merged, total_ms



# ── select() timeout configuration, from the actual source ───────────
# Coordinator: struct timeval tv = {.tv_sec = 1, .tv_usec = 0};        (1000 ms)
# Signer:      struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};  (500 ms)
# Used to split CP_SELECT_BLOCKING into "near-instant" (data was already
# ready) vs "near-timeout" (genuinely idle, nothing to do) buckets --
# lumping both into one mean/total obscures which one actually dominates.
SELECT_TIMEOUT_MS_BY_ROLE = {"coordinator": 1000.0, "signer": 500.0}
NEAR_INSTANT_THRESHOLD_MS = 1.0
NEAR_TIMEOUT_FRACTION = 0.9  # >= 90% of the role's configured timeout


def infer_role(ids_seen):
    if ids_seen & COORD_ONLY_IDS:
        return "coordinator"
    if ids_seen & SIGNER_ONLY_IDS:
        return "signer"
    return "unknown"


def percentile(sorted_vals, pct):
    """Linear-interpolation percentile. sorted_vals must already be sorted."""
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def stats_for(values):
    v = sorted(values)
    n = len(v)
    return {
        "count": n,
        "total_ms": sum(v),
        "mean_ms": statistics.mean(v) if n else float("nan"),
        "median_ms": statistics.median(v) if n else float("nan"),
        "stdev_ms": statistics.pstdev(v) if n > 1 else 0.0,
        "min_ms": v[0] if n else float("nan"),
        "max_ms": v[-1] if n else float("nan"),
        "p90_ms": percentile(v, 90),
        "p95_ms": percentile(v, 95),
        "p99_ms": percentile(v, 99),
    }


def parse_ts(ts_str):
    """Parse 'YYYY-MM-DDTHH:MM:SS.mmmZ' -> aware datetime. %f zero-pads on
    the right when parsing, so 3-digit milliseconds ('.056') is handled
    correctly (interpreted as 056000 microseconds = 56 ms)."""
    return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def parse_files(paths):
    events = []
    warnings = []
    unparsed = 0
    for path in paths:
        with open(path, "r", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                if not line:
                    continue
                m = EVENT_RE.match(line)
                if m:
                    events.append({
                        "ts": m.group("ts"),
                        "label": m.group("label"),
                        "cp_id": m.group("cp_id"),
                        "ms": float(m.group("ms")),
                        "file": m.group("file"),
                        "line": int(m.group("line")),
                        "source_file": str(path),
                    })
                    continue
                w = WARNING_RE.match(line)
                if w:
                    warnings.append({
                        "ts": w.group("ts"),
                        "label": w.group("label"),
                        "msg": w.group("msg"),
                        "source_file": str(path),
                    })
                    continue
                unparsed += 1
    return events, warnings, unparsed


def fmt_ms(x):
    return f"{x:,.3f}"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfiles", nargs="+", help="one or more checkpoint log files")
    ap.add_argument("--events-csv", default="checkpoint_events.csv",
                     help="output path for raw per-event CSV (default: %(default)s)")
    ap.add_argument("--summary-csv", default="checkpoint_summary.csv",
                     help="output path for per-id summary CSV (default: %(default)s)")
    ap.add_argument("--no-csv", action="store_true",
                     help="skip writing CSV files, print report only")
    args = ap.parse_args()

    events, warnings, unparsed = parse_files(args.logfiles)

    if not events:
        print("No checkpoint events parsed -- check the log format/path.", file=sys.stderr)
        sys.exit(1)

    # ── group by cp_id ────────────────────────────────────────────────
    by_id = defaultdict(list)
    for e in events:
        by_id[e["cp_id"]].append(e["ms"])
    id_stats = {cp_id: stats_for(vals) for cp_id, vals in by_id.items()}

    # ── group by process/label ────────────────────────────────────────
    ids_by_label = defaultdict(set)
    ms_by_label = defaultdict(list)
    ts_by_label = defaultdict(list)
    intervals_by_label = defaultdict(list)
    for e in events:
        ids_by_label[e["label"]].add(e["cp_id"])
        ms_by_label[e["label"]].append(e["ms"])
        ts_by_label[e["label"]].append(e["ts"])
        end_dt = parse_ts(e["ts"])
        start_dt = end_dt - timedelta(milliseconds=e["ms"])
        intervals_by_label[e["label"]].append((start_dt, end_dt))
    roles_by_label = {label: infer_role(ids) for label, ids in ids_by_label.items()}

    busy_ms_by_label = {}
    for label, intervals in intervals_by_label.items():
        _, busy_ms = merge_intervals(intervals)
        busy_ms_by_label[label] = busy_ms

    # ── wall-clock span (whole run, and per process) ──────────────────
    all_ts_sorted = sorted(e["ts"] for e in events)
    first_ts, last_ts = all_ts_sorted[0], all_ts_sorted[-1]
    run_span_ms = (parse_ts(last_ts) - parse_ts(first_ts)).total_seconds() * 1000.0

    grand_total_ms = sum(e["ms"] for e in events)

    # ══════════════════════════════════════════════════════════════
    # Report
    # ══════════════════════════════════════════════════════════════
    print("=" * 78)
    print("CHECKPOINT LOG ANALYSIS")
    print("=" * 78)
    print(f"Files parsed        : {', '.join(args.logfiles)}")
    print(f"Events parsed       : {len(events)}")
    print(f"Warnings found      : {len(warnings)}")
    print(f"Unparsed lines      : {unparsed}")
    print(f"Logged time span    : {first_ts} -> {last_ts}  ({run_span_ms:,.1f} ms wall-clock)")
    print(f"Sum of all durations: {fmt_ms(grand_total_ms)} ms "
          f"(NOTE: processes run concurrently, so this can exceed wall-clock span)")
    print(f"Distinct processes  : {len(ids_by_label)}")
    for label, role in sorted(roles_by_label.items()):
        proc_total = sum(ms_by_label[label])
        busy_ms = busy_ms_by_label[label]
        proc_span_ms = (parse_ts(max(ts_by_label[label])) -
                        parse_ts(min(ts_by_label[label]))).total_seconds() * 1000.0
        if proc_span_ms > 0:
            instrumented_str = f"{100.0 * busy_ms / proc_span_ms:5.1f}%"
        else:
            instrumented_str = "  n/a"
        print(f"    {label:<16} role={role:<12} events={len(ms_by_label[label]):<6} "
              f"naive_sum={fmt_ms(proc_total):>10} ms  busy(merged)={fmt_ms(busy_ms):>10} ms  "
              f"span={proc_span_ms:>10,.1f} ms  instrumented={instrumented_str}")
    print()

    nested_present = {child for child in NESTED_WITHIN if child in id_stats}
    if nested_present:
        print("-" * 78)
        print("NESTING NOTE")
        print("-" * 78)
        print("The ids below are called from *inside* another instrumented region,")
        print("so their time is already included in that parent's total. Don't sum")
        print("parent + child totals together -- that double-counts. The per-process")
        print("'busy(merged)' figure above already accounts for this correctly.")
        for child in sorted(nested_present):
            parents = ", ".join(sorted(NESTED_WITHIN[child]))
            print(f"    {child:<24} is nested within: {parents}")
        print()

    # ── per-checkpoint-id table ────────────────────────────────────────
    print("-" * 78)
    print("PER-CHECKPOINT-ID BREAKDOWN (sorted by total time, descending)")
    print("-" * 78)
    header = (f"{'cp_id':<24}{'n':>6}{'total_ms':>12}{'mean_ms':>10}"
              f"{'median':>9}{'stdev':>9}{'min':>9}{'max':>10}{'p95':>9}")
    print(header)
    print("-" * len(header))
    for cp_id, s in sorted(id_stats.items(), key=lambda kv: kv[1]["total_ms"], reverse=True):
        pct = 100.0 * s["total_ms"] / grand_total_ms if grand_total_ms else 0.0
        print(f"{cp_id:<24}{s['count']:>6}{fmt_ms(s['total_ms']):>12}"
              f"{fmt_ms(s['mean_ms']):>10}{fmt_ms(s['median_ms']):>9}"
              f"{fmt_ms(s['stdev_ms']):>9}{fmt_ms(s['min_ms']):>9}"
              f"{fmt_ms(s['max_ms']):>10}{fmt_ms(s['p95_ms']):>9}  ({pct:5.1f}% of total)")
    print()

    # ── per-role aggregate ─────────────────────────────────────────────
    print("-" * 78)
    print("PER-ROLE AGGREGATE")
    print("-" * 78)
    role_totals = defaultdict(float)
    role_counts = defaultdict(int)
    for label, vals in ms_by_label.items():
        role = roles_by_label[label]
        role_totals[role] += sum(vals)
        role_counts[role] += len(vals)
    for role, total in sorted(role_totals.items(), key=lambda kv: -kv[1]):
        pct = 100.0 * total / grand_total_ms if grand_total_ms else 0.0
        print(f"  {role:<14} events={role_counts[role]:<8} total={fmt_ms(total):>12} ms  ({pct:5.1f}%)")
    print()

    # ── intrinsic vs contingent ─────────────────────────────────────────
    print("-" * 78)
    print("INTRINSIC vs CONTINGENT  (edit the CLASSIFICATION table to match your methodology)")
    print("-" * 78)
    cat_totals = defaultdict(float)
    cat_counts = defaultdict(int)
    unclassified = set()
    for cp_id, s in id_stats.items():
        cat = CLASSIFICATION.get(cp_id, "unclassified")
        cat_totals[cat] += s["total_ms"]
        cat_counts[cat] += s["count"]
        if cat == "unclassified":
            unclassified.add(cp_id)
    for cat, total in sorted(cat_totals.items(), key=lambda kv: -kv[1]):
        pct = 100.0 * total / grand_total_ms if grand_total_ms else 0.0
        print(f"  {cat:<14} events={cat_counts[cat]:<8} total={fmt_ms(total):>12} ms  ({pct:5.1f}%)")
    if unclassified:
        print(f"\n  NOTE: cp_ids seen in the log but missing from CLASSIFICATION "
              f"(counted as 'unclassified'): {', '.join(sorted(unclassified))}")
    if nested_present:
        print(f"\n  CAUTION: these totals sum per-id totals directly, so nested ids "
              f"(see NESTING NOTE above) are double-counted along with their parent. "
              f"In this codebase all known nested pairs fall in the same category "
              f"(e.g. CP_COMMIT_ROUTE and its child CP_ASSEMBLE_BASH are both "
              f"'intrinsic'), so the double-count inflates that category's total "
              f"without shifting the intrinsic/contingent split -- but recheck this "
              f"if you reclassify anything.")
    print()

    print("-" * 78)
    print("WHAT'S DRIVING EACH CATEGORY")
    print("-" * 78)
    for cat in ("intrinsic", "contingent", "unclassified"):
        members = [cp_id for cp_id in id_stats if CLASSIFICATION.get(cp_id, "unclassified") == cat]
        if not members:
            continue
        print(f"  [{cat}]")
        for cp_id in sorted(members, key=lambda c: -id_stats[c]["total_ms"]):
            s = id_stats[cp_id]
            print(f"      {cp_id:<24} total={fmt_ms(s['total_ms']):>10} ms   n={s['count']}")
    print()

    # ── select() blocking: near-instant poll vs near-timeout idle wait ──
    if "CP_SELECT_BLOCKING" in by_id:
        print("-" * 78)
        print("CP_SELECT_BLOCKING BREAKDOWN (near-instant poll vs near-timeout idle wait)")
        print("-" * 78)
        print(f"  'near-instant' = < {NEAR_INSTANT_THRESHOLD_MS} ms (a message was already waiting)")
        print(f"  'near-timeout' = >= {int(NEAR_TIMEOUT_FRACTION * 100)}% of that role's configured "
              f"select() timeout (genuinely idle, nothing to do)")
        print(f"  'mid-range'    = everything in between")
        print()
        buckets_by_role = defaultdict(lambda: defaultdict(lambda: [0, 0.0]))  # role -> bucket -> [count, total_ms]
        for e in events:
            if e["cp_id"] != "CP_SELECT_BLOCKING":
                continue
            role = roles_by_label.get(e["label"], "unknown")
            timeout_ms = SELECT_TIMEOUT_MS_BY_ROLE.get(role)
            ms = e["ms"]
            if ms < NEAR_INSTANT_THRESHOLD_MS:
                bucket = "near-instant"
            elif timeout_ms is not None and ms >= NEAR_TIMEOUT_FRACTION * timeout_ms:
                bucket = "near-timeout"
            else:
                bucket = "mid-range"
            buckets_by_role[role][bucket][0] += 1
            buckets_by_role[role][bucket][1] += ms
        for role in sorted(buckets_by_role):
            role_total = sum(v[1] for v in buckets_by_role[role].values())
            print(f"  role={role}  (configured timeout: "
                  f"{SELECT_TIMEOUT_MS_BY_ROLE.get(role, 'unknown')} ms)")
            for bucket in ("near-instant", "mid-range", "near-timeout"):
                count, total = buckets_by_role[role].get(bucket, [0, 0.0])
                pct = 100.0 * total / role_total if role_total else 0.0
                print(f"      {bucket:<14} n={count:<6} total={fmt_ms(total):>12} ms  ({pct:5.1f}%)")
        print()

    # ── warnings ─────────────────────────────────────────────────────────
    if warnings:
        print("-" * 78)
        print("WARNINGS (protocol/log anomalies, e.g. an overwritten check_in or an")
        print("unmatched check_out -- worth noting in a reliability discussion)")
        print("-" * 78)
        warn_counts = defaultdict(int)
        for w in warnings:
            # strip only a trailing "(file:line)" location suffix, not any
            # earlier parenthesized content like "check_out(CP_TEST)"
            key = re.sub(r'\s*\([^()]+:\d+\)\s*$', '', w["msg"]).strip()
            warn_counts[key] += 1
        for msg, count in sorted(warn_counts.items(), key=lambda kv: -kv[1]):
            print(f"  {count:>5}x  {msg}")
        print()

    # ══════════════════════════════════════════════════════════════
    # CSV export
    # ══════════════════════════════════════════════════════════════
    if not args.no_csv:
        with open(args.events_csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["timestamp", "label", "role", "cp_id", "ms", "file", "line", "source_file"])
            for e in events:
                w.writerow([e["ts"], e["label"], roles_by_label[e["label"]], e["cp_id"],
                            e["ms"], e["file"], e["line"], e["source_file"]])
        print(f"Wrote raw events -> {args.events_csv}  ({len(events)} rows)")

        with open(args.summary_csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["cp_id", "classification", "count", "total_ms", "mean_ms",
                        "median_ms", "stdev_ms", "min_ms", "max_ms", "p90_ms", "p95_ms",
                        "p99_ms", "pct_of_grand_total"])
            for cp_id, s in sorted(id_stats.items(), key=lambda kv: -kv[1]["total_ms"]):
                pct = 100.0 * s["total_ms"] / grand_total_ms if grand_total_ms else 0.0
                w.writerow([cp_id, CLASSIFICATION.get(cp_id, "unclassified"), s["count"],
                            round(s["total_ms"], 6), round(s["mean_ms"], 6),
                            round(s["median_ms"], 6), round(s["stdev_ms"], 6),
                            round(s["min_ms"], 6), round(s["max_ms"], 6),
                            round(s["p90_ms"], 6), round(s["p95_ms"], 6),
                            round(s["p99_ms"], 6), round(pct, 3)])
        print(f"Wrote id summary -> {args.summary_csv}  ({len(id_stats)} rows)")


if __name__ == "__main__":
    main()
