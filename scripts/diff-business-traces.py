#!/usr/bin/env python3
"""Compare a succeeding business trace against a failing (419) trace to locate the first divergence.

Only API names, offsets, field names, lengths, SHA-256 digests, and event categories
are emitted; raw private buffers and tokens are never printed.
"""
import argparse
import json
from pathlib import Path

FACTOR_KEYS = (
    "x-sign", "x-mini-wua", "x-sgext", "x-umt",
    "x-gst", "x-us", "x-pipu1", "wua",
)


def summarize_fields(trace):
    fields = trace.get("output_fields", {})
    digests = trace.get("output_sha256", {})
    summary = {}
    for key in FACTOR_KEYS:
        if key in fields:
            meta = fields[key]
            summary[key] = {
                "present": bool(meta.get("present")),
                "length": int(meta.get("length", 0)),
                "sha256": meta.get("sha256"),
            }
        else:
            h = digests.get(key)
            summary[key] = {"present": bool(h), "length": None, "sha256": h}
    return summary


def first_sequence_divergence(seq_a, seq_b, key_fn):
    limit = min(len(seq_a), len(seq_b))
    for i in range(limit):
        ka = key_fn(seq_a[i])
        kb = key_fn(seq_b[i])
        if ka != kb:
            return {"index": i, "ok": ka, "fail": kb}
    if len(seq_a) != len(seq_b):
        return {
            "index": limit,
            "ok": key_fn(seq_a[limit]) if limit < len(seq_a) else "<end>",
            "fail": key_fn(seq_b[limit]) if limit < len(seq_b) else "<end>",
            "length_mismatch": [len(seq_a), len(seq_b)],
        }
    return None


def diff_traces(ok_trace, fail_trace):
    ok_fields = summarize_fields(ok_trace)
    fail_fields = summarize_fields(fail_trace)
    field_diffs = {}
    for key in FACTOR_KEYS:
        a, b = ok_fields[key], fail_fields[key]
        if a["present"] != b["present"] or a["length"] != b["length"] or a["sha256"] != b["sha256"]:
            field_diffs[key] = {"ok": a, "fail": b}

    ok_native = ok_trace.get("native", {})
    fail_native = fail_trace.get("native", {})
    append_div = first_sequence_divergence(
        ok_native.get("records", []),
        fail_native.get("records", []),
        lambda r: {"caller_offset": r.get("caller_offset"), "source_length": r.get("source_length")},
    )
    event_div = first_sequence_divergence(
        ok_native.get("events", []),
        fail_native.get("events", []),
        lambda e: {
            "caller_offset": e.get("caller_offset"),
            "kind": e.get("kind"),
            "target": e.get("target"),
            "ret": "<tid>" if e.get("kind") == "syscall_num" and e.get("target") == "178" else e.get("ret"),
        },
    )
    return {
        "ok_api": ok_trace.get("api"),
        "fail_api": fail_trace.get("api"),
        "ok_append_calls": ok_native.get("append_calls", 0),
        "fail_append_calls": fail_native.get("append_calls", 0),
        "field_diffs": field_diffs,
        "first_append_divergence": append_div,
        "first_event_divergence": event_div,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traces", type=Path, required=True)
    parser.add_argument("--ok-api", default="mtop.relationrecommend.wirelessrecommend.recommend")
    parser.add_argument("--fail-api", default="mtop.trade.query.bag")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    records = [json.loads(line) for line in args.traces.read_text().splitlines() if line.strip()]
    sign_traces = [r for r in records if r.get("record_type") != "mtop_response"]
    ok_trace = next((r for r in sign_traces if r.get("api") == args.ok_api), None)
    fail_trace = next((r for r in sign_traces if r.get("api") == args.fail_api), None)
    if not ok_trace or not fail_trace:
        raise SystemExit(f"Missing trace pair: ok={bool(ok_trace)} fail={bool(fail_trace)}")
    report = diff_traces(ok_trace, fail_trace)
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
