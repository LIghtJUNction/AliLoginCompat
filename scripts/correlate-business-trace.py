#!/usr/bin/env python3
"""Offline association of private signer traces with captured MTOP requests.

Only API names, capture IDs, status, and field names are emitted. Never uploads
anything and never treats a shared device token as proof of a request match.
"""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit


FACTOR_HEADERS = {
    "x-sign", "x-mini-wua", "x-sgext", "x-umt",
    "x-gst", "x-us", "x-pipu1", "wua",
}


def sanitize_ret(ret):
    if not isinstance(ret, str) or not ret:
        return "UNKNOWN"
    if ret == "SUCCESS" or ret.startswith(("FAIL_SYS_", "ERR_", "FAIL_")):
        return ret[:48]
    return "OTHER"


def header_digests(session):
    result = {}
    for key, value in session.get("request_headers", {}).items():
        key = key.lower()
        if key not in FACTOR_HEADERS:
            continue
        if isinstance(value, list):
            if len(value) != 1:
                continue
            value = value[0]
        if isinstance(value, str):
            # Converter applies URLEncoder once. A second decode corrupts '+'
            # and literal percent sequences in the original factor string.
            result[key] = hashlib.sha256(unquote_plus(value).encode()).hexdigest()
    return result


def correlate(traces, sessions):
    index = {}
    for session in sessions:
        parts = urlsplit(session.get("url", "")).path.strip("/").split("/")
        if len(parts) < 3 or parts[0] != "gw":
            continue
        fields = header_digests(session)
        sign = fields.get("x-sign")
        if sign:
            index.setdefault((parts[1], sign), []).append((session, fields))
    results = []
    for number, trace in enumerate(traces):
        if trace.get("record_type") == "mtop_response":
            continue
        expected = trace.get("output_sha256", {})
        sign = expected.get("x-sign")
        candidates = index.get((trace["api"], sign), []) if sign else []
        matches = []
        for session, actual in candidates:
            different = sorted(k for k, value in expected.items() if actual.get(k) != value)
            matches.append({"session_id": session["id"], "status": session["status"],
                            "ret_category": sanitize_ret(session.get("ret_code")),
                            "all_recorded_fields_match": not different,
                            "different_or_missing_fields": different})
        results.append({"trace_index": number, "api": trace["api"],
                        "signature_recorded": bool(sign), "candidate_count": len(matches),
                        "matches": matches,
                        "append_calls": trace.get("native", {}).get("append_calls")})
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traces", type=Path, required=True)
    parser.add_argument("--sessions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    traces = [json.loads(line) for line in args.traces.read_text().splitlines() if line.strip()]
    result = correlate(traces, json.loads(args.sessions.read_text()))
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"traces": len(result), "associated": sum(bool(x["candidate_count"]) for x in result)}))
