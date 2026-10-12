#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""data-classification-schema — a sensitivity-level schema for data fields with
field-level labeling validation and an unlabeled-field listing.
Pure standard library, single file, offline.
"""
import argparse, fnmatch, json, re, sys, time

ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


def _err(findings, rule, severity, msg, ref=None):
    f = {"rule": rule, "severity": severity, "message": msg}
    if ref is not None:
        f["ref"] = ref
    findings.append(f)


def validate_schema(schema):
    """Structural validation of a classification schema. Returns findings."""
    findings = []
    if not isinstance(schema, dict):
        _err(findings, "R0", "error", "schema must be a JSON object")
        return findings
    levels = schema.get("levels")
    if not isinstance(levels, list) or not levels:
        _err(findings, "R1", "error", "levels must be a non-empty list")
        return findings
    ids, ranks = set(), set()
    for lv in levels:
        if not isinstance(lv, dict):
            _err(findings, "R2", "error", "level entry is not an object")
            continue
        lid = lv.get("id")
        if not isinstance(lid, str) or not ID_RE.match(lid):
            _err(findings, "R2", "error", "level id missing or not [A-Za-z][A-Za-z0-9_-]{0,63}", lid)
            continue
        if lid in ids:
            _err(findings, "R2", "error", "duplicate level id", lid)
            continue
        ids.add(lid)
        rank = lv.get("rank")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 0:
            _err(findings, "R2", "error", "rank must be an integer >= 0", lid)
            continue
        if rank in ranks:
            _err(findings, "R2", "error", "duplicate rank", lid)
            continue
        ranks.add(rank)
    rules = schema.get("rules", [])
    if not isinstance(rules, list):
        _err(findings, "R3", "error", "rules must be a list when present")
        return findings
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            _err(findings, "R3", "error", "rule #%d is not an object" % (i + 1))
            continue
        pat = r.get("field_pattern")
        if not isinstance(pat, str) or not pat.strip():
            _err(findings, "R3", "error", "field_pattern must be a non-empty string", "#%d" % (i + 1))
            continue
        ml = r.get("min_level")
        if ml not in ids:
            _err(findings, "R3", "error", "min_level %r is not a declared level" % (ml,), pat)
    return findings


def _level_ranks(schema):
    return {lv.get("id"): lv.get("rank") for lv in schema.get("levels", [])
            if isinstance(lv, dict) and isinstance(lv.get("id"), str)}


def check_fields(schema, fields):
    """Validate field labels against the schema. Returns a report dict."""
    report = {"ok": 0, "violations": [], "unknown_level": [], "unlabeled": [], "checked": 0}
    if not isinstance(fields, list):
        return report
    ranks = _level_ranks(schema)
    rules = schema.get("rules", []) if isinstance(schema, dict) else []
    for entry in fields:
        report["checked"] += 1
        if not isinstance(entry, dict):
            report["unlabeled"].append({"field": repr(entry), "reason": "entry is not an object"})
            continue
        name = entry.get("field")
        label = entry.get("level")
        if not isinstance(label, str) or not label:
            report["unlabeled"].append({"field": name, "reason": "no level declared"})
            continue
        if label not in ranks:
            report["unknown_level"].append({"field": name, "level": label})
            continue
        hit = False
        for r in rules:
            if not isinstance(r, dict):
                continue
            pat = r.get("field_pattern")
            if isinstance(pat, str) and fnmatch.fnmatchcase(name or "", pat):
                hit = True
                need = ranks.get(r.get("min_level"))
                if need is not None and ranks[label] < need:
                    report["violations"].append({
                        "field": name, "level": label,
                        "min_level": r.get("min_level"),
                        "pattern": pat})
        if not hit:
            report["ok"] += 1
    return report


def _has_blocker(report):
    return bool(report["violations"] or report["unknown_level"])


def _load(path):
    with open(path, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def _print_findings(findings, as_json):
    if as_json:
        print(json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    else:
        if not findings:
            print("OK: no findings")
        for f in findings:
            ref = " [%s]" % f["ref"] if f.get("ref") else ""
            print("%-7s %-4s%s %s" % (f["severity"], f["rule"], ref, f["message"]))


def _print_report(rep, as_json):
    if as_json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print("checked=%d ok=%d violations=%d unknown_level=%d unlabeled=%d"
              % (rep["checked"], rep["ok"], len(rep["violations"]),
                 len(rep["unknown_level"]), len(rep["unlabeled"])))
        for v in rep["violations"]:
            print("violation: %s labeled %s but matches %r (needs %s)"
                  % (v["field"], v["level"], v["pattern"], v["min_level"]))
        for u in rep["unknown_level"]:
            print("unknown_level: %s declares %r" % (u["field"], u["level"]))
        for u in rep["unlabeled"]:
            print("unlabeled: %s (%s)" % (u["field"], u["reason"]))


def _positive_int(text):
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not an integer: %r" % text)
    if v < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return v


def bench(n):
    schema = {"levels": [{"id": "public", "rank": 0}, {"id": "internal", "rank": 1},
                         {"id": "confidential", "rank": 2}, {"id": "restricted", "rank": 3}],
              "rules": [{"field_pattern": "*email*", "min_level": "confidential"},
                        {"field_pattern": "*token*", "min_level": "restricted"}]}
    fields = [{"field": "user.col%06d_email" % i, "level": "internal"} for i in range(n)]
    t0 = time.perf_counter()
    rep = check_fields(schema, fields)
    dt = time.perf_counter() - t0
    return rep["checked"], len(rep["violations"]), dt


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="data-classification-schema",
        description="Validate a sensitivity-level schema and field labels against it.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("validate", help="structural validation of a schema file")
    pv.add_argument("schema")
    pv.add_argument("--json", action="store_true")

    pc = sub.add_parser("check", help="validate field labels against a schema")
    pc.add_argument("schema")
    pc.add_argument("fields")
    pc.add_argument("--json", action="store_true")

    pb = sub.add_parser("bench", help="run check on synthetic fields and time it")
    pb.add_argument("--fields", type=_positive_int, default=10000)

    args = ap.parse_args(argv)
    if args.cmd == "bench":
        checked, viol, dt = bench(args.fields)
        print("fields=%d checked=%d violations=%d in %.4fs (%.0f fields/s)"
              % (args.fields, checked, viol, dt, args.fields / dt if dt else 0))
        sys.exit(0)

    try:
        schema = _load(args.schema)
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.schema, exc), file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print("error: invalid JSON in %s: %s" % (args.schema, exc), file=sys.stderr)
        sys.exit(1)

    if args.cmd == "validate":
        findings = validate_schema(schema)
        _print_findings(findings, args.json)
        sys.exit(1 if any(f["severity"] == "error" for f in findings) else 0)

    try:
        fields = _load(args.fields)
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.fields, exc), file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print("error: invalid JSON in %s: %s" % (args.fields, exc), file=sys.stderr)
        sys.exit(1)

    rep = check_fields(schema, fields)
    _print_report(rep, args.json)
    sys.exit(1 if _has_blocker(rep) else 0)


if __name__ == "__main__":
    main()
