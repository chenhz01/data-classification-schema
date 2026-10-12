# -*- coding: utf-8 -*-
"""self_test for data-classification-schema — inherits scaffold v2 four defenses:
  D1 SystemExit/BaseException capture in run_cli
  D2 Unicode-safe patterns (CJK/emoji fixtures)
  D3 fixtures written with newline="" (Windows CRLF safe)
  D4 last line `SUMMARY: PASS n/n`
"""
import contextlib, io, json, os, sys, tempfile, unittest

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import importlib
mod = importlib.import_module("data_classification_schema")
main = mod.main


def run_cli(argv):
    """D1: catch SystemExit and Exception; return (code, stdout, stderr)."""
    buf_out, buf_err = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            main(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception as e:
        code = 1
        buf_err.write(repr(e))
    return code, buf_out.getvalue(), buf_err.getvalue()


def _write(text, suffix=".json"):
    """D3: newline="" prevents \r\n double-write on Windows."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return path


def _schema(**kw):
    s = {
        "levels": [
            {"id": "public", "rank": 0},
            {"id": "internal", "rank": 1},
            {"id": "confidential", "rank": 2},
            {"id": "restricted", "rank": 3},
        ],
        "rules": [
            {"field_pattern": "*email*", "min_level": "confidential"},
            {"field_pattern": "*token*", "min_level": "restricted"},
        ],
    }
    s.update(kw)
    return s


def _fields(*entries):
    return json.dumps(list(entries))


CASES = []


def case(fn):
    CASES.append(fn)
    return fn


# ---------------- [A] functional ----------------

@case
def a01_validate_good_schema_exit0():
    p = _write(json.dumps(_schema()))
    code, out, _ = run_cli(["validate", p])
    assert code == 0 and "OK" in out, (code, out)


@case
def a02_validate_json_output_parseable():
    p = _write(json.dumps(_schema()))
    code, out, _ = run_cli(["validate", p, "--json"])
    assert code == 0 and json.loads(out)["findings"] == []


@case
def a03_check_all_ok_exit0():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "user.name", "level": "internal"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "checked=1 ok=1" in out


@case
def a04_check_violation_detected():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "user.email", "level": "internal"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 1 and "violation: user.email" in out


@case
def a05_check_meets_min_level_ok():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "user.email", "level": "confidential"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0


@case
def a06_check_unlabeled_listed_exit0():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "user.phone"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "unlabeled: user.phone" in out


@case
def a07_check_unknown_level_exit1():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "x", "level": "topsecret"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 1 and "unknown_level" in out


@case
def a08_check_json_report():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "api.token", "level": "public"}))
    code, out, _ = run_cli(["check", sp, fp, "--json"])
    assert code == 1
    rep = json.loads(out)
    assert rep["violations"][0]["min_level"] == "restricted"


@case
def a09_r2_duplicate_level_id():
    p = _write(json.dumps({"levels": [{"id": "a", "rank": 0}, {"id": "a", "rank": 1}]}))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def a10_r2_duplicate_rank():
    p = _write(json.dumps({"levels": [{"id": "a", "rank": 0}, {"id": "b", "rank": 0}]}))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def a11_r3_min_level_not_declared():
    p = _write(json.dumps(_schema(rules=[{"field_pattern": "*", "min_level": "vault"}])))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R3" in out


@case
def a12_r3_empty_field_pattern():
    p = _write(json.dumps(_schema(rules=[{"field_pattern": "  ", "min_level": "public"}])))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R3" in out


@case
def a13_rules_optional():
    p = _write(json.dumps({"levels": [{"id": "public", "rank": 0}]}))
    code, out, _ = run_cli(["validate", p])
    assert code == 0


@case
def a14_bench_small_runs():
    code, out, _ = run_cli(["bench", "--fields", "100"])
    assert code == 0 and "fields/s" in out and "fields=100" in out


@case
def a15_bench_default_runs():
    code, out, _ = run_cli(["bench"])
    assert code == 0 and "violations=" in out


@case
def a16_direct_functions_clean():
    rep = mod.check_fields(_schema(), [{"field": "a", "level": "public"}])
    assert rep["ok"] == 1 and rep["checked"] == 1


@case
def a17_direct_validate_clean():
    assert mod.validate_schema(_schema()) == []


@case
def a18_help_exit0():
    code, out, _ = run_cli(["--help"])
    assert code == 0 and "data-classification-schema" in out


@case
def a19_no_args_exit2():
    code, _, _ = run_cli([])
    assert code == 2


@case
def a20_unknown_subcommand_exit2():
    code, _, _ = run_cli(["transmogrify"])
    assert code == 2


@case
def a21_exact_pattern_match():
    sp = _write(json.dumps(_schema(rules=[{"field_pattern": "ssn_exact", "min_level": "restricted"}])))
    fp = _write(_fields({"field": "ssn_exact", "level": "public"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 1 and "ssn_exact" in out


@case
def a22_no_rule_hit_counts_as_ok():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "user.age", "level": "internal"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "ok=1" in out


@case
def a23_violation_on_multiple_rules():
    s = _schema(rules=[{"field_pattern": "*email*", "min_level": "confidential"},
                       {"field_pattern": "user.*", "min_level": "internal"}])
    sp = _write(json.dumps(s))
    fp = _write(_fields({"field": "user.email", "level": "public"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 1 and out.count("violation:") == 2


# ---------------- [B] exception paths ----------------

@case
def b01_missing_schema_file():
    code, _, err = run_cli(["validate", "Z:/no/schema.json"])
    assert code == 1 and "cannot read" in err


@case
def b02_invalid_json_schema():
    p = _write("{oops")
    code, _, err = run_cli(["validate", p])
    assert code == 1 and "invalid JSON" in err


@case
def b03_schema_is_list():
    p = _write("[]")
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R0" in out


@case
def b04_schema_is_string():
    p = _write('"x"')
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R0" in out


@case
def b05_levels_missing():
    p = _write("{}")
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R1" in out


@case
def b06_levels_empty():
    p = _write('{"levels": []}')
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R1" in out


@case
def b07_level_not_object():
    p = _write('{"levels": [42]}')
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def b08_rank_negative():
    p = _write(json.dumps({"levels": [{"id": "a", "rank": -1}]}))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def b09_rank_is_string():
    p = _write(json.dumps({"levels": [{"id": "a", "rank": "0"}]}))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def b10_rules_not_list():
    p = _write(json.dumps(_schema(rules={"a": 1})))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R3" in out


@case
def b11_rule_not_object():
    p = _write(json.dumps(_schema(rules=[7])))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R3" in out


@case
def b12_missing_fields_file():
    sp = _write(json.dumps(_schema()))
    code, _, err = run_cli(["check", sp, "Z:/no/fields.json"])
    assert code == 1 and "cannot read" in err


@case
def b13_fields_invalid_json():
    sp = _write(json.dumps(_schema()))
    fp = _write("[broken")
    code, _, err = run_cli(["check", sp, fp])
    assert code == 1 and "invalid JSON" in err


@case
def b14_fields_is_object_not_list():
    sp = _write(json.dumps(_schema()))
    fp = _write('{"field": "x"}')
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "checked=0" in out


@case
def b15_bench_fields_zero():
    code, _, _ = run_cli(["bench", "--fields", "0"])
    assert code == 2


@case
def b16_bench_fields_negative():
    code, _, _ = run_cli(["bench", "--fields", "-5"])
    assert code == 2


@case
def b17_bench_fields_not_int():
    code, _, _ = run_cli(["bench", "--fields", "x"])
    assert code == 2


@case
def b18_field_name_is_null():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": None, "level": "public"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "ok=1" in out  # fnmatch(None -> "" handled)


@case
def b19_entry_is_not_object():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields(42))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "unlabeled" in out


@case
def b20_directory_as_input():
    code, _, err = run_cli(["validate", os.path.dirname(os.path.abspath(__file__))])
    assert code == 1 and "cannot read" in err


# ---------------- [C] extreme / edge ----------------

@case
def c01_empty_file():
    p = _write("")
    code, _, err = run_cli(["validate", p])
    assert code == 1 and "invalid JSON" in err


@case
def c02_whitespace_only():
    p = _write(" \t\n ")
    code, _, _ = run_cli(["validate", p])
    assert code == 1


@case
def c03_utf8_bom_schema():
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(p, "wb") as fh:
        fh.write(b"\xef\xbb\xbf" + json.dumps(_schema()).encode("utf-8"))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c04_unicode_cjk_level_id():
    p = _write(json.dumps({"levels": [{"id": "机密", "rank": 0}]}))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out  # id grammar is ASCII by design


@case
def c05_unicode_cjk_field_name():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "用户.邮箱"}))  # no level: ASCII patterns cannot rescue it
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "unlabeled: 用户.邮箱" in out  # D2: CJK survives the report path


@case
def c06_unicode_emoji_field_name_ok():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "profile \U0001f600 bio", "level": "public"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "ok=1" in out


@case
def c07_huge_field_name_100k():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "x" * 100000, "level": "public"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0


@case
def c08_single_level_single_field():
    p = _write(json.dumps({"levels": [{"id": "only", "rank": 0}]}))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c09_rank_large_values_ok():
    p = _write(json.dumps({"levels": [{"id": "a", "rank": 999999}, {"id": "b", "rank": 1000000}]}))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c10_pattern_bare_asterisk_matches_all():
    sp = _write(json.dumps(_schema(rules=[{"field_pattern": "*", "min_level": "restricted"}])))
    fp = _write(_fields({"field": "anything", "level": "public"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 1


@case
def c11_pattern_with_brackets():
    sp = _write(json.dumps(_schema(rules=[{"field_pattern": "user[._]email", "min_level": "confidential"}])))
    fp = _write(_fields({"field": "user.email", "level": "public"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 1


@case
def c12_case_sensitive_pattern():
    sp = _write(json.dumps(_schema(rules=[{"field_pattern": "*EMAIL*", "min_level": "confidential"}])))
    fp = _write(_fields({"field": "user.email", "level": "public"}))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0  # fnmatchcase: no match


@case
def c13_200_fields_bulk():
    sp = _write(json.dumps(_schema()))
    entries = [{"field": "f%03d_email" % i, "level": "confidential"} for i in range(200)]
    fp = _write(_fields(*entries))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "checked=200" in out


@case
def c14_100_unlabeled_bulk():
    sp = _write(json.dumps(_schema()))
    entries = [{"field": "f%03d" % i} for i in range(100)]
    fp = _write(_fields(*entries))
    code, out, _ = run_cli(["check", sp, fp])
    assert code == 0 and "unlabeled=100" in out


@case
def c15_extra_keys_on_level_ignored():
    p = _write(json.dumps({"levels": [{"id": "a", "rank": 0, "color": "#fff"}]}))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c16_extra_keys_on_field_ignored():
    sp = _write(json.dumps(_schema()))
    fp = _write(_fields({"field": "x", "level": "public", "owner": "t"}))
    code, _, _ = run_cli(["check", sp, fp])
    assert code == 0


@case
def c17_crlf_line_endings():
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(p, "w", encoding="utf-8", newline="") as fh:  # D3
        fh.write(json.dumps(_schema()).replace("\n", "\r\n"))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c18_level_id_max_len_64_ok():
    p = _write(json.dumps({"levels": [{"id": "a" * 64, "rank": 0}]}))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c19_level_id_65_chars_rejected():
    p = _write(json.dumps({"levels": [{"id": "a" * 65, "rank": 0}]}))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def c20_rank_bool_rejected():
    p = _write(json.dumps({"levels": [{"id": "a", "rank": True}]}))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


class T(unittest.TestCase):
    def test_meta_case_count(self):
        self.assertGreaterEqual(len(CASES), 60)


for _fn in CASES:
    setattr(T, "test_" + _fn.__name__, lambda self, f=_fn: f())

if __name__ == "__main__":
    r = unittest.TextTestRunner(verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules["__main__"]))
    total, fails = r.testsRun, len(r.failures) + len(r.errors)
    print("SUMMARY: PASS %d/%d" % (total - fails, total))
    sys.exit(0 if fails == 0 else 1)
