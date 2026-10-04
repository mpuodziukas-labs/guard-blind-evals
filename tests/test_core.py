import json, pathlib, re, shutil, sys

import pytest

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import evaluate as ev

README = (ROOT / "README.md").read_text()


# ---- Wilson interval math: known published values ----------------------------
def test_wilson_half_of_ten():
    lo, hi = ev.wilson(5, 10)
    assert round(lo, 4) == 0.2366 and round(hi, 4) == 0.7634


def test_wilson_zero_of_ten():
    lo, hi = ev.wilson(0, 10)
    assert lo == 0.0 and round(hi, 4) == 0.2775


def test_wilson_ten_of_ten():
    lo, hi = ev.wilson(10, 10)
    assert round(lo, 4) == 0.7225 and round(hi, 4) == 1.0


def test_wilson_empty_is_full_range():
    assert ev.wilson(0, 0) == (0.0, 1.0)


def test_wilson_bounds_and_width_shrinks_with_n():
    lo1, hi1 = ev.wilson(40, 50)
    lo2, hi2 = ev.wilson(400, 500)
    assert 0 <= lo1 < 0.8 < hi1 <= 1 and (hi2 - lo2) < (hi1 - lo1)


# ---- confusion matrix ---------------------------------------------------------
def test_confusion_counts():
    pairs = [(True, True)] * 3 + [(True, False)] * 2 + [(False, True)] * 1 + [(False, False)] * 4
    c = ev.confusion(pairs)
    assert (c["tp"], c["fp"], c["tn"], c["fn"]) == (3, 1, 4, 2)
    p, r = ev.rates(c)
    assert p == 3 / 4 and r == 3 / 5


def test_rates_undefined_when_no_positive_predictions():
    c = ev.confusion([(True, False), (False, False)])
    p, r = ev.rates(c)
    assert p is None and r == 0.0


def test_fmt_undefined_is_na():
    assert ev.fmt_rate(None, 0, 0).startswith("n/a")


# ---- hash freeze ---------------------------------------------------------------
def test_readme_pins_the_case_hash():
    m = re.search(r"cases-sha256: ([0-9a-f]{64})", README)
    assert m, "README has no cases-sha256 line"
    assert ev.cases_hash() == m.group(1), "cases changed without updating the pre-registered hash"


def test_hash_changes_when_a_case_changes(tmp_path):
    d = tmp_path / "cases"
    shutil.copytree(ROOT / "cases", d)
    before = ev.cases_hash(d)
    f = d / "goal.jsonl"
    f.write_text(f.read_text().replace('"label": "benign"', '"label": "attack"', 1))
    assert ev.cases_hash(d) != before


def test_hash_changes_when_a_case_file_is_removed(tmp_path):
    d = tmp_path / "cases"
    shutil.copytree(ROOT / "cases", d)
    before = ev.cases_hash(d)
    (d / "egress.jsonl").unlink()
    assert ev.cases_hash(d) != before


# ---- case file shape --------------------------------------------------------------
@pytest.mark.parametrize("name,na,nb", [("injection", 40, 40), ("egress", 40, 40), ("goal", 20, 20)])
def test_case_counts_and_ids(name, na, nb):
    cases = ev.load_cases(name)
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids))
    assert sum(c["label"] == "attack" for c in cases) >= na
    assert sum(c["label"] == "benign" for c in cases) >= nb
    assert all(c["label"] in ("attack", "benign") for c in cases)


def test_no_literal_key_shapes_in_case_files():
    pat = re.compile(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|xox[bp]-|\b\d{3}-\d{2}-\d{4}\b|\b4111111111111111\b")
    for p in (ROOT / "cases").glob("*.jsonl"):
        assert not pat.search(p.read_text()), p.name


def test_placeholders_all_resolve():
    for name in ("injection", "egress"):
        for c in ev.load_cases(name):
            for t in (c["text"],) if "text" in c else c["msgs"]:
                out = ev.resolve(t)
                assert "{{" not in out, c["id"]


def test_key_shapes_are_built_at_runtime():
    assert re.fullmatch(r"AKIA[0-9A-Z]{16}", ev.resolve("{{key:aws}}"))
    assert re.fullmatch(r"ghp_[A-Za-z0-9]{36}", ev.resolve("{{key:gh}}"))
    assert ev.resolve("{{key:aws:1}}") + ev.resolve("{{key:aws:2}}") == ev.resolve("{{key:aws}}")
    assert ev.resolve("{{b64:hello world}}") == "aGVsbG8gd29ybGQ="


# ---- fake guards ---------------------------------------------------------------------
def _cases(name):
    return ev.load_cases(name)


def _fake_for(name):
    def run(argv, stdin, env, cwd, timeout):
        if name == "injection":
            return 2, '{"verdict": "BLOCK", "reason": "x"}', False
        if name == "egress":
            return 0, '{"class": "secret", "destination": "local", "rule": "x"}', False
        return 1, "RED fake", False
    return run


@pytest.mark.parametrize("name", ["injection", "egress", "goal"])
def test_says_attack_to_everything_recall_one_precision_base_rate(name):
    cases = _cases(name)
    res = ev.run_guard(name, cases, _fake_for(name))
    c = ev.confusion([(r["label"] == "attack", r["pred"]) for r in res])
    p, r = ev.rates(c)
    base = sum(x["label"] == "attack" for x in cases) / len(cases)
    assert r == 1.0 and c["fn"] == 0
    assert abs(p - base) < 1e-12


@pytest.mark.parametrize("name", ["injection", "egress", "goal"])
def test_says_benign_to_everything_misses_every_attack(name):
    ok = {"injection": (0, '{"verdict": "PASS"}'), "egress": (0, '{"destination": "cloud"}'), "goal": (0, "GREEN")}[name]
    res = ev.run_guard(name, _cases(name), lambda *a: (ok[0], ok[1], False))
    c = ev.confusion([(r["label"] == "attack", r["pred"]) for r in res])
    assert c["tp"] == 0 and c["fp"] == 0 and c["fn"] > 0


def _boom(*a):
    raise RuntimeError("guard blew up")


def _segv(*a):
    return -11, "", False


def _timeout(*a):
    return None, "", True


def _garbage_exit0(*a):
    return 0, "<<not json, not GREEN>>", False


@pytest.mark.parametrize("name", ["injection", "egress", "goal"])
@pytest.mark.parametrize("bad", [_boom, _segv, _timeout, _garbage_exit0])
def test_crash_is_fail_closed_not_skipped(name, bad):
    cases = _cases(name)
    res = ev.run_guard(name, cases, bad)
    assert len(res) == len(cases), "a crash must not drop a case"
    assert all(r["pred"] is True for r in res), "a crash must count as the contract's refuse/block/RED"
    c = ev.confusion([(r["label"] == "attack", r["pred"]) for r in res])
    assert c["fn"] == 0 and c["fp"] == sum(x["label"] == "benign" for x in cases)
    assert all("fail-closed" in r["reason"] for r in res)


# ---- README == recorded run ---------------------------------------------------------------
def test_readme_table_matches_recorded_predictions():
    preds = json.loads((ROOT / "predictions.json").read_text())
    table, misses = ev.summarize(preds)
    assert table in README, "README results table drifted from predictions.json"
    for m in misses:
        assert f"`{m['id']}`" in README, f"miss {m['id']} not published in README"


def test_recorded_predictions_cover_every_case():
    preds = json.loads((ROOT / "predictions.json").read_text())
    want = {c["id"] for n in ev.GUARDS for c in ev.load_cases(n)}
    assert {p["id"] for p in preds} == want
    assert len(preds) == len(want)


@pytest.mark.live
def test_live_run_matches_readme():
    if not ev.guards_present():
        pytest.skip("guard repos not checked out beside this repo (set GUARD_ROOT)")
    preds = ev.run_all()
    table, _ = ev.summarize(preds)
    assert table in README, "live run differs from README table"
