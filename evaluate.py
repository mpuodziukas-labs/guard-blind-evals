"""Blind held-out evaluation of three AI security guards, run as black boxes.

    python3 evaluate.py            live run: print the table and every miss
    python3 evaluate.py --record   same, and write predictions.json

A positive is an attack: the guard's block / refuse / RED answer. A guard that
crashes, times out or prints something unreadable is scored as that answer
(fail closed), never skipped.
"""
import codecs, hashlib, hmac, json, os, pathlib, re, subprocess, sys, tempfile, urllib.parse
from math import sqrt

ROOT = pathlib.Path(__file__).parent
CASES_DIR = ROOT / "cases"
EXT_SAMPLE = ROOT / "external" / "deepset-prompt-injections" / "sample.jsonl"
EXT_TITLE = "deepset/prompt-injections (external)"
_HERE = pathlib.Path(__file__).resolve().parent.parent   # sibling checkout first, then the home default
GUARD_ROOT = pathlib.Path(os.environ.get("GUARD_ROOT") or next((p for p in (_HERE, pathlib.Path.home() / "proof-artifacts") if (p / "llm-adversarial-gate").is_dir()), _HERE))
PY = os.environ.get("GUARD_PY", sys.executable)
TIMEOUT = 20
GUARDS = {  # name -> (label in the table, repo directory)
    "injection": ("injection firewall", "context-injection-firewall"),
    "egress": ("egress router", "sensitivity-egress-router"),
    "goal": ("goal guard", "goal-election-guard"),
}


# ---- statistics ---------------------------------------------------------------
def wilson(k, n, z=1.959964):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def confusion(pairs):
    c = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for is_attack, flagged in pairs:
        c[("tp" if flagged else "fn") if is_attack else ("fp" if flagged else "tn")] += 1
    return c


def rates(c):
    pp, ap = c["tp"] + c["fp"], c["tp"] + c["fn"]
    return (c["tp"] / pp if pp else None, c["tp"] / ap if ap else None)


def fmt_rate(p, k, n):
    if p is None:
        return "n/a (0 cases)"
    lo, hi = wilson(k, n)
    return f"{p:.2f} [{lo:.2f}, {hi:.2f}]"


# ---- the frozen case set ----------------------------------------------------------
def cases_hash(d=CASES_DIR):
    h = hashlib.sha256()
    for p in sorted(pathlib.Path(d).glob("*.jsonl")):
        h.update(p.name.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def load_cases(name):
    return [json.loads(l) for l in (CASES_DIR / f"{name}.jsonl").read_text().splitlines() if l]


# ---- runtime construction of key-shaped strings (no literal shape sits in a file) -----
_KEYS = {
    "aws": lambda: "AK" + "IA" + "QWERTY12" + "34567890",
    "gh": lambda: "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "sk": lambda: "sk" + "-" + "Zx9Qw8Er7T" * 4,
    "pem": lambda: "-----BEGIN " + "RSA PRIVATE KEY" + "-----\n" + "MIIEFAKEFAKEFAKE\n" * 3 + "-----END " + "RSA PRIVATE KEY" + "-----",
    "slack": lambda: "xo" + "xb-" + "1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx",
    "jwt": lambda: "ey" + "J" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "ey" + "J" + "zdWIiOiJmYWtlLXVzZXIifQ.c2lnbmF0dXJlZmFrZQ",
    "awssecret": lambda: "wJalr" + "XUtnFEMI/K7MDENG/" + "bPxRfiCYFAKE" + "FAKE9",
}
_SIMPLE = {
    "pw": lambda: "Tr0ub4dor" + "3Fake",
    "seed": lambda: "abandon " * 11 + "about",
    "ssn": lambda: "912" + "-" + "34" + "-" + "5678",
    "ssnplain": lambda: "912" + "34" + "5678",
    "ssnspace": lambda: "912 34 5678",
    "ssndots": lambda: "912.34.5678",
    "digits8": lambda: "48201937",
}
_CARD = lambda: "4111" + "1111" + "1111" + "1111"
_PARTS = {"aws": 2, "gh": 3, "card": 2}
_ENC = {
    "b64": lambda s: codecs.encode(s.encode(), "base64").decode().replace("\n", ""),
    "hex": lambda s: s.encode().hex(),
    "rot13": lambda s: codecs.encode(s, "rot13"),
    "urlenc": lambda s: urllib.parse.quote(s, safe=""),
    "rev": lambda s: s[::-1],
    "spaced": lambda s: " ".join(s),
}


def _part(v, base, idx):
    if idx is None:
        return v
    n, i = _PARTS[base], int(idx)
    return v[len(v) * (i - 1) // n: len(v) * i // n]


def _token(tok):
    name, _, arg = tok.partition(":")
    if name == "key":
        base, _, idx = arg.partition(":")
        return _part(_KEYS[base](), base, idx or None)
    if name == "card":
        return _part(_CARD(), "card", arg or None)
    if name in _SIMPLE:
        return _SIMPLE[name]()
    if name in _ENC:
        return _ENC[name](arg)
    raise ValueError(f"unknown placeholder {{{{{tok}}}}}")


def resolve(text):
    pat = re.compile(r"\{\{([^{}]*)\}\}")
    while pat.search(text):
        text = pat.sub(lambda m: _token(m.group(1)), text)
    return text


# ---- goal transcripts -----------------------------------------------------------------
def _fake_key():
    return "goal-" + "guard-" + "test-" + "key"


def build_goal(case):
    """Return (transcript text, GOAL_GUARD_KEY or None) for one goal case."""
    key = _fake_key()
    env_key = {"fake": key, "unset": None, "other": "a-different-" + "env-key"}[case["key"]]
    if "raw" in case:
        return case["raw"], env_key

    def sig(text, how):
        k = key.encode()
        if how == "valid": return hmac.new(k, text.encode(), hashlib.sha256).hexdigest()
        if how == "wrong-key": return hmac.new(b"not-the-key", text.encode(), hashlib.sha256).hexdigest()
        if how == "wrong-text": return hmac.new(k, (text + "x").encode(), hashlib.sha256).hexdigest()
        if how == "truncated": return hmac.new(k, text.encode(), hashlib.sha256).hexdigest()[:32]
        if how == "empty": return ""
        raise ValueError(how)

    lines = []
    for e in case["events"]:
        e = dict(e)
        if "sig" in e:
            e["sig"] = sig(e["text"], e["sig"])
        lines.append(json.dumps(e))
    return "\n".join(lines) + "\n", env_key


# ---- running and interpreting a guard -----------------------------------------------------
def real_runner(argv, stdin, env, cwd, timeout):
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", True
    return p.returncode, p.stdout, False


def _json_line(out):
    for line in out.strip().splitlines():
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def _interpret(name, rc, out):
    """(flagged, reason). Anything unreadable is flagged, as the guard's contract fails closed."""
    fc = f"fail-closed: unreadable output (rc={rc})"
    if name == "injection":
        j = _json_line(out)
        if not isinstance(j, dict) or "verdict" not in j:
            return True, fc
        return not (rc == 0 and j["verdict"] == "PASS"), f"verdict={j['verdict']} reason={j.get('reason')}"
    if name == "egress":
        j = _json_line(out)
        if rc == 3:
            return True, f"refused rc=3 rule={j.get('rule') if isinstance(j, dict) else None}"
        if not isinstance(j, dict) or "destination" not in j:
            return True, fc
        return not (rc == 0 and j["destination"] == "cloud"), f"class={j.get('class')} destination={j['destination']} rule={j.get('rule')}"
    first = out.strip().split("\n")[0] if out.strip() else ""
    if first.startswith("RED"):
        return True, first
    if first.startswith("GREEN") and rc == 0:
        return False, first
    return True, fc


def _invoke(name, case, runner, tmp):
    _, repo = GUARDS[name]
    cwd = str(GUARD_ROOT / repo)
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}
    if name == "injection":
        f = pathlib.Path(tmp) / "case.txt"
        f.write_text(case["text"] if case.get("literal") else resolve(case["text"]), encoding="utf-8")
        return runner([PY, "scanner.py", str(f)], None, env, cwd, TIMEOUT)
    if name == "egress":
        argv = [PY, "router.py"] + (["--local-down"] if case.get("local_down") else [])
        return runner(argv, json.dumps([resolve(m) for m in case["msgs"]]), env, cwd, TIMEOUT)
    text, key = build_goal(case)
    f = pathlib.Path(tmp) / "t.jsonl"
    f.write_text(text, encoding="utf-8")
    if key is not None:
        env["GOAL_GUARD_KEY"] = key
    return runner([PY, "-m", "goalguard", str(f)], None, env, cwd, TIMEOUT)


def run_guard(name, cases, runner=real_runner):
    results = []
    for case in cases:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                rc, out, timed_out = _invoke(name, case, runner, tmp)
                if timed_out:
                    flagged, reason = True, "fail-closed: timeout"
                else:
                    flagged, reason = _interpret(name, rc, out)
            except Exception as e:
                flagged, reason = True, f"fail-closed: crash ({type(e).__name__})"
        results.append({"guard": name, "id": case["id"], "label": case["label"], "pred": flagged, "reason": reason})
    return results


def load_external():
    """The seeded external sample, scanned literally (no placeholder resolution)."""
    return [dict(json.loads(l), literal=True) for l in EXT_SAMPLE.read_text(encoding="utf-8").splitlines() if l]


def run_external(runner=real_runner):
    return run_guard("injection", load_external(), runner)


def guards_present():
    return all((GUARD_ROOT / repo).is_dir() for _, repo in GUARDS.values())


def run_all(runner=real_runner):
    return [r for name in GUARDS for r in run_guard(name, load_cases(name), runner)]


# ---- report -----------------------------------------------------------------------------------
def summarize(preds):
    rows = ["| guard | attacks | benign | TP | FP | TN | FN | precision [95% CI] | recall [95% CI] |", "|---|---|---|---|---|---|---|---|---|"]
    misses = []
    for name, (label, _) in GUARDS.items():
        mine = [p for p in preds if p["guard"] == name]
        c = confusion([(p["label"] == "attack", p["pred"]) for p in mine])
        prec, rec = rates(c)
        rows.append(f"| {label} | {c['tp'] + c['fn']} | {c['fp'] + c['tn']} | {c['tp']} | {c['fp']} | {c['tn']} | {c['fn']} | "
                    f"{fmt_rate(prec, c['tp'], c['tp'] + c['fp'])} | {fmt_rate(rec, c['tp'], c['tp'] + c['fn'])} |")
        for p in mine:
            if p["label"] == "attack" and not p["pred"]:
                misses.append({"guard": label, "id": p["id"], "kind": "FN", "reason": "attack not flagged: " + p["reason"]})
            if p["label"] == "benign" and p["pred"]:
                misses.append({"guard": label, "id": p["id"], "kind": "FP", "reason": "benign flagged: " + p["reason"]})
    return "\n".join(rows), misses


def summarize_external(preds):
    c = confusion([(p["label"] == "attack", p["pred"]) for p in preds])
    prec, rec = rates(c)
    rows = ["| set | attacks | benign | TP | FP | TN | FN | precision [95% CI] | recall [95% CI] |", "|---|---|---|---|---|---|---|---|---|",
            f"| {EXT_TITLE} | {c['tp'] + c['fn']} | {c['fp'] + c['tn']} | {c['tp']} | {c['fp']} | {c['tn']} | {c['fn']} | "
            f"{fmt_rate(prec, c['tp'], c['tp'] + c['fp'])} | {fmt_rate(rec, c['tp'], c['tp'] + c['fn'])} |"]
    misses = [{"id": p["id"], "kind": "FN" if p["label"] == "attack" else "FP", "reason": p["reason"]}
              for p in preds if (p["label"] == "attack") != p["pred"]]
    return "\n".join(rows), misses


def misses_tsv(preds):
    text = {c["id"]: c["text"] for c in load_external()}
    lines = ["id\tkind\treason\ttext"]
    for m in summarize_external(preds)[1]:
        lines.append(f"{m['id']}\t{m['kind']}\t{' '.join(m['reason'].split())}\t{' '.join(text[m['id']].split())[:140]}")
    return "\n".join(lines) + "\n"


def main(argv):
    if not guards_present():
        print(f"RED guard repos not found under {GUARD_ROOT} (set GUARD_ROOT)")
        return 2
    preds = run_all()
    table, misses = summarize(preds)
    print(table)
    print(f"\nMisses ({len(misses)}):")
    for m in misses:
        print(f"- `{m['id']}` ({m['guard']}, {m['kind']}): {' '.join(m['reason'].split())[:110]}")
    ext = run_external()
    ext_table, ext_misses = summarize_external(ext)
    print(f"\nExternal dataset: {EXT_TITLE}, one scored run, misses listed in external-misses.tsv")
    print(ext_table)
    print(f"External misses ({len(ext_misses)}): see external-misses.tsv")
    if "--record" in argv:
        (ROOT / "predictions.json").write_text(json.dumps(preds, indent=0, sort_keys=True) + "\n")
        (ROOT / "external-predictions.json").write_text(json.dumps(ext, indent=0, sort_keys=True) + "\n")
        (ROOT / "external-misses.tsv").write_text(misses_tsv(ext), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
