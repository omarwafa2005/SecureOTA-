#!/usr/bin/env python3
"""Automated traceability consistency checks (guide Section 12; P2-01, P2-02, P2-03, P2-06, P2-08, P2-09).

Usage:  python tools/check_trace.py      (exit code 0 = all checks pass)

Checks:
  * no duplicate requirement, threat, asset, standards or matrix-row IDs
  * every Must requirement has owner, reviewer (different from owner), component and an implemented test
  * statements use SHALL and avoid vague words (working rules, Section 1)
  * every referenced test exists as a docstring ID in tests/
  * risk score = likelihood x impact, class matches the score band, rationale present
  * every high/critical risk has requirement, prevention, detection, recovery, owner and a negative test
  * every high/critical risk and every Must requirement appears in the traceability matrix
  * matrix rows reference known assets, threats, requirements and tests, with matching scores
  * standards rows avoid certification and compliance claims
"""
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_ID_RE = re.compile(r'"""\s*((?:ACC|AT|FT|QT|E2E)-\d{2}[a-z]?)\s*\|')
THREAT_RE = re.compile(r"^(T|F|V|B|K)-\d+$")
HIGH = 10
CLAIM_WORDS = re.compile(r"\b(?:certified|certification|compliant|compliance with|conforms to)\b", re.I)


def read(name: str) -> list[dict]:
    with open(ROOT / "trace" / name, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for i, row in enumerate(rows, start=2):
        if None in row or any(v is None for v in row.values()):
            raise SystemExit(f"{name}:{i}: wrong number of columns (unquoted comma?)")
    return rows


def split(cell: str) -> list[str]:
    return [x.strip() for x in cell.split("|") if x.strip() and x.strip() != "-"]


def implemented_tests() -> set[str]:
    ids = set()
    for path in (ROOT / "tests").glob("test_*.py"):
        for m in TEST_ID_RE.finditer(path.read_text(encoding="utf-8")):
            ids.add(re.sub(r"[a-z]$", "", m.group(1)))
    return ids


def main() -> int:
    reqs, threats = read("requirements.csv"), read("threats.csv")
    matrix, fields = read("traceability.csv"), read("state_fields.csv")
    assets, standards = read("assets.csv"), read("standards.csv")
    tests = implemented_tests()
    errors: list[str] = []

    def ids(rows, key, name):
        seen = set()
        for r in rows:
            if r[key] in seen:
                errors.append(f"{name}: duplicate id {r[key]}")
            seen.add(r[key])
        return seen

    req_ids = ids(reqs, "id", "requirements")
    threat_ids = ids(threats, "id", "threats")
    asset_ids = ids(assets, "id", "assets")
    ids(standards, "id", "standards")
    must_ids = {r["id"] for r in reqs if r["priority"] == "Must"}

    for r in reqs:
        if r["priority"] not in ("Must", "Should", "Could"):
            errors.append(f"{r['id']}: priority {r['priority']!r} is not Must/Should/Could")
        if r["priority"] == "Must":
            for col in ("owner", "reviewer", "tests", "component"):
                if not r[col].strip():
                    errors.append(f"{r['id']}: Must requirement missing {col}")
            if r["owner"] == r["reviewer"]:
                errors.append(f"{r['id']}: reviewer must differ from owner")
        if "SHALL" not in r["statement"]:
            errors.append(f"{r['id']}: statement has no SHALL")
        for word in ("secure", "fast", "reliable", "user-friendly"):
            if re.search(rf"\b{word}\b", r["statement"], re.I):
                errors.append(f"{r['id']}: vague word '{word}' (working rule)")
        for t in split(r["tests"]):
            if t not in tests:
                errors.append(f"{r['id']}: test {t} not implemented in tests/")
        for s in split(r["source"]):
            if THREAT_RE.match(s) and s not in threat_ids:
                errors.append(f"{r['id']}: source {s} is not a known threat")

    for t in threats:
        L, I, score = int(t["likelihood"]), int(t["impact"]), int(t["score"])
        if not (1 <= L <= 5 and 1 <= I <= 5):
            errors.append(f"{t['id']}: likelihood and impact must be 1-5")
        if L * I != score:
            errors.append(f"{t['id']}: score {score} != {L}x{I}")
        expected = "Critical" if score >= 15 else "High" if score >= 10 else "Medium" if score >= 5 else "Low"
        if t["class"] != expected:
            errors.append(f"{t['id']}: class {t['class']} should be {expected}")
        if not t["likelihood_rationale"] or not t["impact_rationale"]:
            errors.append(f"{t['id']}: missing scoring rationale")
        for a in split(t["asset"]):
            if a not in asset_ids:
                errors.append(f"{t['id']}: unknown asset {a}")
        for rid in split(t["requirements"]):
            if rid not in req_ids:
                errors.append(f"{t['id']}: unknown requirement {rid}")
        if score >= HIGH:
            for col in ("requirements", "prevention", "detection", "recovery", "owner"):
                if not t[col].strip():
                    errors.append(f"{t['id']}: high/critical risk missing {col}")
            negatives = [x for x in split(t["tests"]) if x.startswith(("AT-", "FT-", "QT-"))]
            if not negatives:
                errors.append(f"{t['id']}: high/critical risk has no negative test (AT/FT/QT)")
        for x in split(t["tests"]):
            if x not in tests:
                errors.append(f"{t['id']}: test {x} not implemented in tests/")

    score_of = {t["id"]: t["score"] for t in threats}
    for i, row in enumerate(matrix, start=2):
        if row["asset_id"] not in asset_ids:
            errors.append(f"traceability:{i}: unknown asset {row['asset_id']}")
        if row["requirement_id"] not in req_ids:
            errors.append(f"traceability:{i}: unknown requirement {row['requirement_id']}")
        if row["threat_id"] != "-" and row["threat_id"] not in threat_ids:
            errors.append(f"traceability:{i}: unknown threat {row['threat_id']}")
        if row["test_id"] not in tests:
            errors.append(f"traceability:{i}: unknown test {row['test_id']}")
        if row["threat_id"] in score_of and row["risk_score"] != score_of[row["threat_id"]]:
            errors.append(f"traceability:{i}: risk score differs from threats.csv")
        if not row["evidence_path"].startswith("evidence/"):
            errors.append(f"traceability:{i}: evidence path must be under evidence/")

    covered_threats = {r["threat_id"] for r in matrix}
    for t in threats:
        if int(t["score"]) >= HIGH and t["id"] not in covered_threats:
            errors.append(f"{t['id']}: high/critical risk absent from traceability matrix")
    covered_reqs = {r["requirement_id"] for r in matrix}
    for rid in sorted(must_ids - covered_reqs):
        errors.append(f"{rid}: Must requirement absent from traceability matrix")

    for f in fields:
        for col in ("producer", "consumer", "validation"):
            if not f[col].strip():
                errors.append(f"state_fields {f['field']}: missing {col}")

    for s in standards:
        if CLAIM_WORDS.search(s["relationship"] + " " + s["theme"]):
            errors.append(f"{s['id']}: wording claims certification or compliance")
        if not s["relationship"].startswith(("Informed by", "Mapped to")):
            errors.append(f"{s['id']}: relationship must be 'Informed by' or 'Mapped to'")
        for rid in split(s["requirement_ids"]):
            if rid not in req_ids:
                errors.append(f"{s['id']}: unknown requirement {rid}")

    high = sum(1 for t in threats if int(t["score"]) >= HIGH)
    print(f"requirements: {len(reqs)} ({len(must_ids)} Must) | threats: {len(threats)} "
          f"({high} high/critical) | assets: {len(assets)} | matrix rows: {len(matrix)} | "
          f"standards: {len(standards)} | state fields: {len(fields)} | "
          f"implemented test IDs: {len(tests)}")
    if errors:
        print(f"FAIL: {len(errors)} problem(s)")
        for e in errors:
            print("  -", e)
        return 1
    print("PASS: every Must requirement has owner, reviewer, matrix row and an implemented test;"
          " every high/critical risk has controls, a matrix row and a negative test;"
          " standards rows make no compliance claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
