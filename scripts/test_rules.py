#!/usr/bin/env python3
"""Replay the example events through the Sigma rules and check what fires.

This is a small reference evaluator, written so the repo can prove each
rule fires on its scenario and stays quiet on the others. It supports the
subset of Sigma used in rules/sigma/:

- field equals value, list of values (OR), modifiers startswith, gte, exists
- conditions built from selection names with and / or / not
- correlation types event_count, value_count, temporal_ordered, with
  sliding windows and correlation chaining

It is not a replacement for your SIEM backend. Convert the rules with
sigma-cli for production use, then verify there with the same events.
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules" / "sigma"
EVENTS_DIR = ROOT / "examples" / "events"

# Scenario file -> alerting rule ids expected to fire (level above informational).
EXPECTED = {
    # One IP inside one ASN also crosses the spray threshold. Both firing is correct.
    "credential-stuffing": {"DET-AUTH-01", "DET-AUTH-03"},
    "password-spray": {"DET-AUTH-03"},
    "brute-force-single-account": set(),
    "mfa-fatigue": {"DET-AUTH-06"},
    "device-change-then-transfer": {"DET-BIZ-01"},
    "reset-flood": set(),
    "session-hijack": {"DET-SESS-01"},
    "object-level-probe": {"DET-AUTHZ-01", "DET-AUTHZ-02"},
    "admin-route-probe": {"DET-AUTHZ-04"},
    "mass-assignment": set(),
    "bulk-export": set(),
    "account-takeover-chain": {"DET-BIZ-01"},
    "limit-raise-drain": set(),
    "below-threshold-transfers": set(),
    "tampered-amounts": set(),
    "promo-abuse": set(),
    "scanner-noise": {"DET-INPUT-01", "DET-INPUT-02"},
    "insider-lookups": {"DET-DATA-02"},
    "privileged-grant": {"DET-AUTHZ-05"},
    "config-change": {"DET-PLAT-01"},
    "refresh-token-reuse": {"DET-AUTH-09"},
    "idempotency-conflict": {"DET-BIZ-05"},
}

DET_ID = re.compile(r"\((DET-[A-Z]+-\d+)\)")
SPAN = re.compile(r"^(\d+)([smhd])$")


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def timespan(value: str) -> timedelta:
    m = SPAN.match(value)
    if not m:
        raise ValueError(f"bad timespan {value}")
    n, unit = int(m.group(1)), m.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: n})


def match_item(event: dict, key: str, expected) -> bool:
    field, *mods = key.split("|")
    values = expected if isinstance(expected, list) else [expected]
    if "exists" in mods:
        return (field in event) == bool(values[0])
    if field not in event:
        return any(v is None for v in values)
    actual = event[field]
    for v in values:
        if "startswith" in mods and isinstance(actual, str) and actual.startswith(str(v)):
            return True
        if "gte" in mods and isinstance(actual, (int, float)) and actual >= v:
            return True
        if not mods and actual == v:
            return True
    return False


def match_selection(event: dict, selection: dict) -> bool:
    return all(match_item(event, k, v) for k, v in selection.items())


def eval_condition(condition: str, results: dict[str, bool]) -> bool:
    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    expr = []
    for tok in tokens:
        if tok in ("and", "or", "not", "(", ")"):
            expr.append(tok)
        elif tok in results:
            expr.append(str(results[tok]))
        else:
            raise ValueError(f"unsupported condition token {tok!r}")
    return bool(eval(" ".join(expr), {"__builtins__": {}}, {}))  # noqa: S307 (tokens are whitelisted)


class Rule:
    def __init__(self, doc: dict, path: Path) -> None:
        self.doc = doc
        self.path = path
        self.title = doc["title"]
        self.name = doc.get("name")
        self.level = doc.get("level", "medium")
        m = DET_ID.search(self.title)
        self.det_id = m.group(1) if m else None
        self.alerting = self.level != "informational" and self.det_id is not None

    def matches(self, event: dict) -> bool:
        det = self.doc["detection"]
        results = {k: match_selection(event, v) for k, v in det.items() if k != "condition"}
        return eval_condition(det["condition"], results)


def load_rules() -> list[Rule]:
    rules = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if doc:
                rules.append(Rule(doc, path))
    return rules


def hits_for(rule: Rule, events: list[dict], by_name: dict[str, Rule], cache: dict) -> list[dict]:
    """Return the list of hits a rule produces. A hit is a dict with ts and group fields."""
    key = id(rule)
    if key in cache:
        return cache[key]
    if "correlation" not in rule.doc:
        out = [dict(e, _ts=parse_ts(e["ts"])) for e in events if rule.matches(e)]
        cache[key] = out
        return out

    corr = rule.doc["correlation"]
    span = timespan(corr["timespan"])
    group_by = corr.get("group-by", [])
    refs = [by_name[n] for n in corr["rules"]]
    out: list[dict] = []

    def gkey(h: dict):
        return tuple(h.get(f) for f in group_by)

    if corr["type"] in ("event_count", "value_count"):
        cond = corr["condition"]
        threshold = cond["gte"]
        groups: dict = defaultdict(list)
        for ref in refs:
            for h in hits_for(ref, events, by_name, cache):
                groups[gkey(h)].append(h)
        for g, hs in groups.items():
            hs.sort(key=lambda h: h["_ts"])
            fired = False
            for i, last in enumerate(hs):
                window = [h for h in hs[: i + 1] if last["_ts"] - h["_ts"] <= span]
                if corr["type"] == "event_count":
                    value = len(window)
                else:
                    value = len({h.get(cond["field"]) for h in window if h.get(cond["field"]) is not None})
                if value >= threshold and not fired:
                    out.append(dict(zip(group_by, g), _ts=last["_ts"]))
                    fired = True
                elif value < threshold:
                    fired = False
    elif corr["type"] == "temporal_ordered":
        per_ref = [hits_for(r, events, by_name, cache) for r in refs]
        groups = defaultdict(lambda: [[] for _ in refs])
        for idx, hs in enumerate(per_ref):
            for h in hs:
                groups[gkey(h)][idx].append(h["_ts"])
        for g, lists in groups.items():
            for start in lists[0]:
                t = start
                ok = True
                for later in lists[1:]:
                    nxt = [x for x in later if x >= t and x - start <= span]
                    if not nxt:
                        ok = False
                        break
                    t = min(nxt)
                if ok:
                    out.append(dict(zip(group_by, g), _ts=t))
                    break
    else:
        raise ValueError(f"unsupported correlation type {corr['type']}")

    cache[key] = out
    return out


def main() -> int:
    rules = load_rules()
    by_name = {r.name: r for r in rules if r.name}
    files = {p.stem: p for p in sorted(EVENTS_DIR.glob("*.jsonl"))}
    failures = 0

    missing = set(EXPECTED) ^ set(files)
    if missing:
        print(f"Scenario list and event files differ: {sorted(missing)}")
        return 1

    covered: set[str] = set()
    for name, path in files.items():
        events = [json.loads(line) for line in path.read_text().splitlines()]
        cache: dict = {}
        fired = {r.det_id for r in rules if r.alerting and hits_for(r, events, by_name, cache)}
        covered |= fired
        expected = EXPECTED[name]
        status = "ok" if fired == expected else "FAIL"
        if fired != expected:
            failures += 1
        print(f"{status:4}  {name:30} fired={sorted(fired) or '-'} expected={sorted(expected) or '-'}")

    rule_ids = {r.det_id for r in rules if r.alerting}
    never = rule_ids - covered
    if never:
        print(f"FAIL  rules with no scenario that fires them: {sorted(never)}")
        failures += 1

    if failures:
        print(f"{failures} failure(s)", file=sys.stderr)
        return 1
    print(f"All {len(files)} scenarios behave as expected across {len(rule_ids)} alerting detections.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
