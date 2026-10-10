#!/usr/bin/env python3
"""
watchdog.py -- the front door and its watchdog rules.

Every lookup goes through one front door, which rings it up as a receipt carrying THREE signatures:
the front door's own, the user's key (their PIN), and the device's key (held in the terminal's
secure chip). So "the sheriff's key only works on the sheriff's devices" is checkable: a copied
password or key used on another machine can't produce that machine's signature under his name.

The rules live in rules.json as data, so the rule set can grow without new code. The rule set is
guarded like everything else: its hash is published as a RULESET receipt, adding a rule needs the
auditor, and weakening or removing one needs the auditor AND the county clerk.

Run it: python watchdog.py     (standard library only; builds on lightlog.py)
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

from lightlog import H, Signer, canon, hx, verify_sig

ROOT = Path(__file__).parent
DAY, HOUR, MIN = 86400, 3600, 60


# --------------------------------------------------------------------------------------------
# The front door: one register for every lookup, review and rule change
# --------------------------------------------------------------------------------------------
class FrontDoor:
    def __init__(self):
        self.badge = Signer("FRONT-DOOR", height=8)
        self.journal, self.payloads, self.seq, self.prev = [], {}, 0, "0" * 64

    def ring(self, t, kind, payload, cosigners=()):
        self.seq += 1
        blob = canon(payload)
        self.payloads[hx(H(blob))] = json.loads(blob)
        body = dict(src="FRONT-DOOR", seq=self.seq, t=t, kind=kind, data=hx(H(blob)), prev=self.prev)
        msg = canon(body)
        rec = dict(body=body, sig=self.badge.sign(msg),
                   cosigs=[dict(who=s.name, sig=s.sign(msg)) for s in cosigners])
        self.prev = hx(H(msg))
        self.journal.append(rec)
        return rec

    def query(self, t, user, device, case, reason, plate, shared_with=None):
        return self.ring(t, "QUERY", dict(user=user.name, device=device.name, case=case, reason=reason,
                                          plate=plate, shared_with=shared_with), cosigners=(user, device))

    def presence(self, t, user, device, live, faces):
        """Eyes on: the device's secure chip matched the user's eyes and checked liveness. Only the
        RESULT is recorded, signed by the device and the unlocked user key. The biometric itself never
        leaves the chip and never enters the journal."""
        return self.ring(t, "PRESENCE", dict(user=user.name, device=device.name, live=live, faces=faces),
                         cosigners=(user, device) if live else (device,))

    def review(self, t, auditor, through_seq, notes):
        return self.ring(t, "REVIEW", dict(auditor=auditor.name, through_seq=through_seq, notes=notes),
                         cosigners=(auditor,))

    def publish_rules(self, t, rules, change, signers):
        return self.ring(t, "RULESET", dict(rules_hash=hx(H(canon(rules))), version=rules["version"],
                                            change=change, rules=rules), cosigners=signers)


def classify_change(old, new):
    """Anything except adding brand-new rules counts as weakening, and needs two signatures."""
    if old is None:
        return "initial"
    old_r, new_r = {r["id"]: r for r in old["rules"]}, {r["id"]: r for r in new["rules"]}
    if all(k in new_r and canon(new_r[k]) == canon(v) for k, v in old_r.items()):
        return "add" if len(new_r) > len(old_r) else "none"
    return "weaken"


# --------------------------------------------------------------------------------------------
# The rule engine: one small function per rule TYPE; rules.json supplies the instances
# --------------------------------------------------------------------------------------------
RULE_TYPES = {}


def rule(name):
    def deco(fn):
        RULE_TYPES[name] = fn
        return fn
    return deco


@rule("key_on_own_devices")
def _(qs, p, ctx):
    for q in qs:
        allowed = p["bindings"].get(q["user"])
        if allowed is None:
            yield q, f"{q['user']} has no registered devices"
        elif q["device"] not in allowed:
            yield q, f"{q['user']}'s key used on {q['device']}, not on their registered devices {allowed}"


@rule("case_must_be_open")
def _(qs, p, ctx):
    for q in qs:
        if q["case"] not in ctx["open_cases"]:
            yield q, f"case '{q['case']}' is not an open case on the county list"


@rule("reason_quality")
def _(qs, p, ctx):
    for q in qs:
        r = q["reason"].strip().lower()
        if len(r) < p["min_chars"] or r in p["banned"]:
            yield q, f"reason '{q['reason']}' is too thin to review"


@rule("off_hours")
def _(qs, p, ctx):
    for q in qs:
        h = (q["t"] // HOUR) % 24
        if not (p["start_h"] <= h < p["end_h"]) and ctx["roles"].get(q["user"]) not in p["exempt_roles"]:
            yield q, f"lookup at {h:02d}:{(q['t'] // MIN) % 60:02d}"


@rule("distinct_plates_per_day")
def _(qs, p, ctx):
    seen = defaultdict(set)
    for q in qs:
        key = (q["user"], q["t"] // DAY)
        seen[key].add(q["plate"])
        if len(seen[key]) == p["max"] + 1:
            yield q, f"{q['user']} looked up {p['max'] + 1}+ different plates on day {key[1] + 1}"


@rule("plates_per_case")
def _(qs, p, ctx):
    seen = defaultdict(set)
    for q in qs:
        seen[q["case"]].add(q["plate"])
        if len(seen[q["case"]]) == p["max"] + 1:
            yield q, f"case {q['case']} has been used for {p['max'] + 1}+ different plates"


@rule("protected_plates")
def _(qs, p, ctx):
    for q in qs:
        if q["plate"] in ctx["protected"]:
            yield q, "a protected plate was looked up: sent to the auditor"


@rule("sharing_allowlist")
def _(qs, p, ctx):
    for q in qs:
        if q.get("shared_with") and q["shared_with"] not in p["allowed"]:
            yield q, f"result shared with '{q['shared_with']}', which is not on the approved list"


@rule("impossible_travel")
def _(qs, p, ctx):
    last = {}
    for q in qs:
        prev = last.get(q["user"])
        if prev and prev["device"] != q["device"] and q["t"] - prev["t"] < p["minutes"] * MIN:
            yield q, f"{q['user']} on {prev['device']} and {q['device']} within {(q['t'] - prev['t']) // MIN} min"
        last[q["user"]] = q


@rule("eyes_on")
def _(qs, p, ctx):
    """Every lookup needs a live eye match for the same person on the same device, moments before."""
    for q in qs:
        ok = [e for e in ctx["presence"] if e["user"] == q["user"] and e["device"] == q["device"]
              and e["live"] and e["user_signed"] and 0 <= q["t"] - e["t"] <= p["max_age_s"]]
        if not ok:
            yield q, f"no live eye match for {q['user']} on {q['device']} in the {p['max_age_s']} s before this lookup"


@rule("liveness_failed")
def _(qs, p, ctx):
    for e in ctx["presence"]:
        if not e["live"]:
            yield e, f"eye match on {e['device']} failed liveness (photo, screen or replay?)"


@rule("extra_eyes")
def _(qs, p, ctx):
    for e in ctx["presence"]:
        if e["faces"] > p["max_faces"]:
            yield e, f"{e['faces']} faces in view of {e['device']} while {e['user']} was looking"


@rule("review_overdue")
def _(qs, p, ctx):
    reviews = sorted(ctx["reviews"])
    checkpoints = [0] + reviews + [ctx["now"]]
    for a, b in zip(checkpoints, checkpoints[1:]):
        if b - a > p["max_days"] * DAY:
            yield dict(seq="-", t=b), f"no signed auditor review for {(b - a) / DAY:.1f} days (max {p['max_days']})"


@rule("revoked_key")
def _(qs, p, ctx):
    for q in qs:
        if q["user"] in p["revoked"]:
            yield q, f"revoked key '{q['user']}' was used"


# --------------------------------------------------------------------------------------------
# The watchdog: verify signatures and the rule set, then run every rule
# --------------------------------------------------------------------------------------------
def watch(door, rules_on_disk, registry, ctx):
    findings = []
    queries, reviews, rulesets, presence = [], [], [], []
    for rec in door.journal:
        b, msg = rec["body"], canon(rec["body"])
        p = door.payloads[b["data"]]
        if not verify_sig(registry["FRONT-DOOR"], msg, rec["sig"]):
            findings.append(("RED", "SIG", b["seq"], "front door signature fails"))
        signed = {c["who"] for c in rec["cosigs"]
                  if c["who"] in registry and verify_sig(registry[c["who"]], msg, c["sig"])}
        if b["kind"] == "QUERY":
            if p["user"] not in signed:
                findings.append(("RED", "SIG", b["seq"], f"no valid signature from user '{p['user']}'"))
            if p["device"] not in signed:
                findings.append(("RED", "SIG", b["seq"], f"no valid signature from device '{p['device']}'"))
            queries.append(dict(p, t=b["t"], seq=b["seq"]))
        elif b["kind"] == "PRESENCE":
            if p["device"] not in signed:
                findings.append(("RED", "SIG", b["seq"], f"presence not signed by device '{p['device']}'"))
            presence.append(dict(p, t=b["t"], seq=b["seq"], user_signed=p["user"] in signed))
        elif b["kind"] == "REVIEW" and p["auditor"] in signed:
            reviews.append(b["t"])
        elif b["kind"] == "RULESET":
            rulesets.append((b["seq"], p, signed))

    # the rules guard themselves
    prev_rules = None
    for seq, p, signed in rulesets:
        change = classify_change(prev_rules, p["rules"])
        need = {"initial": {"auditor"}, "add": {"auditor"}, "weaken": {"auditor", "clerk"}, "none": {"auditor"}}[change]
        have = {ctx["offices"].get(s) for s in signed}
        if not need <= have:
            findings.append(("RED", "RULES", seq, f"rule change '{change}' signed by {sorted(have - {None}) or 'nobody'}; needs {sorted(need)}"))
        if p["change"] != change:
            findings.append(("RED", "RULES", seq, f"labelled '{p['change']}' but is really '{change}'"))
        prev_rules = p["rules"]
    if prev_rules is None or hx(H(canon(rules_on_disk))) != hx(H(canon(prev_rules))):
        findings.append(("RED", "RULES", "-", "rules.json on disk is not the rule set published on the journal"))

    ctx = dict(ctx, reviews=reviews, presence=presence)
    for r in prev_rules["rules"] if prev_rules else []:
        fn = RULE_TYPES.get(r["type"])
        if fn is None:
            findings.append(("RED", r["id"], "-", f"rule type '{r['type']}' has no checker: fail loud, never skip"))
            continue
        for q, msg in fn(queries, r["params"], ctx):
            findings.append((r["severity"], r["id"], q["seq"], msg))
    return findings


# --------------------------------------------------------------------------------------------
# A week at the sheriff's office, with a few things going wrong
# --------------------------------------------------------------------------------------------
def week(rules):
    people = {n: Signer(n, height=6) for n in
              ("sheriff", "deputy-a", "investigator-b", "former-deputy-c", "auditor-board", "county-clerk")}
    devices = {n: Signer(n, height=7) for n in ("SO-TERM-01", "SO-TERM-02", "SO-LAPTOP-S1", "SO-MDT-07", "UNKNOWN-PC")}
    door = FrontDoor()
    registry = {"FRONT-DOOR": hx(door.badge.root), **{k: hx(v.root) for k, v in {**people, **devices}.items()}}
    ctx = dict(open_cases={"26-0412", "26-0418"},
               roles={"sheriff": "sheriff", "deputy-a": "deputy", "investigator-b": "investigator"},
               protected={"SHELTER1"},
               offices={"auditor-board": "auditor", "county-clerk": "clerk"},
               now=10 * DAY)
    P, D = people, devices
    real_query = door.query

    def look(t, user, device, *a, eyes=True, live=True, faces=1, **k):
        if eyes:
            door.presence(t - 20, user, device, live, faces)
        return real_query(t, user, device, *a, **k)

    door.query = look
    door.publish_rules(0, rules, "initial", [P["auditor-board"]])
    d1 = DAY + 9 * HOUR
    door.query(d1, P["deputy-a"], D["SO-MDT-07"], "26-0412", "stolen truck seen on Hwy 67 report", "7ABC123")
    door.query(d1 + 2 * HOUR, P["sheriff"], D["SO-LAPTOP-S1"], "26-0418", "hit-and-run suspect vehicle, witness partial", "ARK55X1")
    door.query(d1 + 3 * HOUR, P["investigator-b"], D["SO-TERM-02"], "26-0418", "second partial-plate candidate", "ARK55X7",
               shared_with="Arkansas State Police")
    door.review(2 * DAY + 10 * HOUR, P["auditor-board"], door.seq, "all lookups tied to open cases")
    # the planted problems
    door.query(3 * DAY + 14 * HOUR, P["sheriff"], D["UNKNOWN-PC"], "26-0418", "follow-up on hit-and-run vehicle", "ARK55X1",
               eyes=False)  # someone with the sheriff's password, but not his eyes
    door.query(3 * DAY + 14 * HOUR + 4 * MIN, P["sheriff"], D["SO-LAPTOP-S1"], "26-0418", "follow-up on hit-and-run vehicle", "ARK55X2")
    door.query(4 * DAY + 2 * HOUR + 17 * MIN, P["deputy-a"], D["SO-MDT-07"], "26-9999", "idk", "SHELTER1", faces=2)
    door.presence(4 * DAY + 3 * HOUR, P["deputy-a"], D["SO-MDT-07"], live=False, faces=1)  # a photo held up to the camera
    for k in range(16):
        door.query(5 * DAY + 13 * HOUR + k * MIN, P["investigator-b"], D["SO-TERM-02"], "26-0412",
                   "canvass of plates near the theft location", f"ARK{100 + k}", shared_with="Data Broker LLC" if k == 15 else None)
    door.query(6 * DAY + 11 * HOUR, P["former-deputy-c"], D["SO-TERM-01"], "26-0412", "checking an old lead on the truck", "7ABC123")
    door.query = real_query
    return door, registry, ctx, P


def show(title, findings):
    print(f"\n{title}")
    if not findings:
        print("   GREEN  every signature verifies, rules match the journal, no rule fired")
    order = {"RED": 0, "AMBER": 1}
    for sev, rid, seq, msg in sorted(findings, key=lambda f: (order[f[0]], str(f[1]))):
        print(f"   {sev:5} {rid:5} #{str(seq):3} {msg}")


if __name__ == "__main__":
    import copy
    sys.stdout.reconfigure(encoding="utf-8")
    rules = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))
    door, registry, ctx, P = week(rules)
    show(f"A week at the front door: {door.seq} receipts, {len(rules['rules'])} rules", watch(door, rules, registry, ctx))

    # someone quietly drops the protected-plate rule, signed by the auditor alone
    weaker = copy.deepcopy(rules)
    weaker["version"] = 2
    weaker["rules"] = [r for r in weaker["rules"] if r["id"] != "R07"]
    door2 = copy.deepcopy(door)
    door2.publish_rules(7 * DAY, weaker, "add", [P["auditor-board"]])
    f = [x for x in watch(door2, weaker, registry, ctx) if x[1] == "RULES"]
    show("Rule R07 removed with one signature, labelled as a harmless 'add'", f)

    # someone edits rules.json on the server and never publishes it
    edited = copy.deepcopy(rules)
    edited["rules"][4]["params"]["max"] = 500
    f = [x for x in watch(door, edited, registry, ctx) if x[1] == "RULES"]
    show("rules.json edited on the server (bulk-search limit 15 -> 500), never published", f)

    # a new rule added properly: one auditor signature, and it starts working at once
    grown = copy.deepcopy(rules)
    grown["version"] = 2
    grown["rules"].append({"id": "R15", "type": "protected_plates", "severity": "RED", "params": {"list": "v2"},
                           "why": "example of the rule set growing"})
    door3 = copy.deepcopy(door)
    door3.publish_rules(7 * DAY, grown, "add", [P["auditor-board"]])
    f = [x for x in watch(door3, grown, registry, ctx) if x[1] in ("RULES", "R15")]
    show("A new rule R15 added the proper way (auditor signs), applied to the whole history", f)
