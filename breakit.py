#!/usr/bin/env python3
"""
breakit.py -- try to break the commit-before-release chain. Each attack is scored:
  HELD   the attack was blocked, or it was caught and named
  BROKEN the attack worked unseen (these are the open problems; see DESIGN.md)

Run: python breakit.py
"""
import copy
import json
import sys

from ackgate import FrontDoor, build, witness_check
from lightlog import H, Signer, canon, hx

results = []


def score(name, held, detail):
    results.append((name, held, detail))


def fresh(n=2):
    gate, wd, door, link = build()
    for k in range(n):
        door.lookup(100 + k * 10, link.carry, "deputy-a", f"ARK{k}", "26-0412", "...")
    return gate, wd, door, link


# A1 a fake mirror hands back receipts signed by the wrong key, to drain the queue
gate, wd, door, link = fresh()
fake = Signer("NOT-THE-WATCHDOG", height=4)


def forged(frame, now):
    r = dict(record=hx(H(canon(json.loads(frame)["body"]))), wd_seq=1, wd_head="0" * 64, wd_t=now)
    return dict(receipt=r, sig=fake.sign(canon(r)))


out = door.lookup(500, forged, "deputy-a", "XYZ1", "26-0412", "...")
score("fake receipts to release data and drain the queue", out.startswith("WITHHELD") and door.outbox,
      f"{out}; {len(door.outbox)} entries kept queued for the real watchdog")

# A2 replay an already-accepted record
gate, wd, door, link = fresh()
old = json.dumps(dict(body=door.journal[0]["body"], sig=door.journal[0]["sig"], payload=door.journal[0]["payload"])).encode()
score("replay an old record", link.carry(old, 600) is None and gate.alarms, gate.alarms[-1] if gate.alarms else "accepted")

# A3 rewrite history: resend a record whose prev doesn't match what the watchdog holds
gate, wd, door, link = fresh()
door.prev = "f" * 64
door.ring(600, "QUERY", dict(user="deputy-a", plate="ARK9", case="26-0412"))
door.flush(link.carry, 600)
score("fork the history sent to the watchdog", bool(door.outbox) and gate.alarms, gate.alarms[-1] if gate.alarms else "accepted")

# A4 swap the payload after signing (log one plate, look up another)
gate, wd, door, link = fresh()
door.ring(600, "QUERY", dict(user="deputy-a", plate="ARK1", case="26-0412"))
f = json.loads(door.outbox[0])
f["payload"]["plate"] = "SHELTER1"
score("swap the payload under a valid signature", link.carry(json.dumps(f).encode(), 600) is None and gate.alarms,
      gate.alarms[-1] if gate.alarms else "accepted")

# A5 clone the front door (same key on two machines)
gate, wd, door, link = fresh()
clone = copy.deepcopy(door)
door.lookup(600, link.carry, "deputy-a", "ARK7", "26-0412", "...")
out = clone.lookup(610, link.carry, "deputy-a", "SHELTER1", "26-0412", "...")
score("clone the front door's key onto a second machine", out.startswith("WITHHELD") and gate.alarms,
      gate.alarms[-1] if gate.alarms else out)

# A6 back-date a record
gate, wd, door, link = fresh()
door.ring(50, "QUERY", dict(user="deputy-a", plate="ARK8", case="26-0412"))
door.flush(link.carry, 600)
score("back-date a record", bool(door.outbox) and gate.alarms, gate.alarms[-1] if gate.alarms else "accepted")

# A7 a dishonest watchdog signs receipts without recording
gate, wd, door, link = fresh()
wd.skip_recording = True
door.lookup(600, link.carry, "investigator-b", "ARK2001", "26-0418", "...")
probs = witness_check(door, wd, link, 700)
score("watchdog signs without recording", any("link sentinel passed" in p or "signed without" in p for p in probs),
      next((p for p in probs if "link sentinel" in p or "signed without" in p), "unseen"))

# A8 junk at the watchdog: commands, HTTP, garbage, a signature over something else
gate, wd, door, link = fresh()
junk = [b"GET /admin HTTP/1.1", b'{"cmd":"delete_all"}', b"\x00" * 64,
        json.dumps(dict(body=dict(src="FRONT-DOOR", seq=3, t=600, kind="QUERY", data="x", prev="y"),
                        sig=door.key.sign(b"other"), payload={})).encode()]
score("reach the watchdog with anything but a log record", all(link.carry(j, 600) is None for j in junk),
      f"{len(gate.dropped)} frames dropped at the gate")

# A9 break-glass as a habit
gate, wd, door, link = fresh()
for k in range(3):
    door.lookup(600 + k, lambda f, n: None, "deputy-a", f"BG{k}", "26-0412", "...", break_glass=True)
door.flush(link.carry, 700)
probs = witness_check(door, wd, link, 700)
score("make break-glass the normal path", any("becoming the normal path" in p for p in probs),
      next((p for p in probs if "normal path" in p), "unseen"))

# A10 the watchdog's side tries to send data back out through the mirror
gate, wd, door, link = fresh()
wd.receive = lambda msg, now: {"plates": ["ARK1", "ARK2"]}
door.ring(600, "QUERY", dict(user="deputy-a", plate="ARK3", case="26-0412"))
score("send data back through the mirror (exfiltration)", door.flush(link.carry, 600) == {} and gate.alarms,
      gate.alarms[-1] if gate.alarms else "leaked")

# A11 the watchdog and the link sentinel collude (watchdog skips, sentinel's count lowered to match)
gate, wd, door, link = fresh()
wd.skip_recording = True
door.lookup(600, link.carry, "investigator-b", "ARK2002", "26-0418", "...")
link.passed_in -= 1
probs = witness_check(door, wd, link, 700)
score("watchdog + link sentinel collude", any("signed without" in p or "different records" in p for p in probs),
      next((p for p in probs if "signed without" in p or "different records" in p), "unseen"))

# A12 an insider at dispatch reads the plate store directly, never calling the front door
gate, wd, door, link = fresh()
door.released.append(("insider", "SHELTER1", "read straight from the database"))
probs = witness_check(door, wd, link, 700)
score("read the plate store directly, skipping the front door", False,
      "nothing records it: the store itself must refuse to release without a receipt (see DESIGN: key release)")

# A13 exhaust the one-time keys with spam lookups (denial of service)
gate, wd, door, link = build()
door.key = Signer("FRONT-DOOR", height=3)
link.gate.senders["FRONT-DOOR"] = hx(door.key.root)
try:
    for k in range(10):
        door.lookup(100 + k, link.carry, "deputy-a", f"SPAM{k}", "26-0412", "...")
    exhausted = False
except RuntimeError:
    exhausted = True
score("exhaust the front door's one-time keys (denial of service)", not exhausted,
      "front door stopped signing: real LMS trees are far larger, but lookups also need rate limits" if exhausted else "ok")

# A14 search by area instead of plate, to find people at a protected address without naming them
import watchdog as W
q = [dict(user="deputy-a", plate="AREA:shelter street 01:00-03:00", case="26-0412", t=0, seq=1, device="SO-MDT-07")]
before = list(W.RULE_TYPES["protected_plates"](q, {}, dict(protected={"SHELTER1"})))
rules = json.load(open("rules.json", encoding="utf-8"))
r16 = next(r for r in rules["rules"] if r["type"] == "area_or_partial")
after = list(W.RULE_TYPES["area_or_partial"](q, r16["params"], {}))
score("search by area to find a protected address without naming a plate", bool(after) and not before,
      ("protected-plate rule misses it; R16 catches it: " + after[0][1]) if after else "unseen")

sys.stdout.reconfigure(encoding="utf-8")
w = max(len(r[0]) for r in results)
for name, held, detail in results:
    print(f"{'HELD  ' if held else 'BROKEN'}  {name:{w}}  {detail}")
print(f"\n{sum(1 for r in results if r[1])} held, {sum(1 for r in results if not r[1])} broken")
