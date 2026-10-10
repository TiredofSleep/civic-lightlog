#!/usr/bin/env python3
"""
ackgate.py -- commit before release.

Nothing leaves the system until the independent watchdog has recorded it and its mirror has said so.

    dispatch Jetson                 LINK SENTINEL (FPGA, owned by neither side)           watchdog Jetson
      front door  --frames-->  [ gate: only well-formed, signed, in-order records ] -->  records them
                  <--receipts- [ mirror: only fixed-size signed receipts          ] <--  signs receipts
                               counts + fingerprints both directions, signs the tally,
                               reports it to the witnesses on its own radio: the tiebreaker

- You can't reach the watchdog unless you're sending logs: the gate drops everything else.
- Only the log knows if it logged the log: only the watchdog's key can sign a receipt.
- The log logs the log: every front-door entry, receipts included, goes to the watchdog in order;
  nothing is released until its receipt is verified and journaled.
- No receipt, no release (fail closed). Emergencies use a break-glass path that is itself a red flag.

Same pattern as Certificate Transparency's signed certificate timestamps. Run: python ackgate.py
Attacks against it: python breakit.py
"""
import json
import sys

from lightlog import H, Signer, canon, hx, verify_sig

RECORD_FIELDS = {"src", "seq", "t", "kind", "data", "prev"}
RECEIPT_FIELDS = {"record", "wd_seq", "wd_head", "wd_t"}
CLOCK_TOLERANCE_S = 120


# --------------------------------------------------------------------------------------------
# The gate (in hardware: the FPGA): exact format, registered sender, valid signature,
# payload matches its hash, one-time keys never reused, records strictly in order
# --------------------------------------------------------------------------------------------
class Gate:
    def __init__(self, senders):
        self.senders = senders
        self.dropped, self.alarms = [], []
        self.used_leaves = {}  # sender -> {one-time key leaf: record hash it signed}
        self.last = {}         # sender -> (seq, record hash, record time)

    def _drop(self, frame, why, alarm=False):
        self.dropped.append(why)
        if alarm:
            self.alarms.append(why)
        return None

    def admit(self, frame):
        try:
            msg = json.loads(frame)
            body, sig, payload = msg["body"], msg["sig"], msg["payload"]
            if set(msg) != {"body", "sig", "payload"} or set(body) != RECORD_FIELDS:
                return self._drop(frame, "not a log record")
        except (ValueError, KeyError, TypeError):
            return self._drop(frame, "not a log record")
        src = body["src"]
        if src not in self.senders or not verify_sig(self.senders[src], canon(body), sig):
            return self._drop(frame, f"bad signature or unknown sender '{src}'")
        if hx(H(canon(payload))) != body["data"]:
            return self._drop(frame, f"{src} #{body['seq']}: payload doesn't match its hash", alarm=True)
        leaf, rh = sig["leaf"], hx(H(canon(body)))
        seen = self.used_leaves.setdefault(src, {})
        if leaf in seen and seen[leaf] == rh:
            return self._drop(frame, f"{src} #{body['seq']}: replay of a record already received", alarm=True)
        if leaf in seen:
            return self._drop(frame, f"{src} reused one-time key #{leaf} on a different record: the key has been cloned", alarm=True)
        seq0, h0, t0 = self.last.get(src, (0, "0" * 64, None))
        if body["seq"] <= seq0:
            return self._drop(frame, f"{src} #{body['seq']}: replay or rewrite of an earlier record", alarm=True)
        if body["seq"] != seq0 + 1 or body["prev"] != h0:
            return self._drop(frame, f"{src} #{body['seq']}: out of order or forked from the watchdog's copy", alarm=True)
        if t0 is not None and body["t"] < t0:
            return self._drop(frame, f"{src} #{body['seq']}: time runs backwards ({t0} -> {body['t']}): back-dated", alarm=True)
        seen[leaf] = rh
        self.last[src] = (body["seq"], rh, body["t"])
        return msg


# --------------------------------------------------------------------------------------------
# The watchdog and its mirror
# --------------------------------------------------------------------------------------------
class Watchdog:
    def __init__(self):
        self.key = Signer("WATCHDOG", height=7)
        self.chain, self.head = [], "0" * 64
        self.alarms = []
        self.skip_recording = False  # a dishonest watchdog, for testing

    def receive(self, msg, now):
        rh = hx(H(canon(msg["body"])))
        if msg["body"]["t"] > now + CLOCK_TOLERANCE_S:
            self.alarms.append(f"{msg['body']['src']} #{msg['body']['seq']}: dated {msg['body']['t'] - now} s in the future")
        if not self.skip_recording:
            self.chain.append(dict(record=rh, prev=self.head, payload=msg["payload"], kind=msg["body"]["kind"]))
            self.head = hx(H(canon(self.chain[-1])))
        return self.mirror(rh, now)

    def mirror(self, record_hash, now):
        """The mirror only ever emits this one shape: which record, where in the chain, when, signed."""
        receipt = dict(record=record_hash, wd_seq=len(self.chain), wd_head=self.head, wd_t=now)
        return dict(receipt=receipt, sig=self.key.sign(canon(receipt)))


# --------------------------------------------------------------------------------------------
# The link sentinel: the only path between the two Jetsons, owned by neither
# --------------------------------------------------------------------------------------------
class LinkSentinel:
    def __init__(self, gate, watchdog):
        self.gate, self.wd = gate, watchdog
        self.key = Signer("LINK-SENTINEL", height=6)
        self.passed_in = self.passed_out = 0
        self.fp_in = self.fp_out = "0" * 64

    def carry(self, frame, now):
        msg = self.gate.admit(frame)
        if msg is None:
            return None
        self.passed_in += 1
        self.fp_in = hx(H(bytes.fromhex(self.fp_in) + H(canon(msg["body"]))))
        ack = self.wd.receive(msg, now)
        if not (isinstance(ack, dict) and set(ack) == {"receipt", "sig"} and set(ack["receipt"]) == RECEIPT_FIELDS):
            self.gate.alarms.append("the watchdog sent something that isn't a receipt: blocked at the mirror")
            return None
        self.passed_out += 1
        self.fp_out = hx(H(bytes.fromhex(self.fp_out) + H(canon(ack["receipt"]))))
        return ack

    def tally(self, now):
        """Signed and sent to the witnesses on the sentinel's own radio, on a schedule."""
        t = dict(t=now, passed_in=self.passed_in, passed_out=self.passed_out, fp_in=self.fp_in, fp_out=self.fp_out,
                 dropped=len(self.gate.dropped))
        return dict(tally=t, sig=self.key.sign(canon(t)))


# --------------------------------------------------------------------------------------------
# The front door: journal, send everything in order, verify the receipt, journal it, then release
# --------------------------------------------------------------------------------------------
class FrontDoor:
    def __init__(self, wd_root, key=None):
        self.key = key or Signer("FRONT-DOOR", height=7)
        self.wd_root = wd_root
        self.journal, self.seq, self.prev, self.released, self.outbox = [], 0, "0" * 64, [], []

    def ring(self, t, kind, payload):
        self.seq += 1
        body = dict(src="FRONT-DOOR", seq=self.seq, t=t, kind=kind, data=hx(H(canon(payload))), prev=self.prev)
        sig = self.key.sign(canon(body))
        self.prev = hx(H(canon(body)))
        self.journal.append(dict(body=body, sig=sig, payload=payload))
        self.outbox.append(json.dumps(dict(body=body, sig=sig, payload=payload)).encode())
        return body

    def valid_receipt(self, ack, record_hash):
        return (isinstance(ack, dict) and set(ack.get("receipt", {})) == RECEIPT_FIELDS
                and ack["receipt"]["record"] == record_hash
                and verify_sig(self.wd_root, canon(ack["receipt"]), ack["sig"]))

    def flush(self, link, now):
        """Send the queue in order. A frame leaves the queue only on a VALID receipt for that frame."""
        acks = {}
        while self.outbox:
            frame = self.outbox[0]
            rh = hx(H(canon(json.loads(frame)["body"])))
            ack = link(frame, now)
            if not self.valid_receipt(ack, rh):
                break
            acks[rh] = ack
            self.outbox.pop(0)
        return acks

    def lookup(self, t, link, user, plate, case, result, break_glass=False):
        body = self.ring(t, "QUERY", dict(user=user, plate=plate, case=case))
        rh = hx(H(canon(body)))
        ack = self.flush(link, t).get(rh)
        if ack:
            self.ring(t, "RECEIPT", ack)  # the log logs the log
            self.flush(link, t)
            self.released.append((user, plate, result))
            return "RELEASED"
        if break_glass:
            self.ring(t, "BREAK_GLASS", dict(user=user, plate=plate, case=case, why="no watchdog receipt"))
            self.released.append((user, plate, result))
            return "RELEASED UNDER BREAK-GLASS (red flag, needs a response)"
        self.ring(t, "WITHHELD", dict(user=user, plate=plate, why="no valid watchdog receipt"))
        return "WITHHELD: no receipt, no release"


# --------------------------------------------------------------------------------------------
# The witness check, run from the watchdog's published chain
# --------------------------------------------------------------------------------------------
def witness_check(door, wd, link, now, max_break_glass=2):
    problems = []
    tl = link.tally(now)
    if not verify_sig(hx(link.key.root), canon(tl["tally"]), tl["sig"]):
        problems.append("link sentinel tally doesn't verify")
    t = tl["tally"]
    if t["passed_in"] != len(wd.chain):
        problems.append(f"link sentinel passed {t['passed_in']} records to the watchdog; its chain holds {len(wd.chain)}")
    fp = "0" * 64
    for e in wd.chain:
        fp = hx(H(bytes.fromhex(fp) + bytes.fromhex(e["record"])))
    if len(wd.chain) == t["passed_in"] and fp != t["fp_in"]:
        problems.append("the watchdog's chain holds different records than the link sentinel passed")
    in_chain = {e["record"]: n + 1 for n, e in enumerate(wd.chain)}
    for e in door.journal:
        if e["body"]["kind"] == "RECEIPT":
            r = e["payload"]["receipt"]
            if in_chain.get(r["record"]) != r["wd_seq"]:
                problems.append(f"receipt claims watchdog entry #{r['wd_seq']} holds record {r['record'][:10]}…, "
                                f"but the watchdog's chain doesn't: it signed without recording")
    glass = [e for e in wd.chain if e["kind"] == "BREAK_GLASS"]
    for e in glass:
        problems.append(f"break-glass release to {e['payload']['user']} (plate {e['payload']['plate']}): needs a signed response")
    if len(glass) > max_break_glass:
        problems.append(f"{len(glass)} break-glass releases (limit {max_break_glass}): break-glass is becoming the normal path")
    unsent = len(door.outbox)
    if unsent:
        problems.append(f"{unsent} front-door entries never reached the watchdog")
    return problems + link.gate.alarms + wd.alarms


def build():
    gate, wd = Gate({}), Watchdog()
    link = LinkSentinel(gate, wd)
    door = FrontDoor(hx(wd.key.root))
    gate.senders["FRONT-DOOR"] = hx(door.key.root)
    return gate, wd, door, link


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    gate, wd, door, link = build()
    up, down = link.carry, (lambda frame, now: None)
    print("1. Normal lookup:", door.lookup(100, up, "deputy-a", "7ABC123", "26-0412", "seen US 67, 09:14"))
    print("2. Watchdog link cut:", door.lookup(200, down, "deputy-a", "ARK1001", "26-0412", "..."))
    print("3. Link cut during an Amber alert, break-glass:",
          door.lookup(300, down, "sheriff", "AMBER01", "26-0420", "...", break_glass=True))
    print("4. Link restored, next lookup:", door.lookup(400, up, "deputy-a", "ARK1002", "26-0412", "..."))
    print(f"\nfront-door journal {len(door.journal)} entries; watchdog chain {len(wd.chain)}; "
          f"queued {len(door.outbox)}; gate dropped {len(gate.dropped)}")
    print("Witness check:")
    for p in witness_check(door, wd, link, 500) or ["all receipts accounted for"]:
        print("   ", p)
