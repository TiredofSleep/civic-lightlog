#!/usr/bin/env python3
"""
lightlog.py -- a tamper-visible event log for city-owned cameras, built like a POS journal.

Every camera is an "employee": it clocks in, rings up every event with a receipt number, signs each
one with its own key (its PIN), chains it to the last, and prints a Z-report at the end of the shift
that independent witnesses keep. Officers who query are "managers": an override needs their own PIN.

No encryption anywhere. Only hashes, which survive quantum attack at SHA-256 and above, and hash-based
signatures (Lamport one-time keys under a Merkle tree: a teaching-size cousin of NIST's SLH-DSA/XMSS).

Standard library only. Run it: python lightlog.py
"""
import hashlib
import json
import os
import sys

H = lambda b: hashlib.sha256(b).digest()
hx = lambda b: b.hex()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# --------------------------------------------------------------------------------------------
# The PIN: hash-based signatures (Lamport one-time keys, many of them under one Merkle root)
# --------------------------------------------------------------------------------------------
class Signer:
    """A badge: the public identity is one Merkle root; each signature spends one leaf key."""

    def __init__(self, name, height=6, seed=None):
        self.name, self.height = name, height
        self.seed = seed or os.urandom(32)
        self.next_leaf = 0
        self.leaves = [H(b"".join(self._pub(i))) for i in range(2 ** height)]
        self.tree = [self.leaves]
        while len(self.tree[-1]) > 1:
            lvl = self.tree[-1]
            self.tree.append([H(lvl[k] + lvl[k + 1]) for k in range(0, len(lvl), 2)])
        self.root = self.tree[-1][0]

    def _secret(self, i, bit, b):
        return H(self.seed + i.to_bytes(4, "big") + bytes([bit]) + b.to_bytes(2, "big"))

    def _pub(self, i):
        return [H(self._secret(i, bit, b)) for b in range(256) for bit in (0, 1)]

    def sign(self, msg):
        i = self.next_leaf
        if i >= len(self.leaves):
            raise RuntimeError(f"{self.name}: out of one-time keys; issue a new badge")
        self.next_leaf += 1
        d = int.from_bytes(H(msg), "big")
        reveal, other = [], []
        for b in range(256):
            bit = (d >> (255 - b)) & 1
            reveal.append(hx(self._secret(i, bit, b)))
            other.append(hx(H(self._secret(i, 1 - bit, b))))
        path, k = [], i
        for lvl in self.tree[:-1]:
            path.append(hx(lvl[k ^ 1]))
            k //= 2
        return dict(leaf=i, reveal=reveal, other=other, path=path)


def verify_sig(root_hex, msg, sig):
    d = int.from_bytes(H(msg), "big")
    pub = []
    for b in range(256):
        bit = (d >> (255 - b)) & 1
        mine, theirs = H(bytes.fromhex(sig["reveal"][b])), bytes.fromhex(sig["other"][b])
        pub += [mine, theirs] if bit == 0 else [theirs, mine]
    node, k = H(b"".join(pub)), sig["leaf"]
    for sib in sig["path"]:
        sib = bytes.fromhex(sib)
        node = H(node + sib) if k % 2 == 0 else H(sib + node)
        k //= 2
    return hx(node) == root_hex


# --------------------------------------------------------------------------------------------
# The register: an append-only, hash-chained, signed journal per camera
# --------------------------------------------------------------------------------------------
HEARTBEAT_MAX_S = 300  # a camera that says nothing for 5 minutes is visibly silent


class Camera:
    def __init__(self, cam_id, location, firmware=b"lightcam-fw-1.0", config=b"hotlist-v12;retain=30d", seed=None):
        self.id, self.location = cam_id, location
        self.badge = Signer(cam_id, seed=seed)
        self.journal, self.payloads = [], {}
        self.seq, self.prev = 0, "0" * 64
        self.seen = self.forgotten = 0
        self.fw, self.cfg = hx(H(firmware)), hx(H(config))

    def ring(self, t, kind, payload=None, cosigner=None):
        """Ring up one event: receipt number, chain link, camera PIN, optional manager PIN."""
        self.seq += 1
        data_hash = None
        if payload is not None:
            blob = canon(payload)
            data_hash = hx(H(blob))
            self.payloads[data_hash] = json.loads(blob)  # a copy: later edits to the caller's dict can't touch it
        body = dict(cam=self.id, seq=self.seq, t=t, kind=kind, data=data_hash, prev=self.prev,
                    seen=self.seen, forgotten=self.forgotten)
        msg = canon(body)
        rec = dict(body=body, sig=self.badge.sign(msg))
        if cosigner is not None:
            rec["cosig"] = dict(who=cosigner.name, sig=cosigner.sign(msg))
        self.prev = hx(H(msg))
        self.journal.append(rec)
        return rec

    # --- events -------------------------------------------------------------------------
    def clock_in(self, t, witness_nonce):
        return self.ring(t, "CLOCK_IN", dict(location=self.location, firmware=self.fw, config=self.cfg,
                                             badge=hx(self.badge.root), witness_nonce=witness_nonce))

    def see_plate(self, plate, hotlist):
        """The edge forgets: a non-match is counted and dropped, never stored."""
        self.seen += 1
        if plate not in hotlist:
            self.forgotten += 1
            return None
        return plate

    def hit(self, t, plate, hotlist):
        return self.ring(t, "HIT", dict(plate=plate, reason=hotlist[plate]))

    def heartbeat(self, t):
        return self.ring(t, "HEARTBEAT")

    def query(self, t, officer, case, reason):
        return self.ring(t, "QUERY", dict(officer=officer.name, case=case, reason=reason), cosigner=officer)

    def purge(self, t, data_hash, why):
        """Retention: the payload is erased, the receipt stays, and the erasure is itself a receipt."""
        self.payloads.pop(data_hash, None)
        return self.ring(t, "PURGE", dict(target=data_hash, why=why))

    def z_report(self, t, since_seq=1):
        """End of shift: Merkle root of every receipt hash, counts, chain head -- for the witnesses."""
        hashes = [H(canon(r["body"])) for r in self.journal if r["body"]["seq"] >= since_seq]
        lvl = hashes or [H(b"")]
        while len(lvl) > 1:
            if len(lvl) % 2:
                lvl = lvl + [lvl[-1]]
            lvl = [H(lvl[k] + lvl[k + 1]) for k in range(0, len(lvl), 2)]
        kinds = {}
        for r in self.journal:
            kinds[r["body"]["kind"]] = kinds.get(r["body"]["kind"], 0) + 1
        z = dict(cam=self.id, t=t, through_seq=self.seq + 1, head=self.prev, merkle=hx(lvl[0]),
                 seen=self.seen, forgotten=self.forgotten, kinds=kinds)
        self.ring(t, "Z_REPORT", z)
        z["signed_seq"] = self.seq
        return z


def fingerprint(hex_hash):
    """What a human compares: the clerk's printed tape against the screen."""
    return "-".join(hex_hash[k:k + 4].upper() for k in range(0, 16, 4))


# --------------------------------------------------------------------------------------------
# The auditor: anyone can run this against the raw journal; it trusts nothing it can't recompute
# --------------------------------------------------------------------------------------------
def audit(journal, payloads, badges, witnesses=()):
    findings, prev, last_seq, last_t = [], "0" * 64, 0, None
    purged = set()
    by_seq = {}
    for r in journal:
        b = r["body"]
        msg = canon(b)
        tag = f"#{b['seq']} {b['kind']}"
        root = badges.get(b["cam"])
        if root is None or not verify_sig(root, msg, r["sig"]):
            findings.append(("RED", tag, "camera PIN signature does not verify: the receipt was altered or forged"))
        if b["kind"] == "QUERY":
            co = r.get("cosig")
            if not co or co["who"] not in badges or not verify_sig(badges[co["who"]], msg, co["sig"]):
                findings.append(("RED", tag, "query without a valid officer PIN"))
        if b["seq"] in by_seq and by_seq[b["seq"]] != hx(H(msg)):
            findings.append(("RED", tag, "two different receipts with the same number: a forked register"))
        by_seq[b["seq"]] = hx(H(msg))
        if b["seq"] != last_seq + 1:
            findings.append(("RED", tag, f"receipt numbers jump {last_seq} -> {b['seq']}: missing receipts"))
        if b["prev"] != prev:
            findings.append(("RED", tag, "chain link broken: something before this was changed or removed"))
        if last_t is not None and b["t"] - last_t > HEARTBEAT_MAX_S:
            findings.append(("AMBER", tag, f"silent for {b['t'] - last_t} s (max {HEARTBEAT_MAX_S}): unplugged, blocked or tampered"))
        if last_t is not None and b["t"] < last_t:
            findings.append(("RED", tag, "time runs backwards"))
        if b["kind"] == "PURGE":
            purged.add(payloads.get(b["data"], {}).get("target") if b["data"] in payloads else None)
        if b["data"] and b["data"] not in payloads and b["kind"] not in ("HIT",):
            findings.append(("RED", tag, "payload missing for a record that must keep it"))
        if b["data"] and b["data"] in payloads and hx(H(canon(payloads[b["data"]]))) != b["data"]:
            findings.append(("RED", tag, "payload edited: it no longer matches its receipt"))
        prev, last_seq, last_t = hx(H(msg)), b["seq"], b["t"]
    for r in journal:
        b = r["body"]
        if b["kind"] == "HIT" and b["data"] not in payloads and b["data"] not in purged:
            findings.append(("RED", f"#{b['seq']} HIT", "hit data erased with no PURGE receipt"))
    for w_name, z in witnesses:
        rec = next((r for r in journal if r["body"]["seq"] == z["signed_seq"]), None)
        ok = rec is not None and rec["body"]["data"] == hx(H(canon({k: v for k, v in z.items() if k != "signed_seq"})))
        if not ok:
            findings.append(("RED", f"witness {w_name}", "the Z-report this witness holds is not in the journal: history was rewritten"))
    return findings


# --------------------------------------------------------------------------------------------
# The shift: one honest day, then every way someone might try to cheat
# --------------------------------------------------------------------------------------------
def honest_day(seed=None, officer=None, with_query=True):
    cam = Camera("CAM-07", "US 67, Arkadelphia", seed=seed)
    officer = officer or Signer("Ofc. Rivera #212", height=4)
    hotlist = {"7ABC123": "stolen vehicle, report 26-0412"}
    cam.clock_in(0, witness_nonce="clerk-2026-10-10-7f3a")
    t = 0
    for minute in range(1, 61):
        t = minute * 60
        for plate in ("ARK1001", "ARK1002", "TX55K9"):
            cam.see_plate(plate, hotlist)
        if minute == 23:
            p = cam.see_plate("7ABC123", hotlist)
            cam.hit(t, p, hotlist)
        if minute % 4 == 0:
            cam.heartbeat(t)
    hit_hash = next(r["body"]["data"] for r in cam.journal if r["body"]["kind"] == "HIT")
    if with_query:
        cam.query(t + 10, officer, case="26-0412", reason="locate stolen vehicle")
    cam.purge(t + 20, hit_hash, why="retention: case closed, vehicle recovered")
    z = cam.z_report(t + 30)
    badges = {cam.id: hx(cam.badge.root), officer.name: hx(officer.root)}
    witnesses = [("County Clerk", dict(z)), ("Public Library", dict(z)), ("Local paper", dict(z))]
    return cam, officer, badges, witnesses, z


def show(title, findings):
    print(f"\n{title}")
    if not findings:
        print("   GREEN  every receipt verifies, chain unbroken, witnesses agree")
    for level, where, what in findings[:4]:
        print(f"   {level:5}  {where:22} {what}")
    if len(findings) > 4:
        print(f"   ...and {len(findings) - 4} more")


if __name__ == "__main__":
    import copy
    sys.stdout.reconfigure(encoding="utf-8")
    cam, officer, badges, witnesses, z = honest_day()
    print(f"CAM-07 shift: {z['seen']} plates seen, {z['forgotten']} forgotten at the edge, "
          f"{len(cam.journal)} receipts, kinds {z['kinds']}")
    print(f"Z-report fingerprint (printed and posted by the clerk): {fingerprint(z['head'])}")
    print(f"journal size: {len(json.dumps(cam.journal)) / 1e3:.0f} kB (hash-based signatures are big but cheap)")

    show("1. Honest shift", audit(cam.journal, cam.payloads, badges, witnesses))

    j, p = copy.deepcopy(cam.journal), copy.deepcopy(cam.payloads)
    q = next(r for r in j if r["body"]["kind"] == "QUERY")
    p[q["body"]["data"]]["reason"] = "routine check"
    show("2. Someone edits the officer's stated reason", audit(j, p, badges, witnesses))

    j = copy.deepcopy(cam.journal)
    j = [r for r in j if r["body"]["kind"] != "QUERY"]
    show("3. Someone deletes the query receipt entirely", audit(j, cam.payloads, badges, witnesses))

    j, p = copy.deepcopy(cam.journal), copy.deepcopy(cam.payloads)
    j = [r for r in j if r["body"]["kind"] != "PURGE"]
    show("4. Hit data erased quietly (no PURGE receipt), and the purge removed to hide it", audit(j, p, badges, witnesses))

    j = copy.deepcopy(cam.journal)
    j = [r for r in j if not (r["body"]["kind"] == "HEARTBEAT" and 1200 <= r["body"]["t"] <= 2400)]
    show("5. Camera unplugged for 20 minutes, then the gap 'cleaned up'", audit(j, cam.payloads, badges, witnesses))

    # 6. a query with no officer PIN: the camera can't do it alone
    cam2 = copy.deepcopy(cam)
    rogue = Signer("unknown user", height=2)
    cam2.query(3700, rogue, case="none", reason="curious")
    show("6. A lookup by someone without a city badge", audit(cam2.journal, cam2.payloads, badges, witnesses))

    # 7. rebuild the whole day from scratch with a stolen key -- the witnesses hold the real Z-report
    forged, *_ = honest_day(seed=cam.badge.seed, officer=officer, with_query=False)
    show("7. Camera key stolen; the whole day rebuilt without the query and re-signed",
         audit(forged.journal, forged.payloads, badges, witnesses))
