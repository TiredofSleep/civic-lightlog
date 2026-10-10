# DESIGN: tamper-visible cameras, built like a POS journal
### v0.1 (immature) · prototype: `lightlog.py`

## 0. The stance
- **Assume nothing stays secret.** Plan as if encryption is broken, keys get stolen, and insiders
  read everything. Today that's an overstatement: NIST's 2024 post-quantum standards exist. But
  "harvest now, decrypt later" and insider access are real now, and a design that doesn't depend
  on secrets can't be broken by losing them.
- **Light protects *who looked*, not *what was seen*.** A transparent store of every plate would be a
  public stalking tool. So light comes paired with **forgetting**: keep almost nothing, and shine
  light on every access to what's kept.
- **Don't depend on encryption, but don't skip it either.** Where CJIS applies (matching against
  NCIC/ACIC data), FIPS-validated encryption in transit and at rest is mandatory. Use it. The point is
  that the system's trustworthiness must still hold if that encryption fails.
- **Integrity survives where secrecy doesn't.** Quantum attacks break public-key encryption. Hash
  functions (SHA-256 and up) and hash-based signatures (NIST SLH-DSA, XMSS/LMS) survive. Tamper
  evidence needs only those.

---

## 1. The POS model
| POS register | camera system | in the prototype |
|---|---|---|
| employee badge | camera identity: one public key root, printed on the pole and published in the inventory | `Signer.root` |
| employee PIN | the camera's signing key, in a tamper-evident secure element | `Signer.sign` |
| clock in | `CLOCK_IN`: location, firmware hash, config/hotlist hash, a fresh nonce from the clerk (proves it wasn't pre-dated) | `Camera.clock_in` |
| receipt number | a sequence number on every record; any gap is visible | `seq` |
| journal tape | append-only, hash-chained records; each one includes the hash of the one before | `prev` |
| sale | `HIT`: a plate matched the hotlist | `Camera.hit` |
| no-sale / drawer open | `HEARTBEAT` every few minutes carrying the seen/forgotten counters, so silence itself is an event | `Camera.heartbeat` |
| manager override | `QUERY`: an officer's lookup needs **the officer's own PIN** as a co-signature, plus case number and reason | `Camera.query` |
| void | `PURGE`: retention erases a payload, but the receipt stays and the erasure is its own receipt | `Camera.purge` |
| Z-report | end of shift (in production: hourly): Merkle root of every receipt, counters, chain head, kept by independent witnesses | `Camera.z_report` |
| till count by a second person | witnesses compare their Z-reports with the journal | `audit(..., witnesses)` |
| mystery shopper | auditors drive known test plates past cameras and check the counters and hits | proposed |

### Record format
```
body = {cam, seq, t, kind, data, prev, seen, forgotten}
data = SHA-256 of the payload (payloads are stored separately, so retention can erase them)
sig  = the camera's hash-based signature over body
cosig = the officer's signature over body (QUERY only)
```
Keeping the payload apart from the chain is what lets a lawful deletion happen **without breaking the
chain**. The chain keeps the hash and a `PURGE` receipt says who erased it, when and why.

---

## 2. Tamper visible: the digital side
| attack | what shows it |
|---|---|
| edit a record | its signature fails, and the next record's `prev` no longer matches |
| edit a payload (e.g. the officer's reason) | the payload's hash no longer matches `data` |
| delete a record | a receipt-number gap and a broken chain link |
| erase hit data quietly | a `HIT` whose data is gone with no `PURGE` receipt |
| unplug, block or blind the camera | heartbeats stop: a visible silence longer than the limit |
| look something up without a badge | a `QUERY` without a valid officer co-signature |
| two versions of history (fork) | two different signed receipts with the same number |
| steal the key and rewrite the day | the Z-reports the witnesses already hold don't match the new journal |
| pre-date a fake shift | `CLOCK_IN` must include a nonce the clerk issued that day |

**The limit (from test 7):** a stolen key can rewrite anything **after the last Z-report the witnesses
received**. So publish checkpoints often (hourly), to several independent witnesses, and print one each
day.

---

## 3. Tamper visible: the UI side
A dashboard can lie too: it can show green over a broken chain. So:
1. **Verify in the viewer's own browser.** The page downloads the raw journal and runs the auditor
   itself. It never displays a "verified" flag computed by the server.
2. **A paper fingerprint.** Each day's chain head is shortened to a fingerprint like `C3C3-4A78-5599-256C`.
   It's printed on paper tape, posted at the clerk's office and the library, and run in the local
   paper. Anyone can compare the screen with the paper. Paper can't be edited remotely.
3. **Show the receipt numbers.** Gaps get a red bar, silences an amber bar, and every human lookup is a
   named line: officer, case, reason, time.
4. **The UI is in the chain too.** Each published page states its own build hash, and that hash is
   logged, so "which software is showing you this?" has a checkable answer.
5. **More than one viewer.** The library, a university or the paper runs its own copy of the open
   viewer against the same raw journal. If they disagree, someone is lying.
6. **The pole tells you too.** Each camera carries its badge root as a QR code linking to its live
   journal, and a status light whose blink follows the heartbeat.
7. **"Was my plate looked up?"** Answered through the clerk, not a public search box. A search box would
   itself leak who is interested in which plate.

---

## 4. Storage
- **On the camera:** append-only flash, the journal plus payloads for hits only (kilobytes a day; the
  full plate stream is never stored).
- **City log server:** a mirror that only appends.
- **Witnesses:** clerk, county, library, the local paper, and a citizen oversight board each keep the
  Z-reports, and ideally the full journal.
- **Retention:** a published setting, from "hits only" (the edge drops non-matches) up to the Arkansas
  government cap of 150 days (60 for private lots), longer only while tied to an open case. In the
  prototype, hit payloads are erased after 30 days. Receipts and purge
  receipts are kept forever.

---

## 5. Not solved yet
- **A camera that lies from the start** (malicious firmware that skips a plate before it ever
  reaches the journal). Countered by open, reproducible firmware builds, the firmware hash in every
  `CLOCK_IN`, and mystery-shopper test plates. Not a proof.
- **All witnesses colluding.** Choose witnesses with opposing interests.
- **Signature size.** The teaching scheme makes ~37 kB per record (745 kB for this shift). Production
  would use SLH-DSA or XMSS/LMS from a vetted library, and sign hourly Merkle batches instead of every
  record.
- **Time.** Clocks drift and can be set. Combine witness nonces with a trusted time source.
- **The hotlist itself.** Who can add a plate, and how is that logged? It needs the same
  journal-and-override treatment.
- **Law.** The design needs an ordinance: a Community Control Over Police Surveillance (CCOPS)-style
  law covering approval, the use policy, retention, an annual report, and a ban on sharing outside the
  county. Without it, anything here can be quietly switched off.
