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

## 3b. The watchdog (`watchdog.py`, `rules.json`)
Every lookup goes through **one front door**, which rings it up with three signatures: the front
door's, **the user's key**, and **the device's key** (held in the terminal's secure chip). That makes
"the sheriff's key only works on the sheriff's devices" checkable. A copied password used on another
machine can't produce that machine's signature under his name, which closes the documented DEA case.

**Rules are data.** Each rule in `rules.json` names a type (a small checker function), its
parameters, a severity, and **the real failure it exists to catch**. New rules of an existing type
need no code. A rule type with no checker fails loudly; it's never silently skipped.

| rule type | catches |
|---|---|
| key_on_own_devices | a user's key used on a device not registered to them |
| case_must_be_open | lookups under case numbers that aren't open cases |
| reason_quality | "idk", "test", one-word reasons |
| off_hours | curiosity searches at 2 a.m. |
| distinct_plates_per_day / plates_per_case | bulk searching; one case number as a skeleton key |
| protected_plates | lookups of shelter staff, judges, officers' families: straight to the auditor |
| sharing_allowlist | results sent to anyone not on the council-approved list |
| impossible_travel | the same key on two devices within minutes (a copied key) |
| review_overdue | **watching the watchers:** no signed auditor review within 7 days is a violation |
| revoked_key | keys still working after someone leaves |

**Eyes on (R12–R14).** The phone or terminal camera is another employee. Before every lookup, the
device's secure chip matches the user's eyes and checks that they're live (not a photo, screen or
replay). It then signs a `PRESENCE` receipt with the device key and the user key that the match
unlocked. The log knows **whose eyes** were on the data, and whether **anyone else's** were in view.

- **The eyes unlock the key; they never enter the log.** A biometric is the one secret that can never
  be changed. A leaked iris template compromises a person for life, and hashing doesn't help: scans
  are noisy, so a plain hash never matches twice, and the workarounds leak. Same model as Face ID and
  passkeys: match on the chip, publish only the signed result.
- **Still not impenetrable.** A coerced user, a compromised chip, or a good enough fake can cross it.
  Each rule raises the cost and makes crossing *visible*. None of them makes crossing impossible.
- **Law and labour.** Arkansas counts biometric data as personal information under its breach law.
  Requiring it of county staff needs a written policy, and it's another reason never to store templates.

**Every red gets an answer (R15).** A flag nobody answers is just a quieter version of an unread
log. So every RED needs a signed `RESPONSE` receipt within 48 hours (what was found and what was done)
from an authorized responder: the auditor or a supervisor, **never the person the flag is about**.
A late answer is flagged as late. A missing one escalates to the clerk and the council. The responses
are public receipts too, so the public can see whether flags are actually acted on.

**The rules guard themselves.** The rule set's hash is published as a `RULESET` receipt. Adding a rule
needs the auditor's signature. **Anything else (removing a rule, loosening a limit) counts as weakening
and needs the auditor and the county clerk.** The watchdog works out the change type itself, so a
weakening labelled "add" is flagged. A `rules.json` edited on the server but never published is
flagged too. New rules apply to the whole history, so a rule written today catches last month's abuse.

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
- **The boundary always gives eventually.** Every link between the digital record and the physical
  world (a camera, a chip, a face, a person under pressure) can be crossed with enough effort. The
  design doesn't promise it can't be. It promises that crossing **costs more, shows up in the record
  sooner, and has a named consequence**, and that keys can be rotated and rules added after each lesson.
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
