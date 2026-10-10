# civic-lightlog

> ## ⚠ IMMATURE: an early design and a teaching prototype
> Nothing here is reviewed, audited, or fit to deploy. The signature scheme is a teaching-size
> stand-in for real standards. The legal and policy pieces are sketches. Read it, argue with it,
> don't install it on a pole.

**City- and county-owned plate cameras, protected by light instead of secrecy.**

Commercial license-plate camera networks keep searchable histories of everyone's movements on a
vendor's servers, shared across agencies in ways residents can't see. This project designs the
local alternative, built on one assumption:

> **Assume nothing stays secret.** Encryption can be broken, keys leak, insiders read everything.
> So keep almost nothing, and make every access to what's kept **known, seen, tracked and audited**.

Two rules carry the whole design:

1. **Keep as little as the law and the job need.** Arkansas caps government plate-read retention at
   150 days (A.C.A. § 12-12-1801 et seq., as amended by Act 668 of 2025). Retention here is a
   published setting, enforced by a deletion job that logs every run. The strictest setting,
   "hits only", has the edge drop every non-match within seconds and keep only a count.
2. **Every camera is an employee on a POS register.** It clocks in, rings up every event with a
   receipt number, signs it with its own PIN, chains it to the last one, and prints a Z-report that
   independent witnesses keep. An officer's lookup is a manager override: it needs the officer's own
   PIN and lands on the public journal.

**Trust never depends on encryption.** The audit trail uses only hashes (SHA-256, which still holds
up against quantum computers) and hash-based signatures. Encryption is still used wherever the law
requires it: CJIS requires FIPS-validated encryption in transit and at rest once criminal-justice
data is involved. It just isn't what makes the system trustworthy.

## Start here
| read | why |
|---|---|
| [DESIGN.md](DESIGN.md) | the POS model, the record format, how tampering shows on the digital side and the UI side, the threat model and its limits |
| [lightlog.py](lightlog.py) | the working prototype: one camera's shift, then seven ways to cheat it, and what the auditor sees |
| [GRAVEYARD.md](GRAVEYARD.md) | ideas that don't work, and why |

```bash
python lightlog.py     # standard library only; runs in about a second
```

What the run shows (abridged):

```
1. Honest shift                       GREEN  every receipt verifies, chain unbroken, witnesses agree
2. Officer's stated reason edited     RED    payload no longer matches its receipt
3. Query receipt deleted              RED    receipt numbers jump 17 -> 19; chain link broken
4. Hit data erased with no purge      RED    hit data erased with no PURGE receipt
5. Camera unplugged, gap cleaned up   AMBER  silent for 420 s; RED missing receipts
6. Lookup without a city badge        RED    query without a valid officer PIN
7. Key stolen, whole day re-signed    RED    the Z-report each witness holds is not in the journal
```

## License
Code under [MIT](LICENSE). Documents under CC BY 4.0. Copyright © 2026 Brayden Sanders.
