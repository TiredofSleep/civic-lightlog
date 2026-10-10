# DEPLOYMENT: a sentinel on every camera, updated only by hand
### v0.1 (immature) · goes with `SENTINEL.md`

**The rule:** no device in the system accepts code over a network. Firmware for sentinels, edge boxes
and cameras changes only when a person is physically present, a witness signs, and the change is a
receipt on the public journal.

**The trick that makes it workable: swap, don't patch.** Nobody updates anything on a pole. Crews swap
a sealed, pre-registered module for another. Updates happen at **one public bench** (the clerk's office
or the library), in front of a witness. Updated units go back out in the next swap round.

---

## 1. What sits at each camera site
Off-the-shelf plate cameras are black boxes: nobody outside the vendor can read or vouch for their
firmware. So the sentinel doesn't live inside the camera. It lives in a **locked box at the base of the
pole**, together with the edge computer, and watches everything that goes up to the camera.

```
            [ plate camera ]   <- no internet, no route out except one cable down the pole
                  |  PoE cable (power + video)
  ┌───────────────┴─────────────── locked pole box (tamper seal, light + door switch) ─┐
  │  [ sentinel ] --watches--> PoE power draw · the camera cable · box door · box light │
  │       ^ transmit-only (optocoupler)                                                 │
  │  [ edge computer: plate matching + journal ] --one-way out (diode)--> uplink/LTE   │
  │  [ sentinel LoRa radio ] -----------------------------------------> county gateway  │
  └─────────────────────────────────────────────────────────────────────────────────────┘
```

- **The camera is fenced in.** It talks only to the edge computer over one cable, and has no other
  network. Its configuration is set once at the bench and recorded as a hash.
- **The sentinel watches the camera from outside.** It watches PoE power draw (a camera that reboots,
  dies or changes behaviour has a different power signature), cable continuity, and the edge
  computer's frame and plate counters, which it receives over the transmit-only line.
- **The edge computer sends out, never takes in.** Receipts leave through a one-way link. Nothing
  reaches back in.
- **The box is reachable from the ground,** so a swap doesn't need a bucket truck. Only camera
  replacement does.

## 2. The one exception: data, not code
Hotlists change daily, so driving them around by hand isn't realistic. **Code only moves by hand. Data
moves on a narrow, signed, one-way feed:**
- If matching runs on the ACIC side (the handoff's preferred design), there's no hotlist on the pole at all.
- If a local hotlist is needed: one inbound one-way link carrying **only signed hotlist files**. The edge
  computer accepts nothing else, and logs each file's hash as a receipt.
- **Configuration is code.** Retention, rules and camera settings change only at the bench.

## 3. The public bench
One table, used for every update. Each session is a run of receipts:

1. **Release.** A tagged firmware release is built reproducibly. Its hash is published **at least 14
   days before** any unit gets it (the notice period), and anyone can rebuild it and compare.
2. **Two people.** A technician and a witness (from the auditor board or the clerk's office), each with
   their own key and eye check.
3. **Open.** The unit's seal number is checked against its last photo. Opening it records `CASE_OPEN`.
4. **Flash.** A cable to the debug port, plus a hardware "update token" kept in the clerk's safe. The
   sentinel only boots firmware signed with the county release key (secure boot), and refuses older
   versions (anti-rollback counter in one-time memory [TO-VERIFY on RP2350]).
5. **Prove.** The unit reports its new firmware hash in a `SENTINEL_HELLO`, which must match the published one.
6. **Seal.** A new numbered seal, photographed, with the photo's hash published.
7. **Sign out.** The technician and witness co-sign an `UPDATE` receipt: old hash, new hash, old and new
   seal numbers.

The **release key** never sits on a networked machine. Ideally it's split, so the release needs two of
three holders (e.g. auditor board, clerk, the county IT owner).

## 4. A field swap
| step | receipt |
|---|---|
| crew arrives; the pole box door opens | `CASE_OPEN` from the outgoing sentinel |
| outgoing sentinel unplugged; its reserve power reports it | `POWER_LOST`, then its final `RETIRED` once back at the bench |
| incoming sentinel (already updated, sealed and registered at the bench) plugged in | `SENTINEL_HELLO` with its badge and seal number, matched against the inventory |
| box closed and resealed; seal photographed | `CASE_CLOSED` + a crew receipt co-signed by both crew members |
| watchdog checks the gap was short, the badge is in inventory, both crew signed | flags anything else |

A swap takes a few minutes of the camera being unwatched. That gap is expected, scheduled and published
ahead of time (date, site, crew), so an **unscheduled** gap stands out.

## 5. Schedule
- **Routine swap round:** quarterly. Every site gets an updated sentinel and a seal check.
- **Urgent fixes:** within 72 hours, from pre-flashed spares.
- **Spares:** at least 1 sealed spare per 5 sites, or 2 minimum, kept in the clerk's safe with seal
  photos on file.
- **The slow-patch trade-off:** physical-only means slower fixes. That's acceptable because nothing on
  the pole accepts incoming connections, so most remote attacks have nothing to aim at. Write that
  trade-off into the ordinance so it's a decision, not an accident.

## 6. Rollout
| phase | sites | proves | rough cost [UNSOURCED estimates] |
|---|---|---|---|
| **0. Bench** | 1 sentinel on the Arkadelphia lot camera | heartbeats over LoRa; door, light and power events show on the journal; one swap done start to finish | ~$50–150 of parts + a LoRa gateway (~$100–250) |
| **1. Pilot** | 2–3 county sites | the full bench ceremony, a quarterly swap round, a planted tamper test caught | ~$300–800 in sentinels and spares, plus pole boxes |
| **2. County** | every site | swap rounds on schedule with trained local staff | per site: sentinel ~$15–40, pole box, seals; staff time is the real cost |

**Gate before phase 2:** a named, trained local person besides the founder can run the bench and a swap
round alone. (The handoff's year-3 maintenance risk.)

## 7. New watchdog rules this needs
- **unscheduled_gap:** a sentinel or camera silence outside a published swap window.
- **badge_not_in_inventory:** a `SENTINEL_HELLO` from a badge the clerk didn't register.
- **unpublished_firmware:** a firmware hash that wasn't published 14 days earlier.
- **solo_update:** an `UPDATE` or swap receipt missing the witness's or second crew member's signature.
- **seal_mismatch:** a seal number that doesn't match the last photographed one.
- **hotlist_unsigned:** an inbound hotlist file without a valid signature.
