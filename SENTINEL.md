# SENTINEL: a locally built watchdog chip on every device
### v0.1 (immature) · a spec, not a build

Every piece of hardware in the system (camera, edge box, front-door server, deputy terminal, witness
box) carries a **sentinel**: a small board with its own power, its own key and its own way out. The
device it sits on can't control it. Its job is to watch that device and report, one way, all the time.

> The device is the employee. The sentinel is the badge clipped to it: it says who the device is,
> whether it's been opened, moved, unplugged or reprogrammed, and it keeps saying so even if the
> device stops cooperating.

---

## 1. What "locally made" can honestly mean
- **Not a chip fabricated here.** A silicon fab costs billions of dollars.
- **A board assembled, flashed, sealed and registered here,** from an open design anyone can inspect:
  commodity parts with published datasheets, open firmware built reproducibly (anyone can rebuild it and
  get the same hash), and keys generated on the board at a public local key ceremony.
- That's the sovereignty that matters: **the county knows exactly what's inside and who put it there**,
  and no vendor holds a key.

## 2. The board (rough parts, ~$15–40 each [UNSOURCED estimate])
| part | example | job |
|---|---|---|
| microcontroller | Raspberry Pi RP2350 (secure boot, one-time-programmable memory, glitch detectors), or an STM32 with TrustZone | runs the sentinel firmware; signs reports |
| key store | the RP2350's OTP memory plus secure boot, and/or a Microchip ATECC608 secure element (~$1) | the key is generated inside and never leaves |
| signatures | hash-based **LMS** (NIST SP 800-208) in software on the microcontroller [TO-VERIFY: speed and state handling] | survives quantum attack; the ATECC608's elliptic curves won't |
| its own way out | a **LoRa radio** (915 MHz, ~$10–20) to a county gateway, independent of the device's network | the host can't silence it by cutting its own network |
| one-way link to the host | **transmit-only** wire through an optocoupler: the sentinel can read the host's state, the host can never send it commands | the host can't reconfigure or gag it |
| tamper senses | case switch, light sensor inside the enclosure, accelerometer (moved, or the pole was hit), power monitor | opening, moving, unplugging all become receipts |
| reserve power | supercapacitor or small cell | it reports its own power loss and keeps reporting for a while |
| host measurement | reads a hash of the host's firmware at boot (over SPI or the boot chain) | reprogramming the device shows up in the next report |

## 3. What it reports (signed receipts on its own chain)
| receipt | when |
|---|---|
| `SENTINEL_HELLO` | power-up: its badge, the host's firmware hash, the sealed-enclosure serial |
| `HEARTBEAT` | every minute: host alive, link up, counters. **Silence is the alarm** |
| `CASE_OPEN` / `LIGHT_IN_CASE` | the enclosure was opened |
| `MOVED` | an acceleration or tilt beyond the mounting baseline |
| `POWER_LOST` / `POWER_BACK` | with the reserve-power timestamp |
| `HOST_CHANGED` | the host's firmware hash differs from the registered one |
| `HOST_SILENT` | the host stopped producing its own receipts while the sentinel is still alive |

These feed the watchdog (`watchdog.py`) as new rule types: a camera whose sentinel says "case open" while
the camera's own journal looks normal is the clearest red flag there is.

## 4. Local key ceremony (each board)
1. Assemble and flash the board in public, at the clerk's office or library, from a tagged firmware
   release whose hash is published.
2. The board generates its key inside and prints its public key; it is never exported.
3. Seal the enclosure with a numbered tamper-evident seal; photograph the seal; publish the photo's hash.
4. Record the badge, the seal number and the device it guards in the public inventory, and as a receipt.
5. Mount it. Its first `SENTINEL_HELLO` must match the inventory.

## 5. Who watches the sentinel?
- **The others.** Every sentinel's heartbeat is visible to the gateway and the witnesses; one going
  quiet is a flag.
- **Two independent reports per device.** The device's own journal and its sentinel's. An attacker has
  to fool both, and keep their stories consistent.
- **Physical audits.** Someone checks seal numbers against the photos on a schedule; each check is a
  receipt.
- **Mystery shoppers.** Test plates and test tamper events; the system has to report them.

## 6. Honest limits
- **A host can lie when measured,** reporting clean firmware while running something else. Measuring
  at boot through the boot chain, not by asking the host, narrows this. It doesn't close it.
- **Replace both.** An attacker who swaps the device and its sentinel together shows up as a new badge,
  so the inventory has to be checked, not trusted.
- **LoRa is slow and shared.** It's fine for minute heartbeats and short alarms, and it's licence-free
  in the US under FCC Part 15. It can't carry video, and it can be jammed (a jam is itself a silence).
- **It's more hardware to maintain.** The handoff's year-3 risk applies twice. Build sentinels only as
  fast as someone local can be trained to make, seal and repair them.
- **A determined physical attacker eventually wins.** The goal is that they can't do it unseen.

## 7. Prior art to read before building
- OpenTitan (open-source silicon root of trust; lowRISC, Google and partners)
- Tillitis TKey (open-hardware USB security key, FPGA-based, measured boot, unique per device)
- Raspberry Pi RP2350 security documentation (secure boot, OTP, glitch detection)
- NIST SP 800-193 (platform firmware resiliency) and SP 800-208 (LMS/XMSS hash-based signatures)
