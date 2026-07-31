# ESP AdBlock (ESP32-S3 / C3 DNS Sinkhole)

A **Pi-hole-style DNS ad-blocker** that runs on a **$2 ESP32-C3** (no PSRAM required) — OR a **$5 ESP32-S3** (with PSRAM) for enterprise-grade RAM caching!

> 📰 Featured on [Tom's Hardware](https://www.tomshardware.com/networking/clever-hacker-fits-537-000-domains-in-a-tiny-usd5-esp32-ad-blocking-dongle-firmware-uses-only-around-50kb-of-ram-and-can-answer-blocked-lookups-in-10-milliseconds), [XDA Developers](https://www.xda-developers.com/this-tiny-esp32-powered-gadget-blocks-537000-domains-only-uses-50kb-of-ram/), and [Korben](https://korben.info/en/half-million-ad-blocking-domains-50kb-ram-esp32.html).

The original trick everyone misses: you don't need to keep the blocklist in RAM. Store the domains as **sorted 40-bit hashes in flash** and binary-search them. 140,000+ domains fit in ~0.7 MB of flash and are matched in ~10 ms, using **~50 KB of RAM**.

## 🚀 NEW: The ESP32-S3 PSRAM "Turbo Mode"
If you upgrade to an **ESP32-S3 (e.g. N16R8: 16MB Flash, 8MB PSRAM)**, this firmware becomes an absolute monster:
- **Zero-Latency RAM Disk**: At boot, the system detects PSRAM and gracefully swallows the entire blocklist into lightning-fast memory (using safe chunked reads to feed the watchdog). DNS lookup times drop from ~30ms to **<0.1ms (500x faster)**.
- **2.6 Million Domain Capacity**: The included 16MB partition scheme (`partitions_s3.csv`) allocates 12.6MB to LittleFS. This fits **>2,600,000 domains** while still keeping Dual-OTA firmware update slots!
- **Smart Fallback**: The exact same code runs on both C3 and S3. If no PSRAM is found, it elegantly falls back to direct Flash reads.

```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ binary-search (in PSRAM if S3, or Flash if C3)
              ├─ hit  ──▶ answer 0.0.0.0   (sinkholed)
              └─ miss ──▶ forward to upstream resolver, relay the reply
```

## Why this is interesting

| | C3 (Hash-in-Flash) | S3 (PSRAM Turbo Cache) |
|---|---|---|
| Hardware | ESP32-C3 (~$2) | ESP32-S3 N16R8 (~$5) |
| Max Domains | ~250k (with OTA) | **~2.6 Million** (with OTA) |
| Lookup Speed | ~10-30 ms | **< 0.1 ms** (Instant) |
| Wear & Tear | Flash reads every query | Zero flash reads during query |

**Why 40 bits?** It's the sweet spot for this flash budget. Collisions follow the birthday bound — at 141k domains you get ~0, at 537k about 1.

## Hardware

- Any **ESP32-C3** or **ESP32-S3** board.
- Power it from a **stable USB source** (a phone charger or your router's USB port).
  Cheap/loose USB-C→A adapters can brown out the radio during WiFi transmit.
- A **USB-A → USB-C dongle** lets it plug straight into the spare USB port on the
  back of most routers — no power supply, no extra box.

### Enclosure

A printable case for the C3 SuperMini: [`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl)

## Build & flash (PlatformIO)

One USB flash to get going — after that, **firmware and blocklist both update over WiFi** (see below).

> 💡 **NEW**: The `tools/build_blocklist.py` script now natively supports **AdBlock Plus syntax** (`||domain.com^`). Feel free to feed it OISD Big, StevenBlack, Hagezi, etc!

```bash
# 1. (optional) set WiFi creds at compile time — or skip this and use the
#    on-device setup portal (below). secrets.h is gitignored, stays local.
cp src/secrets.example.h src/secrets.h

# 2. build the blocklist hash table (can combine multiple lists!)
#    default = StevenBlack base + Hagezi Light (~140k domains)
python3 tools/build_blocklist.py data/blocklist.bin

# 3. flash firmware + the blocklist filesystem (the one and only USB flash)
#    Note: Default is S3. For C3, use `-e c3` instead of `-e s3`.
pio run -e s3 -t upload
pio run -e s3 -t uploadfs

# 4. watch it boot, note the IP / open the dashboard
pio device monitor          # -> http://espadblock.local
```

### WiFi setup (no re-flash needed)

If it can't connect (or you never set `secrets.h`), it starts an open access point
**`ESP-AdBlock-XXXX`** with a captive portal — join it from a phone, pick your network,
type the password, done. To move it to a new network later: open `http://espadblock.local/forgetwifi`,
or hold the **BOOT** button while powering on, and the setup portal comes back.

## Over-the-air updates (no more USB)

The dashboard at **http://espadblock.local** does it all:

- **Blocklist** — drop a freshly built `blocklist.bin` into *Blocklist → Upload*, or set a
  URL under *Remote auto-update* and the device pulls a prebuilt `blocklist.bin`
  on a schedule (e.g. a GitHub release asset — update it once, every device fetches it).
- **Firmware** — upload `.pio/build/[env]/firmware.bin` under *Firmware → OTA update*; the
  device verifies it and reboots into the new image.

## Use it

Point a device's DNS at the device's IP, or add it as a **secondary resolver** behind
your main DNS. Test:

```bash
dig @<device-ip> doubleclick.net   # -> 0.0.0.0  (blocked)
dig @<device-ip> github.com        # -> real IP  (forwarded)
```

## Gotchas (learned the hard way)

- **ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles
  DTR/RTS, which **resets the board** and blocks serial. Fix:
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- DNS clients add an **EDNS OPT** record; a blocked reply must contain only the
  question + answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0) or it's malformed.

## Credits

This project is an upgraded fork of the excellent [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock). We added ESP32-S3 PSRAM caching, ABP filter syntax support, and automated GitHub Actions builds.

The original work was inspired by [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — the "answer 0.0.0.0 for blocklisted domains" idea, with an independent from-scratch implementation by M-Abozaid focused on the hash-in-flash optimization.

## License

MIT — see [LICENSE](LICENSE).
