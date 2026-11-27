
#!/usr/bin/env python3
"""
Build ESP32-AdBlock binary blocklist.

Firmware compatibility:
- FNV-1a 40-bit
- 5 bytes per hash
- Little-endian
- Sorted ascending
- Compatible with src/main.cpp

Sources:
- HaGeZi Multi Pro
- HaGeZi TIF Medium
"""

import os
import re
import sys
import math
import ipaddress
import urllib.request
from pathlib import Path

HASH_BYTES = 5
MASK = (1 << (HASH_BYTES * 8)) - 1

FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3
U64 = (1 << 64) - 1

DEFAULT_SOURCES = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
]

MIN_DOMAINS_PER_SOURCE = 1000

LABEL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


def fnv(domain: str) -> int:
    h = FNV_OFFSET

    for c in domain.encode("ascii"):
        h = ((h ^ c) * FNV_PRIME) & U64

    return h & MASK


def normalize_domain(domain: str):
    domain = domain.strip().lower()

    if domain.startswith("www."):
        domain = domain[4:]

    domain = domain.rstrip(".")

    if not domain or len(domain) > 253:
        return None

    if domain.startswith(".") or ".." in domain:
        return None

    labels = domain.split(".")

    if len(labels) < 2:
        return None

    if not all(LABEL_RE.fullmatch(label) for label in labels):
        return None

    return domain


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_line(line: str):
    line = line.strip()

    if not line:
        return []

    # Ignore comments and headers.
    if line.startswith(("!", "#", "[")):
        return []

    # Exception rules must never become block rules.
    if line.startswith("@@"):
        return []

    # Adblock domain rule: ||example.com^
    if line.startswith("||"):
        rule = line[2:]

        # Keep only the domain portion.
        domain = re.split(r"[\^/$*|]", rule, maxsplit=1)[0]

        normalized = normalize_domain(domain)
        return [normalized] if normalized else []

    parts = line.split()

    # Hosts format: 0.0.0.0 example.com
    if len(parts) >= 2 and is_ip(parts[0]):
        result = []

        for item in parts[1:]:
            normalized = normalize_domain(item)
            if normalized:
                result.append(normalized)

        return result

    # Plain domain format: example.com
    if len(parts) == 1:
        normalized = normalize_domain(parts[0])
        return [normalized] if normalized else []

    return []


def read_source(source: str) -> str:
    if os.path.isfile(source):
        return Path(source).read_text(
            encoding="utf-8",
            errors="ignore",
        )

    print(f"Downloading: {source}")

    request = urllib.request.Request(
        source,
        headers={"User-Agent": "ESP32-AdBlock-Builder/1.0"},
    )

    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read().decode("utf-8", errors="ignore")


def build(out_file: str, sources: list[str]):
    domains = set()

    for source in sources:
        print(f"\nProcessing: {source}")

        try:
            data = read_source(source)
        except Exception as exc:
            raise RuntimeError(
                f"Cannot download/read source: {source}\n{exc}"
            ) from exc

        source_domains = set()

        for line in data.splitlines():
            for domain in parse_line(line):
                source_domains.add(domain)

        print(f"  Domains found: {len(source_domains):,}")

        if len(source_domains) < MIN_DOMAINS_PER_SOURCE:
            raise RuntimeError(
                f"Source returned too few valid domains: {source}"
            )

        domains.update(source_domains)

    if not domains:
        raise RuntimeError("No valid domains found.")

    print("\nCalculating FNV-1a hashes...")

    hashes = [fnv(domain) for domain in domains]

    unique_hashes = sorted(set(hashes))
    collisions = len(hashes) - len(unique_hashes)

    output = Path(out_file)
    temp_output = output.with_suffix(output.suffix + ".tmp")

    try:
        with temp_output.open("wb") as file:
            for value in unique_hashes:
                file.write(value.to_bytes(HASH_BYTES, "little"))

        # Replace the old output only after a successful build.
        os.replace(temp_output, output)

    finally:
        if temp_output.exists():
            temp_output.unlink()

    count = len(unique_hashes)
    size = count * HASH_BYTES

    print("\n========== BUILD RESULT ==========")
    print(f"Unique source domains : {len(domains):,}")
    print(f"Hash entries          : {count:,}")
    print(f"Hash collisions       : {collisions:,}")
    print(f"Hash size             : {HASH_BYTES * 8}-bit")
    print(f"Binary size           : {size:,} bytes")
    print(f"Binary size           : {size / 1024 / 1024:.2f} MB")
    print(f"Binary search         : ~{math.ceil(math.log2(max(count, 2)))} steps")
    print(f"Output                : {output}")
    print("==================================")


def main():
    args = sys.argv[1:]

    out_file = args[0] if args else "blocklist.bin"
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    try:
        build(out_file, sources)
    except Exception as exc:
        print(f"\nBUILD FAILED: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
