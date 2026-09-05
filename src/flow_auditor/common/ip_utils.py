"""IP and CIDR utilities for firewall rules and flow auditing."""

from __future__ import annotations

import math
import re

IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_ip(s: str | None) -> bool:
    """Return True if s is a valid IPv4 string format."""
    if not s:
        return False
    parts = s.strip().split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if n < 0 or n > 255:
            return False
    return True


def ip_to_int(ip: str) -> int:
    """Parse an IPv4 address string into a 32-bit unsigned integer."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid IP address: '{ip}'")
    acc = 0
    for octet in parts:
        try:
            n = int(octet)
        except ValueError as err:
            raise ValueError(f"Invalid IP octet in: '{ip}'") from err
        if n < 0 or n > 255:
            raise ValueError(f"Invalid IP octet in: '{ip}'")
        acc = (acc * 256 + n) & 0xFFFFFFFF
    return acc


def int_to_ip(i: int) -> str:
    """Convert a 32-bit unsigned integer to an IPv4 dotted string."""
    return f"{(i >> 24) & 0xFF}.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"


def mask_to_cidr(mask: str) -> int | None:
    """Convert a subnet mask (or wildcard mask) to a CIDR prefix length."""
    parts = mask.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        int_parts = [int(p) for p in parts]
    except ValueError:
        return None
    if any(p < 0 or p > 255 for p in int_parts):
        return None

    n = (
        (int_parts[0] << 24) | (int_parts[1] << 16) | (int_parts[2] << 8) | int_parts[3]
    ) & 0xFFFFFFFF

    if n == 0:
        return 0

    # If it's a standard subnet mask (leading 1s)
    if (n >> 31) & 1:
        c = 0
        for i in range(31, -1, -1):
            if (n >> i) & 1:
                c += 1
            else:
                break
        return c

    # Wildcard mask check (leading 0s followed by 1s)
    zeros = 0
    for i in range(32):
        if not ((n >> i) & 1):
            zeros += 1
    return zeros


def mask_for(prefix: int) -> int:
    """Return 32-bit subnet mask for given CIDR prefix."""
    if prefix <= 0:
        return 0
    if prefix >= 32:
        return 0xFFFFFFFF
    return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF


def parse_cidr(s: str) -> tuple[int, int]:
    """Parse a CIDR or bare IP into (base_ip_int, prefix_len)."""
    s = s.strip()
    if "/" in s:
        ip_str, prefix_str = s.split("/", 1)
        prefix = int(prefix_str)
        if prefix < 0 or prefix > 32:
            raise ValueError(f"Invalid prefix length in CIDR: '{s}'")
        return ip_to_int(ip_str), prefix
    return ip_to_int(s), 32


def cidr_range(base_int: int, prefix: int) -> tuple[int, int]:
    """Return (start_int, end_int) for a given base and prefix."""
    mask = mask_for(prefix)
    start = base_int & mask
    end = (start + (1 << (32 - prefix)) - 1) & 0xFFFFFFFF
    return start, end


def ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if ip falls within the network described by cidr."""
    normalized = cidr.strip().lower()
    if normalized == "any" or normalized == "0.0.0.0/0":
        return True
    base_int, prefix = parse_cidr(normalized)
    ip_int = ip_to_int(ip)
    mask = mask_for(prefix)
    return (ip_int & mask) == (base_int & mask)


def range_to_cidrs(start: int, end: int) -> list[str]:
    """Convert an inclusive IP int range [start, end] into a minimal list of CIDRs."""
    res = []
    cur = start & 0xFFFFFFFF
    end = end & 0xFFFFFFFF
    while cur <= end:
        max_size_align = cur & -cur
        if max_size_align != 0:
            max_len_align = 32 - int(math.floor(math.log2(max_size_align)))
        else:
            max_len_align = 0
        remaining = end - cur + 1
        max_len_remain = 32 - int(math.floor(math.log2(remaining)))
        prefix = max(max_len_align, max_len_remain)
        res.append(f"{int_to_ip(cur)}/{prefix}")
        cur = (cur + (1 << (32 - prefix))) & 0xFFFFFFFF
    return res


def aggregate_cidrs(cidr_strings: list[str], prefix_len: int) -> list[str]:
    """Aggregate CIDRs into blocks of size prefix_len and merge contiguous runs."""
    if not cidr_strings:
        return []
    block_size = 1 << (32 - prefix_len)
    masked = set()
    for s in cidr_strings:
        base, prefix = parse_cidr(s)
        start, end = cidr_range(base, prefix)
        start_block = start // block_size
        end_block = end // block_size
        for b in range(start_block, end_block + 1):
            masked.add((b * block_size) & 0xFFFFFFFF)

    arr = sorted(masked)
    if not arr:
        return []

    runs = []
    run_start = arr[0]
    run_prev = arr[0]
    for v in arr[1:]:
        if v == (run_prev + block_size) & 0xFFFFFFFF:
            run_prev = v
            continue
        runs.append((run_start, (run_prev + block_size - 1) & 0xFFFFFFFF))
        run_start = v
        run_prev = v
    runs.append((run_start, (run_prev + block_size - 1) & 0xFFFFFFFF))

    result = []
    for r_start, r_end in runs:
        result.extend(range_to_cidrs(r_start, r_end))
    return result


def enclosing_supernet(cidr_list: list[str]) -> str:
    """Find the smallest enclosing supernet containing all CIDRs in cidr_list."""
    if not cidr_list:
        return "0.0.0.0/0"
    min_ip = 0xFFFFFFFF
    max_ip = 0
    for s in cidr_list:
        base, prefix = parse_cidr(s)
        start, end = cidr_range(base, prefix)
        if start < min_ip:
            min_ip = start
        if end > max_ip:
            max_ip = end

    for prefix in range(32, -1, -1):
        mask = mask_for(prefix)
        if (min_ip & mask) == (max_ip & mask):
            net = min_ip & mask
            return f"{int_to_ip(net)}/{prefix}"
    return "0.0.0.0/0"


def count_addresses(cidr_list: list[str]) -> int:
    """Return total number of addresses represented by cidr_list."""
    total = 0
    for s in cidr_list:
        _, prefix = parse_cidr(s)
        total += 1 << (32 - prefix)
    return total
