from __future__ import annotations

try:
    from scapy.layers.dhcp import BOOTP, DHCP
except Exception:
    BOOTP = None
    DHCP = None

try:
    from scapy.layers.dns import DNS
except Exception:
    DNS = None

from scapy.all import UDP


def _clean_hostname(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        text = raw.decode("ascii", errors="ignore")
    else:
        text = str(raw)
    return text.strip("\x00").strip().rstrip(".")


def extract_dhcp_hint(pkt) -> tuple[str, str] | None:
    if DHCP is None or BOOTP is None:
        return None
    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
        return None
    try:
        options = pkt[DHCP].options
    except Exception:
        return None

    hostname = ""
    requested = ""
    for opt in options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        key = opt[0]
        if key == "hostname":
            hostname = _clean_hostname(opt[1])
        elif key == "requested_addr":
            requested = str(opt[1])

    if not hostname:
        return None

    try:
        bootp = pkt[BOOTP]
        ciaddr = str(bootp.ciaddr) if bootp.ciaddr else ""
        yiaddr = str(bootp.yiaddr) if bootp.yiaddr else ""
    except Exception:
        ciaddr = ""
        yiaddr = ""

    ip = ""
    if ciaddr and ciaddr != "0.0.0.0":
        ip = ciaddr
    elif requested and requested != "0.0.0.0":
        ip = requested
    elif yiaddr and yiaddr != "0.0.0.0":
        ip = yiaddr

    if not ip:
        return None
    return (ip, hostname)


def extract_mdns_hints(pkt) -> list[tuple[str, str]]:
    if DNS is None:
        return []
    if not pkt.haslayer(DNS) or not pkt.haslayer(UDP):
        return []
    try:
        udp = pkt[UDP]
        if udp.sport != 5353 and udp.dport != 5353:
            return []
    except Exception:
        return []

    try:
        dns = pkt[DNS]
    except Exception:
        return []

    results: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    ancount = int(getattr(dns, "ancount", 0) or 0)
    rec = getattr(dns, "an", None)
    walked = 0
    while rec is not None and walked < max(ancount, 32):
        walked += 1
        rrtype = getattr(rec, "type", None)
        if rrtype == 1:
            name = _clean_hostname(getattr(rec, "rrname", b""))
            addr = str(getattr(rec, "rdata", "") or "")
            if name and addr and (addr, name) not in seen:
                seen.add((addr, name))
                results.append((addr, name))
        next_rec = getattr(rec, "payload", None)
        if next_rec is None or next_rec.__class__.__name__ == "NoPayload":
            break
        rec = next_rec

    return results


def extract_hostname_hints(pkt) -> list[tuple[str, str]]:
    hints: list[tuple[str, str]] = []
    dhcp_hint = extract_dhcp_hint(pkt)
    if dhcp_hint is not None:
        hints.append(dhcp_hint)
    hints.extend(extract_mdns_hints(pkt))
    return hints
