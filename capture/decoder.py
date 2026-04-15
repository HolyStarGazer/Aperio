from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether

from capture.services import format_port


def decode_packet(pkt) -> dict:
    result = {
        "timestamp": float(pkt.time),
        "src_ip": "",
        "dst_ip": "",
        "src_port": None,
        "dst_port": None,
        "src_mac": "",
        "dst_mac": "",
        "protocol": "Other",
        "info": pkt.summary(),
        "length": len(pkt),
        "_raw": pkt,
    }

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        result["src_mac"] = str(eth.src) if eth.src else ""
        result["dst_mac"] = str(eth.dst) if eth.dst else ""

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        result["protocol"] = "ARP"
        result["src_ip"] = arp.psrc
        result["dst_ip"] = arp.pdst
        op = "request" if arp.op == 1 else "reply"
        result["info"] = f"ARP {op}  who-has {arp.pdst} tell {arp.psrc}"
        return result

    if pkt.haslayer(IP):
        ip = pkt[IP]
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            result["protocol"] = "TCP"
            sport = int(tcp.sport)
            dport = int(tcp.dport)
            result["src_port"] = sport
            result["dst_port"] = dport
            result["info"] = (
                f"{format_port(sport)} → {format_port(dport)}  flags={tcp.flags}"
            )
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport = int(udp.sport)
            dport = int(udp.dport)
            result["src_port"] = sport
            result["dst_port"] = dport
            if sport == 53 or dport == 53:
                result["protocol"] = "DNS"
            else:
                result["protocol"] = "UDP"
            result["info"] = f"{format_port(sport)} → {format_port(dport)}"
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            result["protocol"] = "ICMP"
            result["info"] = f"ICMP type={icmp.type} code={icmp.code}"
        else:
            result["protocol"] = f"IP/{ip.proto}"

    return result


def packet_matches_filter(packet: dict, capture_filter: dict) -> bool:
    if not capture_filter:
        return True
    src_ip = capture_filter.get("src_ip", "")
    if src_ip and src_ip not in packet["src_ip"]:
        return False
    dst_ip = capture_filter.get("dst_ip", "")
    if dst_ip and dst_ip not in packet["dst_ip"]:
        return False
    port = capture_filter.get("port")
    if port is not None:
        if packet["src_port"] != port and packet["dst_port"] != port:
            return False
    protocol = capture_filter.get("protocol", "")
    if protocol and protocol not in packet["protocol"].upper():
        return False
    return True


def summarize_filter(capture_filter: dict) -> str:
    if not capture_filter:
        return ""
    parts = []
    if capture_filter.get("protocol"):
        parts.append(capture_filter["protocol"])
    if capture_filter.get("src_ip"):
        parts.append(f"src={capture_filter['src_ip']}")
    if capture_filter.get("dst_ip"):
        parts.append(f"dst={capture_filter['dst_ip']}")
    if capture_filter.get("port") is not None:
        parts.append(f"port={capture_filter['port']}")
    return ", ".join(parts)
