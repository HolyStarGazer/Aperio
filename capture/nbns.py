from __future__ import annotations

import socket
import struct


def query_nbns_hostname(ip: str, timeout: float = 1.5) -> str:
    trn_id = 0x4170
    header = struct.pack(">HHHHHH", trn_id, 0x0000, 1, 0, 0, 0)
    encoded_wildcard = bytes([0x20]) + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
    question = encoded_wildcard + struct.pack(">HH", 0x0021, 0x0001)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (ip, 137))
            data, _ = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            return ""
    finally:
        sock.close()

    return _parse_nbstat_response(data)


def _parse_nbstat_response(data: bytes) -> str:
    if len(data) < 57:
        return ""

    try:
        offset = 12 + 34 + 4

        if offset >= len(data):
            return ""
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            offset += 34

        offset += 2 + 2 + 4 + 2
        if offset >= len(data):
            return ""

        num_names = data[offset]
        offset += 1

        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name = data[offset : offset + 15]
            name_type = data[offset + 15]
            flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
            offset += 18

            if flags & 0x8000:
                continue
            if name_type != 0x00:
                continue

            decoded = raw_name.decode("ascii", errors="ignore").strip()
            decoded = decoded.rstrip("\x00").strip()
            if decoded and decoded != "*":
                return decoded
    except (IndexError, struct.error):
        return ""

    return ""
