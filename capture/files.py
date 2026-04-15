import datetime
from pathlib import Path

from scapy.all import conf

DEFAULT_INTERFACE = "Ethernet"
CAPTURES_DIR = Path("data") / "captures"
RECENT_CAPTURES_LIMIT = 5


def detect_network_context() -> tuple[str, str]:
    try:
        result = conf.route.route("8.8.8.8")
        if not result or len(result) < 3:
            return "", ""
        _iface, src_ip, gateway_ip = result
        src_ip = src_ip or ""
        gateway_ip = gateway_ip or ""
        if src_ip == "0.0.0.0":
            src_ip = ""
        if gateway_ip == "0.0.0.0":
            gateway_ip = ""
        return src_ip, gateway_ip
    except Exception:
        return "", ""


def _int_to_dotted(n: int) -> str:
    n = n & 0xFFFFFFFF
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def _dotted_to_int(ip: str) -> int | None:
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        return (
            (int(parts[0]) << 24)
            | (int(parts[1]) << 16)
            | (int(parts[2]) << 8)
            | int(parts[3])
        )
    except (ValueError, IndexError):
        return None


def _detect_subnet_from_routes(local_ip: str, gateway_ip: str) -> str:
    if not local_ip:
        return ""
    gateway_int = _dotted_to_int(gateway_ip) if gateway_ip else None
    try:
        for route in conf.route.routes:
            if len(route) < 5:
                continue
            try:
                network = int(route[0])
                netmask = int(route[1])
                gateway_str = str(route[2])
                output = str(route[4])
            except (ValueError, TypeError):
                continue
            if output != local_ip:
                continue
            if gateway_str not in ("0.0.0.0", ""):
                continue
            if netmask == 0 or netmask == 0xFFFFFFFF:
                continue
            prefix_len = bin(netmask & 0xFFFFFFFF).count("1")
            if prefix_len < 8 or prefix_len > 30:
                continue
            if gateway_int is not None:
                if (gateway_int & netmask) != (network & netmask):
                    continue
            return f"{_int_to_dotted(network)}/{prefix_len}"
    except Exception:
        pass
    return ""


def default_subnet(local_ip: str, gateway_ip: str = "") -> str:
    from_routes = _detect_subnet_from_routes(local_ip, gateway_ip)
    if from_routes:
        return from_routes
    if not local_ip:
        return ""
    parts = local_ip.split(".")
    if len(parts) != 4:
        return ""
    try:
        for p in parts:
            int(p)
    except ValueError:
        return ""
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0])
        b = int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    return False


def is_multicast_or_broadcast(ip: str) -> bool:
    if not ip:
        return False
    if ip == "255.255.255.255":
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0])
    except ValueError:
        return False
    return 224 <= a <= 239


def is_multicast_mac(mac: str) -> bool:
    if not mac:
        return False
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return (first & 0x01) != 0


def is_bogus_ip(ip: str) -> bool:
    if not ip:
        return False
    if ip == "0.0.0.0":
        return True
    if ip.startswith("127."):
        return True
    return False


def ensure_captures_dir() -> Path:
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    return CAPTURES_DIR


def new_capture_path() -> Path:
    ensure_captures_dir()
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return CAPTURES_DIR / f"{ts}.pcap"


def find_latest_capture() -> Path | None:
    if not CAPTURES_DIR.exists():
        return None
    files = sorted(CAPTURES_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def list_interfaces() -> list[str]:
    try:
        names = {iface.name for iface in conf.ifaces.values() if iface.name}
        if not names:
            return [DEFAULT_INTERFACE]
        return sorted(names, key=lambda n: (n != DEFAULT_INTERFACE, n.lower()))
    except Exception:
        return [DEFAULT_INTERFACE]
