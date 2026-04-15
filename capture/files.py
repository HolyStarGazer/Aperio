import datetime
from pathlib import Path

from scapy.all import conf

DEFAULT_INTERFACE = "Ethernet"
CAPTURES_DIR = Path("data") / "captures"
RECENT_CAPTURES_LIMIT = 5


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
