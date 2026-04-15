from __future__ import annotations

ROUTER_VENDORS = (
    "ubiquiti", "netgear", "tp-link", "tplink", "cisco", "asus",
    "arris", "linksys", "d-link", "dlink", "mikrotik", "ruckus",
    "aruba", "juniper", "zyxel", "huawei technologies", "belkin",
    "eero", "google fiber", "fortinet", "meraki",
)

PRINTER_VENDORS = (
    "hewlett packard", "hp inc", "brother", "canon", "epson",
    "lexmark", "kyocera", "ricoh", "xerox", "samsung electro",
)

PC_VENDORS = (
    "dell", "lenovo", "acer", "razer", "micro-star", "msi ",
    "gigabyte", "clevo", "framework", "system76", "tuxedo",
)

PHONE_VENDORS = (
    "samsung", "xiaomi", "huawei device",
    "oneplus", "motorola", "lg electronics", "oppo", "vivo",
    "nothing technology",
)

IOT_VENDORS = (
    "philips", "amazon", "nest", "ring", "tuya", "espressif",
    "shelly", "sonos", "roku", "ecobee", "wyze", "tp-link smart",
    "lifx", "belkin wemo", "honeywell", "august", "chamberlain",
    "particle", "itead", "sonoff",
)

ROUTER_HOSTNAME_HINTS = ("onhub", "google-wifi", "googlewifi", "nestwifi", "nest-wifi")
PHONE_HOSTNAME_HINTS = ("iphone", "ipad", "pixel", "android", "galaxy", "oneplus")
PC_HOSTNAME_HINTS = ("macbook", "imac", "mac-mini", "desktop-", "laptop-", "surface")

PRINTER_PORTS = {515, 631, 9100}
ROUTER_PORTS = {53, 67, 1900}
SERVER_PORTS = {22, 80, 443, 3306, 5432, 8080, 8443}


def _vendor_matches(vendor: str, needles: tuple[str, ...]) -> bool:
    if not vendor:
        return False
    v = vendor.lower()
    return any(n in v for n in needles)


def _hostname_matches(hostname: str, needles: tuple[str, ...]) -> bool:
    if not hostname:
        return False
    h = hostname.lower()
    return any(n in h for n in needles)


def guess_device_type(
    vendor: str,
    os_hint: str,
    ports: set[int] | None,
    is_gateway: bool = False,
    is_self: bool = False,
    hostname: str = "",
) -> str:
    if is_gateway:
        return "router"
    if is_self:
        return "pc"

    ports = ports or set()

    if _hostname_matches(hostname, ROUTER_HOSTNAME_HINTS):
        return "router"
    if _hostname_matches(hostname, PC_HOSTNAME_HINTS):
        return "pc"
    if _hostname_matches(hostname, PHONE_HOSTNAME_HINTS):
        return "phone"

    if _vendor_matches(vendor, PRINTER_VENDORS) or (ports & PRINTER_PORTS):
        return "printer"
    if _vendor_matches(vendor, ROUTER_VENDORS):
        return "router"
    if _vendor_matches(vendor, PC_VENDORS):
        return "pc"
    if _vendor_matches(vendor, IOT_VENDORS):
        return "iot"
    if _vendor_matches(vendor, PHONE_VENDORS):
        return "phone"

    if os_hint.startswith("Linux") and (ports & SERVER_PORTS):
        return "server"
    if os_hint.startswith("Windows"):
        return "pc"

    return "unknown"


TYPE_LABELS = {
    "router": "Router",
    "printer": "Printer",
    "server": "Server",
    "pc": "PC",
    "phone": "Phone",
    "iot": "IoT",
    "unknown": "Unknown",
}


def type_label(device_type: str) -> str:
    return TYPE_LABELS.get(device_type, "Unknown")
