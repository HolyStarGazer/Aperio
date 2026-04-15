def guess_os_from_ttl(ttl: int | None) -> str:
    if ttl is None or ttl <= 0 or ttl > 255:
        return ""
    if ttl <= 32:
        return "Windows 9x / embedded"
    if ttl <= 64:
        return "Linux / macOS / iOS"
    if ttl <= 128:
        return "Windows"
    return "Network device"
