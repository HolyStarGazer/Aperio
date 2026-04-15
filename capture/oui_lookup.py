from pathlib import Path

_OUI_DATA_PATH = Path(__file__).parent / "oui_data.txt"
_cache: dict[str, str] | None = None


def _load() -> dict[str, str]:
    global _cache
    if _cache is not None:
        return _cache
    result: dict[str, str] = {}
    try:
        with open(_OUI_DATA_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(" ", 1)
                if len(parts) != 2:
                    continue
                result[parts[0].upper()] = parts[1]
    except FileNotFoundError:
        pass
    _cache = result
    return result


def lookup_vendor(mac: str) -> str:
    if not mac:
        return ""
    normalized = (
        mac.replace(":", "").replace("-", "").replace(".", "").replace(" ", "").upper()
    )
    if len(normalized) < 6:
        return ""
    return _load().get(normalized[:6], "")
