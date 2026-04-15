import json
import sys
from pathlib import Path

CACHE_PATH = Path("data") / "hostnames.json"


class HostnameCache:
    def __init__(self):
        self._entries: dict[str, str] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if not CACHE_PATH.exists():
            return
        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        entries = data.get("entries")
        if not isinstance(entries, dict):
            return
        self._entries = {
            k: v
            for k, v in entries.items()
            if isinstance(k, str) and isinstance(v, str)
        }

    def save(self) -> None:
        if not self._dirty:
            return
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            snapshot = dict(self._entries)
            with open(CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(
                    {"schemaVersion": 1, "entries": snapshot},
                    f,
                    indent=2,
                    sort_keys=True,
                )
            self._dirty = False
        except Exception as e:
            print(f"Failed to save hostname cache: {e}", file=sys.stderr)

    def get(self, ip: str) -> str | None:
        if not ip:
            return None
        return self._entries.get(ip)

    def apply(self, ip: str, hostname: str) -> None:
        if not ip:
            return
        if self._entries.get(ip) != hostname:
            self._entries[ip] = hostname
            self._dirty = True

    def all_entries(self) -> dict[str, str]:
        return dict(self._entries)

    def purge_unresolved(self) -> list[str]:
        removed = [ip for ip, name in self._entries.items() if name == ip]
        for ip in removed:
            del self._entries[ip]
        if removed:
            self._dirty = True
        return removed

    def clear(self) -> list[str]:
        removed = list(self._entries.keys())
        self._entries.clear()
        if removed:
            self._dirty = True
        return removed
