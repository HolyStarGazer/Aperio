from dataclasses import dataclass, field

from PyQt6.QtCore import QObject, pyqtSignal

from capture.files import (
    is_bogus_ip,
    is_multicast_mac,
    is_multicast_or_broadcast,
    is_private_ip,
)
from capture.oui_lookup import lookup_vendor


@dataclass
class Device:
    key: str
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    ports: set = field(default_factory=set)


class DeviceRegistryModel(QObject):
    device_changed = pyqtSignal(str)
    devices_cleared = pyqtSignal()
    topology_structure_changed = pyqtSignal()

    def __init__(self, hostname_cache=None, parent=None):
        super().__init__(parent)
        self._devices: dict[str, Device] = {}
        self._edges: set[tuple[str, str]] = set()
        self._hostname_cache = hostname_cache

    def observe(self, packet: dict) -> None:
        timestamp = packet.get("timestamp", 0.0)
        length = packet.get("length", 0)

        src = self._observe_endpoint(
            packet.get("src_ip", ""),
            packet.get("src_mac", ""),
            packet.get("src_port"),
            timestamp,
            length,
        )
        dst = self._observe_endpoint(
            packet.get("dst_ip", ""),
            packet.get("dst_mac", ""),
            packet.get("dst_port"),
            timestamp,
            length,
        )

        structure_changed = False
        if src is not None and src[1]:
            structure_changed = True
        if dst is not None and dst[1]:
            structure_changed = True

        if src is not None and dst is not None:
            src_key, dst_key = src[0], dst[0]
            if src_key != dst_key:
                edge = (src_key, dst_key) if src_key < dst_key else (dst_key, src_key)
                if edge not in self._edges:
                    self._edges.add(edge)
                    structure_changed = True

        if structure_changed:
            self.topology_structure_changed.emit()

    def _observe_endpoint(
        self,
        ip: str,
        mac: str,
        port,
        timestamp: float,
        length: int,
    ) -> tuple[str, bool] | None:
        if is_bogus_ip(ip):
            ip = ""

        if mac == "ff:ff:ff:ff:ff:ff":
            return None

        if not ip and not mac:
            return None

        if not ip and mac and is_multicast_mac(mac):
            return None

        if ip and is_multicast_or_broadcast(ip):
            key = ip
            effective_mac = ""
        elif ip and not is_private_ip(ip):
            key = ip
            effective_mac = ""
        else:
            key = mac if mac else ip
            effective_mac = mac

        device = self._devices.get(key)
        is_new = device is None

        if is_new:
            initial_hostname = ""
            if self._hostname_cache is not None and ip:
                cached = self._hostname_cache.get(ip)
                if cached and cached != ip:
                    initial_hostname = cached
            device = Device(
                key=key,
                ip=ip,
                mac=effective_mac,
                hostname=initial_hostname,
                vendor=lookup_vendor(effective_mac) if effective_mac else "",
                first_seen=timestamp,
                last_seen=timestamp,
                packet_count=1,
                byte_count=length,
            )
            if port is not None:
                device.ports.add(port)
            self._devices[key] = device
        else:
            device.last_seen = timestamp
            device.packet_count += 1
            device.byte_count += length
            if port is not None:
                device.ports.add(port)
            if not device.ip and ip:
                device.ip = ip
            if not device.mac and effective_mac:
                device.mac = effective_mac
                device.vendor = lookup_vendor(effective_mac)

        self.device_changed.emit(key)
        return key, is_new

    def apply_hostname(self, ip: str, hostname: str) -> None:
        if not ip or hostname == ip:
            return
        for device in self._devices.values():
            if device.ip == ip and device.hostname != hostname:
                device.hostname = hostname
                self.device_changed.emit(device.key)

    def get_device(self, key: str) -> Device | None:
        return self._devices.get(key)

    def all_devices(self) -> list[Device]:
        return list(self._devices.values())

    def all_edges(self) -> list[tuple[str, str]]:
        return list(self._edges)

    def clear(self) -> None:
        self._devices.clear()
        self._edges.clear()
        self.devices_cleared.emit()
        self.topology_structure_changed.emit()
