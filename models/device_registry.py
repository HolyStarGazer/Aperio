from dataclasses import dataclass, field

from PyQt6.QtCore import QObject, pyqtSignal

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

    def __init__(self, parent=None):
        super().__init__(parent)
        self._devices: dict[str, Device] = {}

    def observe(self, packet: dict) -> None:
        timestamp = packet.get("timestamp", 0.0)
        length = packet.get("length", 0)

        self._observe_endpoint(
            packet.get("src_ip", ""),
            packet.get("src_mac", ""),
            packet.get("src_port"),
            timestamp,
            length,
        )
        self._observe_endpoint(
            packet.get("dst_ip", ""),
            packet.get("dst_mac", ""),
            packet.get("dst_port"),
            timestamp,
            length,
        )

    def _observe_endpoint(
        self,
        ip: str,
        mac: str,
        port,
        timestamp: float,
        length: int,
    ) -> None:
        if not ip and not mac:
            return

        key = mac if mac else ip
        device = self._devices.get(key)

        if device is None:
            device = Device(
                key=key,
                ip=ip,
                mac=mac,
                vendor=lookup_vendor(mac) if mac else "",
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
            if not device.mac and mac:
                device.mac = mac
                device.vendor = lookup_vendor(mac)

        self.device_changed.emit(key)

    def apply_hostname(self, ip: str, hostname: str) -> None:
        if not ip or hostname == ip:
            return
        for device in self._devices.values():
            if device.ip == ip and device.hostname != hostname:
                device.hostname = hostname
                self.device_changed.emit(device.key)

    def get_device(self, key: str) -> Device | None:
        return self._devices.get(key)

    def clear(self) -> None:
        self._devices.clear()
        self.devices_cleared.emit()
