import datetime

from PyQt6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)

MAX_PACKETS = 10_000


class PacketTableModel(QAbstractTableModel):
    COLUMNS = ["#", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._packets: list[dict] = []
        self._next_number = 0
        self._hostname_cache: dict[str, str | None] = {}

    def rowCount(self, parent=QModelIndex()):
        if parent.isValid():
            return 0
        return len(self._packets)

    def columnCount(self, parent=QModelIndex()):
        if parent.isValid():
            return 0
        return len(self.COLUMNS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        packet = self._packets[index.row()]
        column = index.column()

        if column == 0:
            return str(packet["number"])
        if column == 1:
            return self._format_time(packet["timestamp"])
        if column == 2:
            return self._display_ip(packet["src_ip"])
        if column == 3:
            return self._display_ip(packet["dst_ip"])
        if column == 4:
            return packet["protocol"]
        if column == 5:
            return str(packet["length"])
        if column == 6:
            return packet["info"]
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return None

    def append_packet(self, packet: dict, allow_eviction: bool = True) -> None:
        self._next_number += 1
        packet["number"] = self._next_number

        if allow_eviction and len(self._packets) >= MAX_PACKETS:
            excess = len(self._packets) - MAX_PACKETS + 1
            self.beginRemoveRows(QModelIndex(), 0, excess - 1)
            del self._packets[:excess]
            self.endRemoveRows()

        row = len(self._packets)
        self.beginInsertRows(QModelIndex(), row, row)
        self._packets.append(packet)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._packets.clear()
        self._next_number = 0
        self.endResetModel()

    def get_packet(self, row: int) -> dict:
        return self._packets[row]

    def populate_hostname_cache(self, entries: dict[str, str]) -> None:
        for ip, hostname in entries.items():
            self._hostname_cache[ip] = hostname

    def mark_pending_hostname(self, ip: str) -> bool:
        if not ip or ip in self._hostname_cache:
            return False
        self._hostname_cache[ip] = None
        return True

    def apply_hostname(self, ip: str, hostname: str) -> None:
        if ip not in self._hostname_cache:
            return
        self._hostname_cache[ip] = hostname
        if not self._packets:
            return
        matching = [
            i for i, p in enumerate(self._packets)
            if p["src_ip"] == ip or p["dst_ip"] == ip
        ]
        if not matching:
            return
        top_left = self.index(matching[0], 2)
        bottom_right = self.index(matching[-1], 3)
        self.dataChanged.emit(top_left, bottom_right, [Qt.ItemDataRole.DisplayRole])

    def _display_ip(self, ip: str) -> str:
        if not ip:
            return ""
        hostname = self._hostname_cache.get(ip)
        if hostname and hostname != ip:
            return hostname
        return ip

    @property
    def total_captured(self) -> int:
        return self._next_number

    @staticmethod
    def _format_time(ts: float) -> str:
        return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


class PacketFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._protocol_filter = ""
        self._ip_filter = ""
        self._port_filter: int | None = None

    def set_protocol_filter(self, text: str) -> None:
        self._protocol_filter = text.strip().upper()
        self.invalidateFilter()

    def set_ip_filter(self, text: str) -> None:
        self._ip_filter = text.strip()
        self.invalidateFilter()

    def set_port_filter(self, text: str) -> None:
        text = text.strip()
        if not text:
            self._port_filter = None
        else:
            try:
                self._port_filter = int(text)
            except ValueError:
                self._port_filter = None
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        packet = model.get_packet(source_row)

        if self._protocol_filter and self._protocol_filter not in packet["protocol"].upper():
            return False

        if self._ip_filter:
            if self._ip_filter not in packet["src_ip"] and self._ip_filter not in packet["dst_ip"]:
                return False

        if self._port_filter is not None:
            if packet["src_port"] != self._port_filter and packet["dst_port"] != self._port_filter:
                return False

        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        model = self.sourceModel()
        left_packet = model.get_packet(left.row())
        right_packet = model.get_packet(right.row())
        column = left.column()

        if column == 0:
            return left_packet["number"] < right_packet["number"]
        if column == 1:
            return left_packet["timestamp"] < right_packet["timestamp"]
        if column == 5:
            return left_packet["length"] < right_packet["length"]

        return super().lessThan(left, right)
