import datetime
import sys
import time

from PyQt6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
    QThread,
    pyqtSignal,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)
from scapy.all import ARP, IP, TCP, UDP, AsyncSniffer, conf

TAB_NAMES = ["Dashboard", "Devices", "Topology", "Packets", "Scan"]
DEFAULT_INTERFACE = "Ethernet"
MAX_PACKETS = 10_000


def list_interfaces() -> list[str]:
    try:
        names = {iface.name for iface in conf.ifaces.values() if iface.name}
        if not names:
            return [DEFAULT_INTERFACE]
        return sorted(names, key=lambda n: (n != DEFAULT_INTERFACE, n.lower()))
    except Exception:
        return [DEFAULT_INTERFACE]


def decode_packet(pkt) -> dict:
    result = {
        "timestamp": time.time(),
        "src_ip": "",
        "dst_ip": "",
        "src_port": None,
        "dst_port": None,
        "protocol": "Other",
        "info": pkt.summary(),
        "length": len(pkt),
    }

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        result["protocol"] = "ARP"
        result["src_ip"] = arp.psrc
        result["dst_ip"] = arp.pdst
        op = "request" if arp.op == 1 else "reply"
        result["info"] = f"ARP {op}  who-has {arp.pdst} tell {arp.psrc}"
        return result

    if pkt.haslayer(IP):
        ip = pkt[IP]
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            result["protocol"] = "TCP"
            result["src_port"] = int(tcp.sport)
            result["dst_port"] = int(tcp.dport)
            result["info"] = f"{tcp.sport} → {tcp.dport}  flags={tcp.flags}"
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            result["protocol"] = "UDP"
            result["src_port"] = int(udp.sport)
            result["dst_port"] = int(udp.dport)
            result["info"] = f"{udp.sport} → {udp.dport}"
        else:
            result["protocol"] = f"IP/{ip.proto}"

    return result


class CaptureThread(QThread):
    packet_captured = pyqtSignal(dict)
    capture_finished = pyqtSignal()

    def __init__(self, iface: str, target: int | None = None, parent=None):
        super().__init__(parent)
        self._iface = iface
        self._target = target
        self._running = True
        self._count = 0

    def run(self):
        sniffer = AsyncSniffer(
            iface=self._iface,
            prn=self._handle_packet,
            store=False,
        )
        sniffer.start()
        while self._running:
            self.msleep(100)
            if self._target is not None and self._count >= self._target:
                break
        sniffer.stop()
        self.capture_finished.emit()

    def _handle_packet(self, pkt):
        if self._target is not None and self._count >= self._target:
            return
        self._count += 1
        decoded = decode_packet(pkt)
        self.packet_captured.emit(decoded)

    def stop(self):
        self._running = False
        self.wait()


class PacketTableModel(QAbstractTableModel):
    COLUMNS = ["#", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._packets: list[dict] = []
        self._next_number = 0

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
            return packet["src_ip"]
        if column == 3:
            return packet["dst_ip"]
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


class PacketsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.header = QLabel("Packets — 0 captured")

        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(6)

        self.protocol_filter = QLineEdit()
        self.protocol_filter.setPlaceholderText("Protocol (TCP, UDP, ARP…)")
        self.protocol_filter.setMaximumWidth(180)

        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("IP substring (src or dst)")
        self.ip_filter.setMaximumWidth(220)

        self.port_filter = QLineEdit()
        self.port_filter.setPlaceholderText("Port")
        self.port_filter.setMaximumWidth(80)

        self.clear_button = QPushButton("Clear")

        filter_bar.addWidget(QLabel("Filter:"))
        filter_bar.addWidget(self.protocol_filter)
        filter_bar.addWidget(self.ip_filter)
        filter_bar.addWidget(self.port_filter)
        filter_bar.addStretch()
        filter_bar.addWidget(self.clear_button)

        self.model = PacketTableModel()
        self.proxy = PacketFilterProxyModel()
        self.proxy.setSourceModel(self.model)

        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.view.setAlternatingRowColors(True)
        self.view.verticalHeader().setVisible(False)

        header = self.view.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.view.setColumnWidth(0, 60)
        self.view.setColumnWidth(1, 110)
        self.view.setColumnWidth(2, 150)
        self.view.setColumnWidth(3, 150)
        self.view.setColumnWidth(4, 80)
        self.view.setColumnWidth(5, 70)

        self.protocol_filter.textChanged.connect(self.proxy.set_protocol_filter)
        self.ip_filter.textChanged.connect(self.proxy.set_ip_filter)
        self.port_filter.textChanged.connect(self.proxy.set_port_filter)
        self.clear_button.clicked.connect(self._on_clear)

        layout.addWidget(self.header)
        layout.addLayout(filter_bar)
        layout.addWidget(self.view)

    def _on_clear(self) -> None:
        self.model.clear()
        self.header.setText("Packets — 0 captured")

    def _is_default_order(self) -> bool:
        sort_column = self.proxy.sortColumn()
        sort_order = self.proxy.sortOrder()
        if sort_column == -1:
            return True
        return sort_column == 0 and sort_order == Qt.SortOrder.AscendingOrder

    def on_packet_received(self, packet: dict) -> None:
        scrollbar = self.view.verticalScrollBar()
        at_bottom = scrollbar.value() >= scrollbar.maximum() - 2
        default_order = self._is_default_order()

        self.model.append_packet(packet, allow_eviction=at_bottom and default_order)
        self.header.setText(f"Packets — {self.model._next_number} captured")

        if at_bottom and default_order:
            self.view.scrollToBottom()


class ScanTab(QWidget):
    start_live_requested = pyqtSignal(str)
    start_scan_requested = pyqtSignal(str, int)
    stop_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Capture")
        title_font = title.font()
        title_font.setPointSize(title_font.pointSize() + 4)
        title_font.setBold(True)
        title.setFont(title_font)

        iface_row = QHBoxLayout()
        iface_row.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        for name in list_interfaces():
            self.iface_combo.addItem(name)
        default_index = self.iface_combo.findText(DEFAULT_INTERFACE)
        if default_index >= 0:
            self.iface_combo.setCurrentIndex(default_index)
        self.iface_combo.setMinimumWidth(280)
        iface_row.addWidget(self.iface_combo)
        iface_row.addStretch()

        self.live_button = QPushButton("Start Live Capture")
        self.live_button.setMinimumWidth(200)

        live_row = QHBoxLayout()
        live_row.addWidget(self.live_button)
        live_row.addStretch()

        self.scan_button = QPushButton("Capture N Packets")
        self.scan_button.setMinimumWidth(200)
        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, 1_000_000)
        self.count_spin.setValue(100)
        self.count_spin.setMaximumWidth(120)

        scan_row = QHBoxLayout()
        scan_row.addWidget(self.scan_button)
        scan_row.addWidget(QLabel("count:"))
        scan_row.addWidget(self.count_spin)
        scan_row.addStretch()

        self.stop_button = QPushButton("Stop")
        self.stop_button.setMinimumWidth(200)
        self.stop_button.setEnabled(False)

        stop_row = QHBoxLayout()
        stop_row.addWidget(self.stop_button)
        stop_row.addStretch()

        self.status_label = QLabel("Status: Idle")

        layout.addWidget(title)
        layout.addLayout(iface_row)
        layout.addLayout(live_row)
        layout.addLayout(scan_row)
        layout.addLayout(stop_row)
        layout.addWidget(self.status_label)
        layout.addStretch()

        self.live_button.clicked.connect(self._on_live_clicked)
        self.scan_button.clicked.connect(self._on_scan_clicked)
        self.stop_button.clicked.connect(self.stop_requested.emit)

    def _on_live_clicked(self) -> None:
        self.start_live_requested.emit(self.iface_combo.currentText())

    def _on_scan_clicked(self) -> None:
        self.start_scan_requested.emit(
            self.iface_combo.currentText(),
            self.count_spin.value(),
        )

    def set_capturing(self, capturing: bool) -> None:
        self.live_button.setEnabled(not capturing)
        self.scan_button.setEnabled(not capturing)
        self.count_spin.setEnabled(not capturing)
        self.iface_combo.setEnabled(not capturing)
        self.stop_button.setEnabled(capturing)

    def set_status(self, text: str) -> None:
        self.status_label.setText(f"Status: {text}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Aperio")
        self.resize(1100, 700)

        self.packets_tab = PacketsTab()
        self.scan_tab = ScanTab()
        self.capture_thread: CaptureThread | None = None

        self.content = QStackedWidget()
        for name in TAB_NAMES:
            if name == "Packets":
                self.content.addWidget(self.packets_tab)
            elif name == "Scan":
                self.content.addWidget(self.scan_tab)
            else:
                placeholder = QLabel(f"{name} (placeholder)")
                placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
                self.content.addWidget(placeholder)

        sidebar = QWidget()
        sidebar.setFixedWidth(160)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(8, 8, 8, 8)
        sidebar_layout.setSpacing(4)

        for index, name in enumerate(TAB_NAMES):
            button = QPushButton(name)
            button.clicked.connect(lambda _checked, i=index: self.content.setCurrentIndex(i))
            sidebar_layout.addWidget(button)

        sidebar_layout.addStretch()

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(sidebar)
        root_layout.addWidget(self.content, stretch=1)

        self.setCentralWidget(root)

        self.scan_tab.start_live_requested.connect(self._start_live)
        self.scan_tab.start_scan_requested.connect(self._start_scan)
        self.scan_tab.stop_requested.connect(self._stop_capture)

    def _start_live(self, iface: str) -> None:
        if self._start_capture(iface, target=None):
            self.scan_tab.set_status(f"Capturing live on {iface}")

    def _start_scan(self, iface: str, count: int) -> None:
        if self._start_capture(iface, target=count):
            self.scan_tab.set_status(f"Capturing {count} packets on {iface}")

    def _start_capture(self, iface: str, target: int | None) -> bool:
        if self.capture_thread is not None:
            return False
        self.capture_thread = CaptureThread(iface, target, self)
        self.capture_thread.packet_captured.connect(self.packets_tab.on_packet_received)
        self.capture_thread.capture_finished.connect(self._on_capture_finished)
        self.capture_thread.start()
        self.scan_tab.set_capturing(True)
        return True

    def _stop_capture(self) -> None:
        if self.capture_thread is None:
            return
        self.capture_thread.stop()
        self.capture_thread = None
        self.scan_tab.set_capturing(False)
        self.scan_tab.set_status("Stopped")

    def _on_capture_finished(self) -> None:
        if self.capture_thread is None:
            return
        self.capture_thread = None
        self.scan_tab.set_capturing(False)
        self.scan_tab.set_status("Finished")

    def closeEvent(self, event):
        if self.capture_thread is not None:
            self.capture_thread.stop()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
