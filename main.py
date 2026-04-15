import datetime
import sys
from pathlib import Path

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
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)
from scapy.all import (
    ARP,
    IP,
    TCP,
    UDP,
    AsyncSniffer,
    PcapReader,
    PcapWriter,
    conf,
)

TAB_NAMES = ["Dashboard", "Devices", "Topology", "Packets", "Scan"]
DEFAULT_INTERFACE = "Ethernet"
MAX_PACKETS = 10_000
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


def decode_packet(pkt) -> dict:
    result = {
        "timestamp": float(pkt.time),
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


def packet_matches_filter(packet: dict, capture_filter: dict) -> bool:
    if not capture_filter:
        return True
    src_ip = capture_filter.get("src_ip", "")
    if src_ip and src_ip not in packet["src_ip"]:
        return False
    dst_ip = capture_filter.get("dst_ip", "")
    if dst_ip and dst_ip not in packet["dst_ip"]:
        return False
    port = capture_filter.get("port")
    if port is not None:
        if packet["src_port"] != port and packet["dst_port"] != port:
            return False
    protocol = capture_filter.get("protocol", "")
    if protocol and protocol not in packet["protocol"].upper():
        return False
    return True


def summarize_filter(capture_filter: dict) -> str:
    if not capture_filter:
        return ""
    parts = []
    if capture_filter.get("protocol"):
        parts.append(capture_filter["protocol"])
    if capture_filter.get("src_ip"):
        parts.append(f"src={capture_filter['src_ip']}")
    if capture_filter.get("dst_ip"):
        parts.append(f"dst={capture_filter['dst_ip']}")
    if capture_filter.get("port") is not None:
        parts.append(f"port={capture_filter['port']}")
    return ", ".join(parts)


class CaptureThread(QThread):
    packet_captured = pyqtSignal(dict)
    capture_finished = pyqtSignal()

    def __init__(
        self,
        iface: str,
        target: int | None = None,
        pcap_path: Path | None = None,
        append: bool = False,
        capture_filter: dict | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._iface = iface
        self._target = target
        self._pcap_path = pcap_path
        self._append = append
        self._filter = capture_filter or {}
        self._running = True
        self._count = 0
        self._writer: PcapWriter | None = None

    def run(self):
        if self._pcap_path is not None:
            self._writer = PcapWriter(
                str(self._pcap_path),
                append=self._append,
                sync=True,
            )

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

        if self._writer is not None:
            self._writer.close()
            self._writer = None

        self.capture_finished.emit()

    def _handle_packet(self, pkt):
        if self._target is not None and self._count >= self._target:
            return
        decoded = decode_packet(pkt)
        if not packet_matches_filter(decoded, self._filter):
            return
        self._count += 1
        if self._writer is not None:
            self._writer.write(pkt)
        self.packet_captured.emit(decoded)

    def stop(self):
        self._running = False
        self.wait()


class PcapLoaderThread(QThread):
    packet_loaded = pyqtSignal(dict)
    load_finished = pyqtSignal(int)
    load_failed = pyqtSignal(str)

    def __init__(self, path: Path, parent=None):
        super().__init__(parent)
        self._path = path

    def run(self):
        count = 0
        try:
            with PcapReader(str(self._path)) as reader:
                for pkt in reader:
                    decoded = decode_packet(pkt)
                    self.packet_loaded.emit(decoded)
                    count += 1
        except Exception as e:
            self.load_failed.emit(str(e))
            return
        self.load_finished.emit(count)


class RecentCapturesScanner(QThread):
    scan_complete = pyqtSignal(list)

    def __init__(self, limit: int = RECENT_CAPTURES_LIMIT, parent=None):
        super().__init__(parent)
        self._limit = limit

    def run(self):
        if not CAPTURES_DIR.exists():
            self.scan_complete.emit([])
            return

        files = sorted(
            CAPTURES_DIR.glob("*.pcap"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[: self._limit]

        results = []
        for path in files:
            try:
                count = 0
                with PcapReader(str(path)) as reader:
                    for _ in reader:
                        count += 1
            except Exception:
                count = -1
            results.append((path, count))

        self.scan_complete.emit(results)


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


class RecentCaptureCard(QFrame):
    load_requested = pyqtSignal(str)

    def __init__(self, path: Path, packet_count: int, parent=None):
        super().__init__(parent)
        self._path = path

        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFrameShadow(QFrame.Shadow.Raised)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(10)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        mtime = datetime.datetime.fromtimestamp(path.stat().st_mtime)
        time_label = QLabel(mtime.strftime("%Y-%m-%d  %H:%M:%S"))
        time_font = time_label.font()
        time_font.setBold(True)
        time_label.setFont(time_font)

        size_kb = path.stat().st_size / 1024
        if packet_count >= 0:
            detail_text = f"{packet_count} packets  ·  {size_kb:.1f} KB  ·  {path.name}"
        else:
            detail_text = f"unreadable  ·  {size_kb:.1f} KB  ·  {path.name}"
        detail_label = QLabel(detail_text)
        detail_label.setStyleSheet("color: gray;")

        info_layout.addWidget(time_label)
        info_layout.addWidget(detail_label)

        load_btn = QPushButton("Load")
        load_btn.setMaximumWidth(90)
        load_btn.clicked.connect(lambda: self.load_requested.emit(str(self._path)))
        if packet_count < 0:
            load_btn.setEnabled(False)

        layout.addLayout(info_layout)
        layout.addStretch()
        layout.addWidget(load_btn)


class ScanTab(QWidget):
    start_live_requested = pyqtSignal(str, bool, dict)
    start_scan_requested = pyqtSignal(str, int, bool, dict)
    stop_requested = pyqtSignal()
    load_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self._capturing = False
        self._loading = False
        self._scanner_thread: RecentCapturesScanner | None = None

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Capture")
        title.setFont(self._section_font())

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

        self.append_checkbox = QCheckBox("Append to previous session")

        filter_title = QLabel("Capture filters (optional, partial matches OK)")
        filter_title.setStyleSheet("color: gray;")

        self.src_ip_input = QLineEdit()
        self.src_ip_input.setPlaceholderText("Source IP")
        self.src_ip_input.setMaximumWidth(180)

        self.dst_ip_input = QLineEdit()
        self.dst_ip_input.setPlaceholderText("Destination IP")
        self.dst_ip_input.setMaximumWidth(180)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port")
        self.port_input.setMaximumWidth(80)

        self.protocol_input = QLineEdit()
        self.protocol_input.setPlaceholderText("Protocol")
        self.protocol_input.setMaximumWidth(120)

        filter_row = QHBoxLayout()
        filter_row.addWidget(self.src_ip_input)
        filter_row.addWidget(self.dst_ip_input)
        filter_row.addWidget(self.port_input)
        filter_row.addWidget(self.protocol_input)
        filter_row.addStretch()

        file_title = QLabel("File")
        file_title.setFont(self._section_font())

        self.load_button = QPushButton("Load Capture File…")
        self.load_button.setMinimumWidth(200)

        load_row = QHBoxLayout()
        load_row.addWidget(self.load_button)
        load_row.addStretch()

        recent_title = QLabel("Recent captures")
        recent_title.setFont(self._section_font())

        self.recent_container = QWidget()
        self.recent_layout = QVBoxLayout(self.recent_container)
        self.recent_layout.setContentsMargins(0, 0, 0, 0)
        self.recent_layout.setSpacing(6)

        self._recent_placeholder = QLabel("(scanning…)")
        self._recent_placeholder.setStyleSheet("color: gray;")
        self.recent_layout.addWidget(self._recent_placeholder)

        self.status_label = QLabel("Status: Idle")

        layout.addWidget(title)
        layout.addLayout(iface_row)
        layout.addLayout(live_row)
        layout.addLayout(scan_row)
        layout.addLayout(stop_row)
        layout.addWidget(self.append_checkbox)
        layout.addWidget(filter_title)
        layout.addLayout(filter_row)
        layout.addSpacing(8)
        layout.addWidget(file_title)
        layout.addLayout(load_row)
        layout.addSpacing(8)
        layout.addWidget(recent_title)
        layout.addWidget(self.recent_container)
        layout.addWidget(self.status_label)
        layout.addStretch()

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)

        self.live_button.clicked.connect(self._on_live_clicked)
        self.scan_button.clicked.connect(self._on_scan_clicked)
        self.stop_button.clicked.connect(self.stop_requested.emit)
        self.load_button.clicked.connect(self._on_load_clicked)

        self.refresh_recent_captures()

    def _section_font(self):
        font = self.font()
        font.setPointSize(font.pointSize() + 4)
        font.setBold(True)
        return font

    def _current_filter(self) -> dict:
        port_text = self.port_input.text().strip()
        port: int | None = None
        if port_text:
            try:
                port = int(port_text)
            except ValueError:
                port = None
        return {
            "src_ip": self.src_ip_input.text().strip(),
            "dst_ip": self.dst_ip_input.text().strip(),
            "port": port,
            "protocol": self.protocol_input.text().strip().upper(),
        }

    def _on_live_clicked(self) -> None:
        self.start_live_requested.emit(
            self.iface_combo.currentText(),
            self.append_checkbox.isChecked(),
            self._current_filter(),
        )

    def _on_scan_clicked(self) -> None:
        self.start_scan_requested.emit(
            self.iface_combo.currentText(),
            self.count_spin.value(),
            self.append_checkbox.isChecked(),
            self._current_filter(),
        )

    def _on_load_clicked(self) -> None:
        start_dir = CAPTURES_DIR if CAPTURES_DIR.exists() else Path.cwd()
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load capture file",
            str(start_dir),
            "Packet captures (*.pcap *.pcapng);;All files (*)",
        )
        if path:
            self.load_requested.emit(path)

    def set_capturing(self, capturing: bool) -> None:
        self._capturing = capturing
        self._update_enabled()

    def set_loading(self, loading: bool) -> None:
        self._loading = loading
        self._update_enabled()

    def _update_enabled(self) -> None:
        active = self._capturing or self._loading
        self.live_button.setEnabled(not active)
        self.scan_button.setEnabled(not active)
        self.count_spin.setEnabled(not active)
        self.iface_combo.setEnabled(not active)
        self.append_checkbox.setEnabled(not active)
        self.src_ip_input.setEnabled(not active)
        self.dst_ip_input.setEnabled(not active)
        self.port_input.setEnabled(not active)
        self.protocol_input.setEnabled(not active)
        self.load_button.setEnabled(not active)
        self.stop_button.setEnabled(self._capturing)

    def set_status(self, text: str) -> None:
        self.status_label.setText(f"Status: {text}")

    def refresh_recent_captures(self) -> None:
        if self._scanner_thread is not None:
            return
        self._scanner_thread = RecentCapturesScanner(parent=self)
        self._scanner_thread.scan_complete.connect(self._on_recent_scan_complete)
        self._scanner_thread.start()

    def _clear_recent_layout(self) -> None:
        while self.recent_layout.count():
            item = self.recent_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _on_recent_scan_complete(self, results: list) -> None:
        self._scanner_thread = None
        self._clear_recent_layout()

        if not results:
            empty = QLabel("(no recent captures)")
            empty.setStyleSheet("color: gray;")
            self.recent_layout.addWidget(empty)
            return

        for path, count in results:
            card = RecentCaptureCard(path, count)
            card.load_requested.connect(self.load_requested.emit)
            self.recent_layout.addWidget(card)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Aperio")
        self.resize(1100, 700)

        self.packets_tab = PacketsTab()
        self.scan_tab = ScanTab()
        self.capture_thread: CaptureThread | None = None
        self.loader_thread: PcapLoaderThread | None = None

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
        self.scan_tab.load_requested.connect(self._on_load_requested)

    def _resolve_pcap_path(self, append: bool) -> tuple[Path, bool]:
        if append:
            latest = find_latest_capture()
            if latest is not None:
                return latest, True
        return new_capture_path(), False

    def _switch_to_packets_tab(self) -> None:
        self.content.setCurrentIndex(TAB_NAMES.index("Packets"))

    def _start_live(self, iface: str, append: bool, capture_filter: dict) -> None:
        pcap_path, actually_appending = self._resolve_pcap_path(append)
        if self._start_capture(iface, None, pcap_path, actually_appending, capture_filter):
            mode = "appending to" if actually_appending else "writing to"
            filter_sum = summarize_filter(capture_filter)
            filter_note = f", filter: {filter_sum}" if filter_sum else ""
            self.scan_tab.set_status(
                f"Capturing live on {iface} ({mode} {pcap_path.name}{filter_note})"
            )

    def _start_scan(
        self,
        iface: str,
        count: int,
        append: bool,
        capture_filter: dict,
    ) -> None:
        pcap_path, actually_appending = self._resolve_pcap_path(append)
        if self._start_capture(iface, count, pcap_path, actually_appending, capture_filter):
            mode = "appending to" if actually_appending else "writing to"
            filter_sum = summarize_filter(capture_filter)
            filter_note = f", filter: {filter_sum}" if filter_sum else ""
            self.scan_tab.set_status(
                f"Capturing {count} packets on {iface} ({mode} {pcap_path.name}{filter_note})"
            )

    def _start_capture(
        self,
        iface: str,
        target: int | None,
        pcap_path: Path,
        append: bool,
        capture_filter: dict,
    ) -> bool:
        if self.capture_thread is not None or self.loader_thread is not None:
            return False
        self.capture_thread = CaptureThread(
            iface,
            target,
            pcap_path,
            append,
            capture_filter,
            self,
        )
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
        self.scan_tab.refresh_recent_captures()

    def _on_capture_finished(self) -> None:
        if self.capture_thread is None:
            return
        self.capture_thread = None
        self.scan_tab.set_capturing(False)
        self.scan_tab.set_status("Finished")
        self.scan_tab.refresh_recent_captures()

    def _on_load_requested(self, path: str) -> None:
        if self.capture_thread is not None or self.loader_thread is not None:
            return
        file_path = Path(path)
        self.loader_thread = PcapLoaderThread(file_path, self)
        self.loader_thread.packet_loaded.connect(self.packets_tab.on_packet_received)
        self.loader_thread.load_finished.connect(self._on_load_finished)
        self.loader_thread.load_failed.connect(self._on_load_failed)
        self.loader_thread.start()
        self.scan_tab.set_loading(True)
        self.scan_tab.set_status(f"Loading {file_path.name}…")
        self._switch_to_packets_tab()

    def _on_load_finished(self, count: int) -> None:
        self.loader_thread = None
        self.scan_tab.set_loading(False)
        self.scan_tab.set_status(f"Loaded {count} packets")
        self.scan_tab.refresh_recent_captures()

    def _on_load_failed(self, error: str) -> None:
        self.loader_thread = None
        self.scan_tab.set_loading(False)
        self.scan_tab.set_status(f"Load failed: {error}")

    def closeEvent(self, event):
        if self.capture_thread is not None:
            self.capture_thread.stop()
        if self.loader_thread is not None:
            self.loader_thread.wait()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
