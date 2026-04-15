from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from models.device_registry import Device, DeviceRegistryModel
from models.packet_table import PacketTableModel
from ui.device_card import DeviceCard


class StatCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFrameShadow(QFrame.Shadow.Raised)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)

        self.value_label = QLabel("—")
        value_font = self.value_label.font()
        value_font.setPointSize(value_font.pointSize() + 10)
        value_font.setBold(True)
        self.value_label.setFont(value_font)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: gray;")

        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)


class DashboardTab(QWidget):
    view_packets_requested = pyqtSignal(str)

    MAX_RECENT_DEVICES = 6
    MAX_RECENT_PACKETS = 50

    def __init__(
        self,
        registry: DeviceRegistryModel,
        packets_model: PacketTableModel,
        parent=None,
    ):
        super().__init__(parent)
        self.registry = registry
        self.packets_model = packets_model

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(12)

        self.content_stack = QStackedWidget()
        self.content_stack.addWidget(self._build_empty_state())

        populated = QWidget()
        populated_layout = QVBoxLayout(populated)
        populated_layout.setContentsMargins(0, 0, 0, 0)
        populated_layout.setSpacing(12)

        self.device_stat = StatCard("Devices")
        self.packet_stat = StatCard("Packets")
        self.bytes_stat = StatCard("Bytes")
        self.edges_stat = StatCard("Connections")

        stats_row = QHBoxLayout()
        stats_row.setSpacing(10)
        stats_row.addWidget(self.device_stat)
        stats_row.addWidget(self.packet_stat)
        stats_row.addWidget(self.bytes_stat)
        stats_row.addWidget(self.edges_stat)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        devices_panel = QWidget()
        devices_layout = QVBoxLayout(devices_panel)
        devices_layout.setContentsMargins(0, 0, 0, 0)
        devices_layout.setSpacing(6)

        section_font = self.font()
        section_font.setPointSize(section_font.pointSize() + 1)
        section_font.setBold(True)

        devices_title = QLabel("Recent devices")
        devices_title.setFont(section_font)

        devices_scroll = QScrollArea()
        devices_scroll.setWidgetResizable(True)
        devices_scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.devices_container = QWidget()
        self.devices_container_layout = QVBoxLayout(self.devices_container)
        self.devices_container_layout.setContentsMargins(0, 0, 0, 0)
        self.devices_container_layout.setSpacing(4)

        self._devices_empty = QLabel("(no devices yet)")
        self._devices_empty.setStyleSheet("color: gray;")
        self.devices_container_layout.addWidget(self._devices_empty)
        self.devices_container_layout.addStretch()

        devices_scroll.setWidget(self.devices_container)

        devices_layout.addWidget(devices_title)
        devices_layout.addWidget(devices_scroll)

        packets_panel = QWidget()
        packets_layout = QVBoxLayout(packets_panel)
        packets_layout.setContentsMargins(0, 0, 0, 0)
        packets_layout.setSpacing(6)

        packets_title = QLabel("Recent packets")
        packets_title.setFont(section_font)

        self.packets_table = QTableWidget(0, 5)
        self.packets_table.setHorizontalHeaderLabels(
            ["#", "Time", "Source", "Destination", "Protocol"]
        )
        self.packets_table.verticalHeader().setVisible(False)
        self.packets_table.verticalHeader().setDefaultSectionSize(24)
        self.packets_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.packets_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.packets_table.setAlternatingRowColors(True)
        header = self.packets_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.packets_table.setColumnWidth(0, 55)
        self.packets_table.setColumnWidth(1, 100)
        self.packets_table.setColumnWidth(4, 80)

        packets_layout.addWidget(packets_title)
        packets_layout.addWidget(self.packets_table, stretch=1)

        splitter.addWidget(devices_panel)
        splitter.addWidget(packets_panel)
        splitter.setSizes([420, 640])
        splitter.setChildrenCollapsible(False)

        populated_layout.addLayout(stats_row)
        populated_layout.addWidget(splitter, stretch=1)

        self.content_stack.addWidget(populated)

        outer.addWidget(self.content_stack)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(1000)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.start()

        self.refresh()

    def _build_empty_state(self) -> QWidget:
        empty = QWidget()
        layout = QVBoxLayout(empty)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(10)

        layout.addStretch(1)

        title = QLabel("APERIO")
        title_font = self.font()
        title_font.setPointSize(title_font.pointSize() + 14)
        title_font.setBold(True)
        title_font.setLetterSpacing(title_font.SpacingType.AbsoluteSpacing, 4)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Network capture and topology analyzer")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: gray;")
        layout.addWidget(subtitle)

        layout.addSpacing(16)

        hint = QLabel(
            "No data yet — start a capture on the Scan tab\n"
            "or load a saved .pcap file to begin."
        )
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color: gray;")
        layout.addWidget(hint)

        layout.addStretch(2)

        return empty

    def refresh(self) -> None:
        devices = self.registry.all_devices()
        edges = self.registry.all_edges()

        total_bytes = sum(d.byte_count for d in devices)
        total_packets = self.packets_model.total_captured

        has_data = total_packets > 0 or len(devices) > 0
        self.content_stack.setCurrentIndex(1 if has_data else 0)

        if not has_data:
            return

        self.device_stat.set_value(str(len(devices)))
        self.packet_stat.set_value(f"{total_packets:,}")
        self.bytes_stat.set_value(self._format_bytes(total_bytes))
        self.edges_stat.set_value(str(len(edges)))

        recent_devices = sorted(
            devices, key=lambda d: d.last_seen, reverse=True
        )[: self.MAX_RECENT_DEVICES]
        self._render_devices(recent_devices)
        self._render_packets()

    def _render_devices(self, devices: list[Device]) -> None:
        while self.devices_container_layout.count() > 1:
            item = self.devices_container_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        if not devices:
            empty = QLabel("(no devices yet)")
            empty.setStyleSheet("color: gray;")
            self.devices_container_layout.insertWidget(0, empty)
            return

        for i, device in enumerate(devices):
            card = DeviceCard(device)
            card.view_packets_requested.connect(self.view_packets_requested.emit)
            self.devices_container_layout.insertWidget(i, card)

    def _render_packets(self) -> None:
        recent = self.packets_model.recent_packets(self.MAX_RECENT_PACKETS)
        if not recent:
            self.packets_table.setRowCount(0)
            return

        recent_newest_first = list(reversed(recent))
        self.packets_table.setRowCount(len(recent_newest_first))

        for row_idx, packet in enumerate(recent_newest_first):
            src = self.packets_model.get_hostname(packet["src_ip"]) or packet["src_ip"]
            dst = self.packets_model.get_hostname(packet["dst_ip"]) or packet["dst_ip"]
            values = [
                str(packet["number"]),
                PacketTableModel._format_time(packet["timestamp"]),
                src,
                dst,
                packet["protocol"],
            ]
            for col, text in enumerate(values):
                self.packets_table.setItem(row_idx, col, QTableWidgetItem(text))

    @staticmethod
    def _format_bytes(n: int) -> str:
        if n >= 1024 ** 3:
            return f"{n / (1024 ** 3):.1f} GB"
        if n >= 1024 ** 2:
            return f"{n / (1024 ** 2):.1f} MB"
        if n >= 1024:
            return f"{n / 1024:.1f} KB"
        return f"{n} B"
