from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from capture.hostname_cache import HostnameCache
from capture.threads import HostnameResolverThread
from models.packet_table import PacketFilterProxyModel, PacketTableModel
from ui.packet_detail import PacketDetailView


class PacketsTab(QWidget):
    def __init__(self, hostname_cache: HostnameCache, parent=None):
        super().__init__(parent)
        self.hostname_cache = hostname_cache

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
        self.model.populate_hostname_cache(self.hostname_cache.all_entries())
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

        self.detail_view = PacketDetailView()

        detail_panel = QWidget()
        detail_panel_layout = QVBoxLayout(detail_panel)
        detail_panel_layout.setContentsMargins(0, 0, 0, 0)
        detail_panel_layout.setSpacing(4)

        detail_header = QLabel("Packet detail")
        detail_header_font = detail_header.font()
        detail_header_font.setBold(True)
        detail_header_font.setPointSize(detail_header_font.pointSize() + 1)
        detail_header.setFont(detail_header_font)
        detail_panel_layout.addWidget(detail_header)
        detail_panel_layout.addWidget(self.detail_view)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.view)
        splitter.addWidget(detail_panel)
        splitter.setSizes([450, 250])
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(14)

        self.protocol_filter.textChanged.connect(self.proxy.set_protocol_filter)
        self.ip_filter.textChanged.connect(self.proxy.set_ip_filter)
        self.port_filter.textChanged.connect(self.proxy.set_port_filter)
        self.clear_button.clicked.connect(self._on_clear)
        self.view.selectionModel().currentChanged.connect(self._on_current_changed)

        self.resolver = HostnameResolverThread(self.hostname_cache, self)
        self.resolver.start()

        layout.addWidget(self.header)
        layout.addLayout(filter_bar)
        layout.addWidget(splitter)

    def _on_clear(self) -> None:
        self.model.clear()
        self.header.setText("Packets — 0 captured")
        self.detail_view.show_packet(None)

    def _on_current_changed(self, current, previous) -> None:
        if not current.isValid():
            self.detail_view.show_packet(None)
            return
        source_index = self.proxy.mapToSource(current)
        if not source_index.isValid():
            self.detail_view.show_packet(None)
            return
        try:
            packet = self.model.get_packet(source_index.row())
        except IndexError:
            self.detail_view.show_packet(None)
            return
        self.detail_view.show_packet(packet)

    def set_ip_filter(self, ip: str) -> None:
        self.ip_filter.setText(ip)

    def shutdown(self) -> None:
        self.resolver.stop()

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
        self.header.setText(f"Packets — {self.model.total_captured} captured")

        for ip in (packet["src_ip"], packet["dst_ip"]):
            if self.model.mark_pending_hostname(ip):
                self.resolver.enqueue(ip)

        if at_bottom and default_order:
            self.view.scrollToBottom()
