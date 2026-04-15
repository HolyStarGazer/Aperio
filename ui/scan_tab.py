import datetime
from pathlib import Path

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from capture.files import CAPTURES_DIR, DEFAULT_INTERFACE, list_interfaces
from capture.threads import RecentCapturesScanner


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
