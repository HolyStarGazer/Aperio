from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from capture.decoder import summarize_filter
from capture.files import find_latest_capture, new_capture_path
from capture.threads import CaptureThread, PcapLoaderThread
from ui.packets_tab import PacketsTab
from ui.scan_tab import ScanTab

TAB_NAMES = ["Dashboard", "Devices", "Topology", "Packets", "Scan"]


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
