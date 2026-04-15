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
from capture.hostname_cache import HostnameCache
from capture.threads import ArpScannerThread, CaptureThread, PcapLoaderThread
from models.device_registry import DeviceRegistryModel
from ui.dashboard_tab import DashboardTab
from ui.devices_tab import DevicesTab
from ui.packets_tab import PacketsTab
from ui.scan_tab import ScanTab
from ui.topology_tab import TopologyTab

TAB_NAMES = ["Dashboard", "Devices", "Topology", "Packets", "Scan"]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Aperio")
        self.resize(1100, 700)

        self.hostname_cache = HostnameCache()
        self.device_registry = DeviceRegistryModel(self.hostname_cache, self)
        self.packets_tab = PacketsTab(self.hostname_cache)
        self.devices_tab = DevicesTab(self.device_registry)
        self.topology_tab = TopologyTab(self.device_registry)
        self.dashboard_tab = DashboardTab(self.device_registry, self.packets_tab.model)
        self.scan_tab = ScanTab()
        self.capture_thread: CaptureThread | None = None
        self.loader_thread: PcapLoaderThread | None = None
        self.arp_scanner: ArpScannerThread | None = None

        self.packets_tab.resolver.hostname_resolved.connect(self._on_hostname_resolved)

        self.content = QStackedWidget()
        for name in TAB_NAMES:
            if name == "Packets":
                self.content.addWidget(self.packets_tab)
            elif name == "Scan":
                self.content.addWidget(self.scan_tab)
            elif name == "Devices":
                self.content.addWidget(self.devices_tab)
            elif name == "Topology":
                self.content.addWidget(self.topology_tab)
            elif name == "Dashboard":
                self.content.addWidget(self.dashboard_tab)
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
        self.scan_tab.arp_scan_requested.connect(self._on_arp_scan_requested)
        self.devices_tab.view_packets_requested.connect(self._on_view_packets_for_device)
        self.dashboard_tab.view_packets_requested.connect(self._on_view_packets_for_device)
        self.topology_tab.view_packets_requested.connect(self._on_view_packets_for_device)

    def _resolve_pcap_path(self, append: bool) -> tuple[Path, bool]:
        if append:
            latest = find_latest_capture()
            if latest is not None:
                return latest, True
        return new_capture_path(), False

    def _switch_to_packets_tab(self) -> None:
        self.content.setCurrentIndex(TAB_NAMES.index("Packets"))

    def _on_hostname_resolved(self, ip: str, hostname: str) -> None:
        self.hostname_cache.apply(ip, hostname)
        self.packets_tab.model.apply_hostname(ip, hostname)
        self.device_registry.apply_hostname(ip, hostname)

    def _on_view_packets_for_device(self, ip: str) -> None:
        self.packets_tab.set_ip_filter(ip)
        self._switch_to_packets_tab()

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
        self.capture_thread.packet_captured.connect(self.devices_tab.on_packet_received)
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
        self.topology_tab.reset_layout()

    def _on_capture_finished(self) -> None:
        if self.capture_thread is None:
            return
        self.capture_thread = None
        self.scan_tab.set_capturing(False)
        self.scan_tab.set_status("Finished")
        self.scan_tab.refresh_recent_captures()
        self.topology_tab.reset_layout()

    def _on_load_requested(self, path: str) -> None:
        if self.capture_thread is not None or self.loader_thread is not None:
            return
        file_path = Path(path)
        self.loader_thread = PcapLoaderThread(file_path, self)
        self.loader_thread.packet_loaded.connect(self.packets_tab.on_packet_received)
        self.loader_thread.packet_loaded.connect(self.devices_tab.on_packet_received)
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
        self.topology_tab.reset_layout()

    def _on_load_failed(self, error: str) -> None:
        self.loader_thread = None
        self.scan_tab.set_loading(False)
        self.scan_tab.set_status(f"Load failed: {error}")

    def _on_arp_scan_requested(self, iface: str, subnet: str) -> None:
        if (
            self.capture_thread is not None
            or self.loader_thread is not None
            or self.arp_scanner is not None
        ):
            return
        self.arp_scanner = ArpScannerThread(iface, subnet, self)
        self.arp_scanner.device_discovered.connect(self.device_registry.observe)
        self.arp_scanner.scan_progress.connect(self.scan_tab.set_arp_progress)
        self.arp_scanner.scan_complete.connect(self._on_arp_scan_complete)
        self.arp_scanner.scan_failed.connect(self._on_arp_scan_failed)
        self.arp_scanner.start()
        self.scan_tab.set_arp_scanning(True)
        self.scan_tab.set_status(f"ARP scanning {subnet}…")

    def _on_arp_scan_complete(self, count: int) -> None:
        self.arp_scanner = None
        self.scan_tab.set_arp_scanning(False)
        self.scan_tab.set_status(f"ARP scan found {count} devices")
        self.topology_tab.reset_layout()

    def _on_arp_scan_failed(self, error: str) -> None:
        self.arp_scanner = None
        self.scan_tab.set_arp_scanning(False)
        self.scan_tab.set_status(f"ARP scan failed: {error}")

    def closeEvent(self, event):
        if self.capture_thread is not None:
            self.capture_thread.stop()
        if self.loader_thread is not None:
            self.loader_thread.wait()
        if self.arp_scanner is not None:
            self.arp_scanner.wait()
        self.packets_tab.shutdown()
        self.hostname_cache.save()
        super().closeEvent(event)
