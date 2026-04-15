from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from models.device_registry import Device


class DeviceCard(QFrame):
    view_packets_requested = pyqtSignal(str)

    def __init__(self, device: Device, parent=None):
        super().__init__(parent)
        self.setObjectName("deviceCard")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFrameShadow(QFrame.Shadow.Raised)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(10)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        self.title_label = QLabel()
        title_font = self.title_label.font()
        title_font.setBold(True)
        title_font.setPointSize(title_font.pointSize() + 1)
        self.title_label.setFont(title_font)

        self.detail_label = QLabel()
        self.detail_label.setStyleSheet("color: gray;")

        self.stats_label = QLabel()
        self.stats_label.setStyleSheet("color: gray;")

        info_layout.addWidget(self.title_label)
        info_layout.addWidget(self.detail_label)
        info_layout.addWidget(self.stats_label)

        self.view_btn = QPushButton("View Packets")
        self.view_btn.setMaximumWidth(120)

        layout.addLayout(info_layout)
        layout.addStretch()
        layout.addWidget(self.view_btn)

        self._ip = ""
        self.view_btn.clicked.connect(self._on_view_clicked)
        self.update_from(device)

    def update_from(self, device: Device) -> None:
        self._ip = device.ip

        title = device.hostname or device.ip or device.mac or device.key
        self.title_label.setText(title)

        detail_parts = []
        if device.hostname and device.ip and device.ip != device.hostname:
            detail_parts.append(device.ip)
        if device.mac:
            detail_parts.append(device.mac)
        if device.vendor:
            detail_parts.append(device.vendor)
        self.detail_label.setText("  ·  ".join(detail_parts) if detail_parts else "—")

        stats_parts = [f"{device.packet_count} packets"]
        if device.byte_count >= 1024 * 1024:
            stats_parts.append(f"{device.byte_count / (1024 * 1024):.1f} MB")
        elif device.byte_count >= 1024:
            stats_parts.append(f"{device.byte_count / 1024:.1f} KB")
        else:
            stats_parts.append(f"{device.byte_count} B")
        if device.ports:
            sorted_ports = sorted(device.ports)
            shown = sorted_ports[:6]
            port_str = ", ".join(str(p) for p in shown)
            if len(sorted_ports) > 6:
                port_str += f" (+{len(sorted_ports) - 6})"
            stats_parts.append(f"ports: {port_str}")
        self.stats_label.setText("  ·  ".join(stats_parts))

        self.view_btn.setEnabled(bool(device.ip))

    def _on_view_clicked(self) -> None:
        if self._ip:
            self.view_packets_requested.emit(self._ip)
