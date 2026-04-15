from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from models.device_registry import DeviceRegistryModel
from ui.device_card import DeviceCard


class DevicesTab(QWidget):
    view_packets_requested = pyqtSignal(str)

    def __init__(self, registry: DeviceRegistryModel, parent=None):
        super().__init__(parent)
        self.registry = registry
        self._cards: dict[str, DeviceCard] = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header_bar = QHBoxLayout()
        header_bar.setContentsMargins(12, 12, 12, 8)

        self.header = QLabel("Devices — 0 discovered")
        header_font = self.header.font()
        header_font.setPointSize(header_font.pointSize() + 2)
        header_font.setBold(True)
        self.header.setFont(header_font)

        self.clear_button = QPushButton("Clear")
        self.clear_button.setMaximumWidth(100)

        header_bar.addWidget(self.header)
        header_bar.addStretch()
        header_bar.addWidget(self.clear_button)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(12, 4, 12, 12)
        self.content_layout.setSpacing(6)

        self._empty_label: QLabel | None = QLabel("(no devices yet — start a capture)")
        self._empty_label.setStyleSheet("color: gray;")
        self.content_layout.addWidget(self._empty_label)
        self.content_layout.addStretch()

        scroll.setWidget(self.content)

        outer.addLayout(header_bar)
        outer.addWidget(scroll)

        self.registry.device_changed.connect(self._on_device_changed)
        self.registry.devices_cleared.connect(self._on_devices_cleared)
        self.clear_button.clicked.connect(self._on_clear_clicked)

    def on_packet_received(self, packet: dict) -> None:
        self.registry.observe(packet)

    def _on_device_changed(self, key: str) -> None:
        device = self.registry.get_device(key)
        if device is None:
            return

        if key in self._cards:
            self._cards[key].update_from(device)
            return

        if self._empty_label is not None:
            self._empty_label.setParent(None)
            self._empty_label.deleteLater()
            self._empty_label = None

        card = DeviceCard(device)
        card.view_packets_requested.connect(self.view_packets_requested.emit)
        self._cards[key] = card
        insert_at = max(0, self.content_layout.count() - 1)
        self.content_layout.insertWidget(insert_at, card)
        self._update_header()

    def _on_devices_cleared(self) -> None:
        for card in self._cards.values():
            card.setParent(None)
            card.deleteLater()
        self._cards.clear()
        self._update_header()

        if self._empty_label is None:
            self._empty_label = QLabel("(no devices yet — start a capture)")
            self._empty_label.setStyleSheet("color: gray;")
            self.content_layout.insertWidget(0, self._empty_label)

    def _on_clear_clicked(self) -> None:
        self.registry.clear()

    def _update_header(self) -> None:
        self.header.setText(f"Devices — {len(self._cards)} discovered")
