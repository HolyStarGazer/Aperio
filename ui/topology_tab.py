from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from models.device_registry import DeviceRegistryModel
from ui.topology_canvas import TopologyCanvas


class TopologyTab(QWidget):
    view_packets_requested = pyqtSignal(str)

    def __init__(self, registry: DeviceRegistryModel, parent=None):
        super().__init__(parent)
        self.registry = registry

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header_bar = QHBoxLayout()
        header_bar.setContentsMargins(12, 12, 12, 8)

        self.header = QLabel("Topology")
        header_font = self.header.font()
        header_font.setPointSize(header_font.pointSize() + 2)
        header_font.setBold(True)
        self.header.setFont(header_font)

        self.reset_button = QPushButton("Reset layout")
        self.reset_button.setMaximumWidth(120)
        self.reset_button.setToolTip(
            "Reset zoom, pan, and node positions to the default fan layout.\n"
            "(Double-clicking the canvas does the same thing.)"
        )

        self.legend = QLabel(
            '<span style="color:#e67840">●</span> gateway'
            '&nbsp;&nbsp;&nbsp;'
            '<span style="color:#966edc">●</span> you'
            '&nbsp;&nbsp;&nbsp;'
            '<span style="color:#6496dc">●</span> local'
            '&nbsp;&nbsp;&nbsp;'
            '<span style="color:#64b464">●</span> multicast'
            '&nbsp;&nbsp;&nbsp;'
            '<span style="color:#b4b4b4">●</span> external'
            '&nbsp;&nbsp;&nbsp;&nbsp;'
            '<span style="color:#dcaa5a">- - -</span> peer traffic'
        )

        header_bar.addWidget(self.header)
        header_bar.addSpacing(12)
        header_bar.addWidget(self.reset_button)
        header_bar.addStretch()
        header_bar.addWidget(self.legend)

        self.canvas = TopologyCanvas(registry)
        self.canvas.view_packets_requested.connect(self.view_packets_requested.emit)
        self.reset_button.clicked.connect(self.canvas.reset_view)

        layout.addLayout(header_bar)
        layout.addWidget(self.canvas, stretch=1)

    def reset_layout(self) -> None:
        self.canvas.reset_view()
