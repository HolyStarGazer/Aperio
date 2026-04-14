import sys
import time

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

TAB_NAMES = ["Dashboard", "Devices", "Topology", "Packets", "Scan"]


class CaptureThread(QThread):
    packet_captured = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True
        self._counter = 0

    def run(self):
        while self._running:
            self._counter += 1
            fake_packet = {
                "number": self._counter,
                "timestamp": time.time(),
                "src_ip": "192.168.86.72",
                "dst_ip": "192.168.86.1",
                "protocol": "TCP",
                "info": f"fake packet #{self._counter}",
            }
            self.packet_captured.emit(fake_packet)
            self.msleep(1000)

    def stop(self):
        self._running = False
        self.wait()


class PacketsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        self.header = QLabel("Packets — 0 captured")
        self.list = QListWidget()

        layout.addWidget(self.header)
        layout.addWidget(self.list)

    def on_packet_received(self, packet: dict):
        row = f"#{packet['number']}  {packet['protocol']}  {packet['src_ip']} → {packet['dst_ip']}  |  {packet['info']}"
        self.list.addItem(row)
        self.header.setText(f"Packets — {packet['number']} captured")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Aperio")
        self.resize(1000, 700)

        self.packets_tab = PacketsTab()

        self.content = QStackedWidget()
        for name in TAB_NAMES:
            if name == "Packets":
                self.content.addWidget(self.packets_tab)
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

        self.capture_thread = CaptureThread(self)
        self.capture_thread.packet_captured.connect(self.packets_tab.on_packet_received)
        self.capture_thread.start()

    def closeEvent(self, event):
        self.capture_thread.stop()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
