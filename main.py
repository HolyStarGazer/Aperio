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
from scapy.all import ARP, IP, TCP, UDP, AsyncSniffer

TAB_NAMES = ["Dashboard", "Devices", "Topology", "Packets", "Scan"]
CAPTURE_INTERFACE = "Ethernet"


def decode_packet(pkt, number: int) -> dict:
    result = {
        "number": number,
        "timestamp": time.time(),
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


class CaptureThread(QThread):
    packet_captured = pyqtSignal(dict)

    def __init__(self, iface: str, parent=None):
        super().__init__(parent)
        self._iface = iface
        self._running = True
        self._counter = 0

    def run(self):
        sniffer = AsyncSniffer(
            iface=self._iface,
            prn=self._handle_packet,
            store=False,
        )
        sniffer.start()
        while self._running:
            self.msleep(100)
        sniffer.stop()

    def _handle_packet(self, pkt):
        self._counter += 1
        decoded = decode_packet(pkt, self._counter)
        self.packet_captured.emit(decoded)

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
        row = (
            f"#{packet['number']:<5} "
            f"{packet['protocol']:<8} "
            f"{packet['src_ip']:<18} → {packet['dst_ip']:<18} "
            f"| {packet['info']}"
        )
        self.list.addItem(row)
        self.header.setText(f"Packets — {packet['number']} captured")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Aperio")
        self.resize(1100, 700)

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

        self.capture_thread = CaptureThread(CAPTURE_INTERFACE, self)
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
