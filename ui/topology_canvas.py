import random

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QWidget

from models.device_registry import Device, DeviceRegistryModel


def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0])
        b = int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    return False


def is_multicast_or_broadcast(ip: str) -> bool:
    if not ip:
        return False
    if ip == "255.255.255.255":
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0])
    except ValueError:
        return False
    return 224 <= a <= 239


COLOR_GATEWAY = QColor(230, 120, 60)
COLOR_SELF = QColor(150, 110, 220)
COLOR_LOCAL = QColor(100, 150, 220)
COLOR_MULTICAST = QColor(100, 180, 100)
COLOR_EXTERNAL = QColor(180, 180, 180)


def detect_network_context() -> tuple[str, str]:
    try:
        from scapy.all import conf
        result = conf.route.route("8.8.8.8")
        if not result or len(result) < 3:
            return "", ""
        _iface, src_ip, gateway_ip = result
        src_ip = src_ip or ""
        gateway_ip = gateway_ip or ""
        if src_ip == "0.0.0.0":
            src_ip = ""
        if gateway_ip == "0.0.0.0":
            gateway_ip = ""
        return src_ip, gateway_ip
    except Exception:
        return "", ""


class TopologyCanvas(QWidget):
    NODE_RADIUS = 22
    MARGIN = 70
    LABEL_HEIGHT = 20

    def __init__(self, registry: DeviceRegistryModel, parent=None):
        super().__init__(parent)
        self.registry = registry
        self._positions: dict[str, tuple[float, float]] = {}
        self._rng = random.Random(42)
        self._local_ip, self._gateway_ip = detect_network_context()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(200)
        self._refresh_timer.timeout.connect(self._recompute_layout)

        self.registry.topology_structure_changed.connect(self._schedule_refresh)
        self.registry.device_changed.connect(self._on_device_changed)
        self.registry.devices_cleared.connect(self._on_cleared)

        self.setMinimumSize(400, 300)

    def sizeHint(self) -> QSize:
        return QSize(800, 600)

    def _schedule_refresh(self) -> None:
        self._refresh_timer.start()

    def _on_device_changed(self, key: str) -> None:
        if key in self._positions:
            self.update()

    def _on_cleared(self) -> None:
        self._positions.clear()
        self.update()

    def _recompute_layout(self) -> None:
        try:
            import networkx as nx
        except ImportError:
            return

        devices = self.registry.all_devices()
        edges = self.registry.all_edges()

        if not devices:
            self._positions.clear()
            self.update()
            return

        graph = nx.Graph()
        device_keys = {d.key for d in devices}
        for key in device_keys:
            graph.add_node(key)
        for a, b in edges:
            if a in device_keys and b in device_keys:
                graph.add_edge(a, b)

        if self._positions:
            cx = sum(p[0] for p in self._positions.values()) / len(self._positions)
            cy = sum(p[1] for p in self._positions.values()) / len(self._positions)
        else:
            cx = cy = 0.0

        initial_pos: dict[str, tuple[float, float]] = {}
        for key in device_keys:
            if key in self._positions:
                initial_pos[key] = self._positions[key]
            else:
                initial_pos[key] = (
                    cx + self._rng.uniform(-0.3, 0.3),
                    cy + self._rng.uniform(-0.3, 0.3),
                )

        try:
            new_pos = nx.spring_layout(
                graph,
                pos=initial_pos,
                seed=42,
                iterations=30,
            )
        except Exception:
            return

        self._positions = {
            k: (float(v[0]), float(v[1])) for k, v in new_pos.items()
        }
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        bg = self.palette().base().color()
        painter.fillRect(self.rect(), bg)

        if not self._positions:
            self._draw_empty(painter)
            return

        devices_by_key = {d.key: d for d in self.registry.all_devices()}
        edges = self.registry.all_edges()

        gateway_key = None
        self_key = None
        for device in devices_by_key.values():
            if self._gateway_ip and device.ip == self._gateway_ip and gateway_key is None:
                gateway_key = device.key
            elif self._local_ip and device.ip == self._local_ip and self_key is None:
                self_key = device.key

        screen_pos = self._to_screen_coords()
        if not screen_pos:
            return

        edge_pen = QPen(QColor(140, 140, 140, 160), 1.5)
        painter.setPen(edge_pen)
        for a, b in edges:
            pa = screen_pos.get(a)
            pb = screen_pos.get(b)
            if pa is not None and pb is not None:
                painter.drawLine(pa, pb)

        label_font = QFont()
        label_font.setPointSize(9)
        painter.setFont(label_font)

        for key, pos in screen_pos.items():
            device = devices_by_key.get(key)
            if device is None:
                continue
            self._draw_node(
                painter,
                pos,
                device,
                is_gateway=(key == gateway_key),
                is_self=(key == self_key),
            )

    def _to_screen_coords(self) -> dict[str, QPointF]:
        if not self._positions:
            return {}

        usable_w = self.width() - 2 * self.MARGIN
        usable_h = self.height() - 2 * self.MARGIN - self.LABEL_HEIGHT
        if usable_w < 100 or usable_h < 100:
            return {}

        xs = [p[0] for p in self._positions.values()]
        ys = [p[1] for p in self._positions.values()]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        span_x = max_x - min_x if max_x > min_x else 1.0
        span_y = max_y - min_y if max_y > min_y else 1.0

        result: dict[str, QPointF] = {}
        for key, (x, y) in self._positions.items():
            sx = self.MARGIN + ((x - min_x) / span_x) * usable_w
            sy = self.MARGIN + ((y - min_y) / span_y) * usable_h
            result[key] = QPointF(sx, sy)
        return result

    def _draw_node(
        self,
        painter: QPainter,
        pos: QPointF,
        device: Device,
        is_gateway: bool,
        is_self: bool,
    ) -> None:
        color = self._node_color(device, is_gateway, is_self)
        painter.setBrush(color)
        painter.setPen(QPen(QColor(30, 30, 30), 1.5))
        painter.drawEllipse(pos, self.NODE_RADIUS, self.NODE_RADIUS)

        label = device.hostname or device.ip or device.mac or device.key
        if len(label) > 26:
            label = label[:25] + "…"

        label_rect = QRectF(
            pos.x() - 120,
            pos.y() + self.NODE_RADIUS + 4,
            240,
            self.LABEL_HEIGHT,
        )
        painter.setPen(self.palette().text().color())
        painter.drawText(
            label_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            label,
        )

    @staticmethod
    def _node_color(device: Device, is_gateway: bool, is_self: bool) -> QColor:
        if is_gateway:
            return COLOR_GATEWAY
        if is_self:
            return COLOR_SELF
        ip = device.ip
        if is_multicast_or_broadcast(ip):
            return COLOR_MULTICAST
        if ip and is_private_ip(ip):
            return COLOR_LOCAL
        if not ip:
            return COLOR_EXTERNAL
        return COLOR_EXTERNAL

    def _draw_empty(self, painter: QPainter) -> None:
        painter.setPen(self.palette().text().color())
        painter.drawText(
            self.rect(),
            Qt.AlignmentFlag.AlignCenter,
            "(no topology yet — start a capture)",
        )
