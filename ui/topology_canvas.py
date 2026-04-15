import math
import random

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QWidget

from capture.files import (
    detect_network_context,
    is_multicast_or_broadcast,
    is_private_ip,
)
from models.device_registry import Device, DeviceRegistryModel


COLOR_GATEWAY = QColor(230, 120, 60)
COLOR_SELF = QColor(150, 110, 220)
COLOR_LOCAL = QColor(100, 150, 220)
COLOR_MULTICAST = QColor(100, 180, 100)
COLOR_EXTERNAL = QColor(180, 180, 180)


class TopologyCanvas(QWidget):
    view_packets_requested = pyqtSignal(str)

    NODE_RADIUS = 22
    MARGIN = 70
    LABEL_HEIGHT = 20
    DRAG_THRESHOLD = 5

    def __init__(self, registry: DeviceRegistryModel, parent=None):
        super().__init__(parent)
        self.registry = registry
        self._positions: dict[str, tuple[float, float]] = {}
        self._graph_edges: list[tuple[str, str]] = []
        self._graph_edges_secondary: list[tuple[str, str]] = []
        self._layout_bounds: tuple[float, float, float, float] = (-1.0, 1.0, -1.0, 1.0)
        self._rng = random.Random(42)
        self._local_ip, self._gateway_ip = detect_network_context()

        self._zoom: float = 1.0
        self._pan_offset: QPointF = QPointF(0, 0)
        self._press_pos: QPointF | None = None
        self._last_move_pos: QPointF | None = None
        self._press_node: str | None = None
        self._press_node_offset: tuple[float, float] = (0.0, 0.0)
        self._drag_mode: str | None = None

        self.setMouseTracking(True)

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

    def _classify(
        self,
        devices: list[Device],
    ) -> tuple[str | None, str | None, list[str], list[str], list[str]]:
        gateway_key: str | None = None
        self_key: str | None = None
        local_keys: list[str] = []
        external_keys: list[str] = []
        multicast_keys: list[str] = []

        for device in devices:
            ip = device.ip
            if self._gateway_ip and ip == self._gateway_ip:
                gateway_key = device.key
                continue
            if self._local_ip and ip == self._local_ip:
                self_key = device.key
                continue
            if is_multicast_or_broadcast(ip):
                multicast_keys.append(device.key)
                continue
            if ip and not is_private_ip(ip):
                external_keys.append(device.key)
                continue
            local_keys.append(device.key)

        return gateway_key, self_key, local_keys, external_keys, multicast_keys

    def _build_edges(
        self,
        devices: list[Device],
    ) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        gateway, self_key, locals_, externals, _multicasts = self._classify(devices)
        primary: list[tuple[str, str]] = []
        secondary: list[tuple[str, str]] = []

        if gateway is not None:
            if self_key is not None and self_key != gateway:
                primary.append((gateway, self_key))
            for key in locals_:
                primary.append((gateway, key))
            for key in externals:
                primary.append((gateway, key))

            lan_keys = set(locals_)
            if self_key is not None:
                lan_keys.add(self_key)
            seen_secondary: set[tuple[str, str]] = set()
            for a, b in self.registry.all_edges():
                if a == b or a not in lan_keys or b not in lan_keys:
                    continue
                canonical = (a, b) if a < b else (b, a)
                if canonical in seen_secondary:
                    continue
                seen_secondary.add(canonical)
                secondary.append((a, b))
        else:
            device_keys = {d.key for d in devices}
            for a, b in self.registry.all_edges():
                if a in device_keys and b in device_keys:
                    primary.append((a, b))

        return primary, secondary

    @staticmethod
    def _fan_positions(
        keys: list[str],
        direction: int,
        start_radius: float = 0.85,
        ring_step: float = 0.34,
        spacing: float = 0.26,
        angle_start: float = math.pi / 6,
        angle_end: float = 5 * math.pi / 6,
    ) -> dict[str, tuple[float, float]]:
        if not keys:
            return {}
        positions: dict[str, tuple[float, float]] = {}
        remaining = list(keys)
        radius = start_radius
        angle_range = angle_end - angle_start
        while remaining:
            arc_length = angle_range * radius
            capacity = max(1, int(arc_length / spacing))
            ring_keys = remaining[:capacity]
            remaining = remaining[capacity:]
            n = len(ring_keys)
            for i, key in enumerate(ring_keys):
                if n == 1:
                    theta = (angle_start + angle_end) / 2
                else:
                    theta = angle_start + angle_range * (i + 0.5) / n
                x = radius * math.cos(theta)
                y = direction * radius * math.sin(theta)
                positions[key] = (x, y)
            radius += ring_step
        return positions

    def _manual_layout(
        self,
        devices: list[Device],
    ) -> dict[str, tuple[float, float]]:
        gateway, self_key, locals_, externals, multicasts = self._classify(devices)
        positions: dict[str, tuple[float, float]] = {}

        if gateway is not None:
            positions[gateway] = (0.0, 0.0)

        if self_key is not None:
            positions[self_key] = (0.0, -0.45)

        positions.update(
            self._fan_positions(
                locals_,
                direction=-1,
                start_radius=0.85,
                ring_step=0.34,
                spacing=0.26,
            )
        )

        positions.update(
            self._fan_positions(
                externals,
                direction=+1,
                start_radius=0.85,
                ring_step=0.34,
                spacing=0.26,
            )
        )

        if multicasts:
            n = len(multicasts)
            span = 1.8
            step = span / max(n - 1, 1) if n > 1 else 0.0
            y0 = -0.9 if n > 1 else 0.0
            for i, key in enumerate(multicasts):
                positions[key] = (-1.55, y0 + step * i)

        return positions

    def _spring_layout_fallback(
        self,
        devices: list[Device],
    ) -> dict[str, tuple[float, float]]:
        try:
            import networkx as nx
        except ImportError:
            return {}

        graph = nx.Graph()
        for device in devices:
            graph.add_node(device.key)
        device_keys = {d.key for d in devices}
        for a, b in self.registry.all_edges():
            if a in device_keys and b in device_keys:
                graph.add_edge(a, b)

        try:
            new_pos = nx.spring_layout(graph, seed=42, iterations=50)
        except Exception:
            return {}
        return {k: (float(v[0]), float(v[1])) for k, v in new_pos.items()}

    def _recompute_layout(self) -> None:
        devices = self.registry.all_devices()
        if not devices:
            self._positions.clear()
            self._graph_edges = []
            self._graph_edges_secondary = []
            self.update()
            return

        self._graph_edges, self._graph_edges_secondary = self._build_edges(devices)

        if self._gateway_ip:
            fresh = self._manual_layout(devices)
        else:
            fresh = self._spring_layout_fallback(devices)

        preserved: dict[str, tuple[float, float]] = {}
        for device in devices:
            if device.key in self._positions:
                preserved[device.key] = self._positions[device.key]
            elif device.key in fresh:
                preserved[device.key] = fresh[device.key]
        self._positions = preserved

        if fresh:
            xs = [p[0] for p in fresh.values()]
            ys = [p[1] for p in fresh.values()]
            self._layout_bounds = (min(xs), max(xs), min(ys), max(ys))

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

        labels = self._compute_labels(devices_by_key)

        if self._graph_edges_secondary:
            dashed_pen = QPen(QColor(220, 170, 90, 200), 1.4)
            dashed_pen.setStyle(Qt.PenStyle.DashLine)
            painter.setPen(dashed_pen)
            for a, b in self._graph_edges_secondary:
                pa = screen_pos.get(a)
                pb = screen_pos.get(b)
                if pa is not None and pb is not None:
                    painter.drawLine(pa, pb)

        edge_pen = QPen(QColor(140, 140, 140, 110), 1.2)
        painter.setPen(edge_pen)
        for a, b in self._graph_edges:
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
                labels.get(key, ""),
                is_gateway=(key == gateway_key),
                is_self=(key == self_key),
            )

    @staticmethod
    def _compute_labels(devices_by_key: dict[str, Device]) -> dict[str, str]:
        prelim: dict[str, str] = {}
        for key, device in devices_by_key.items():
            prelim[key] = device.hostname or device.ip or device.mac or key

        counts: dict[str, int] = {}
        for label in prelim.values():
            counts[label] = counts.get(label, 0) + 1

        final: dict[str, str] = {}
        for key, device in devices_by_key.items():
            label = prelim[key]
            if counts[label] > 1:
                if device.ip:
                    label = f"{label} ({device.ip})"
                elif device.mac:
                    label = f"{label} [{device.mac[-8:]}]"
            if len(label) > 30:
                label = label[:29] + "…"
            final[key] = label
        return final

    def _layout_to_screen(self, lx: float, ly: float) -> QPointF:
        min_x, max_x, min_y, max_y = self._layout_bounds
        span_x = max_x - min_x if (max_x - min_x) > 1e-3 else 1.0
        span_y = max_y - min_y if (max_y - min_y) > 1e-3 else 1.0
        usable_w = max(self.width() - 2 * self.MARGIN, 1)
        usable_h = max(self.height() - 2 * self.MARGIN - self.LABEL_HEIGHT, 1)
        bx = self.MARGIN + ((lx - min_x) / span_x) * usable_w
        by = self.MARGIN + ((ly - min_y) / span_y) * usable_h
        cx = self.width() / 2
        cy = self.height() / 2
        sx = cx + (bx - cx) * self._zoom + self._pan_offset.x()
        sy = cy + (by - cy) * self._zoom + self._pan_offset.y()
        return QPointF(sx, sy)

    def _screen_to_layout(self, sx: float, sy: float) -> tuple[float, float]:
        min_x, max_x, min_y, max_y = self._layout_bounds
        span_x = max_x - min_x if (max_x - min_x) > 1e-3 else 1.0
        span_y = max_y - min_y if (max_y - min_y) > 1e-3 else 1.0
        usable_w = max(self.width() - 2 * self.MARGIN, 1)
        usable_h = max(self.height() - 2 * self.MARGIN - self.LABEL_HEIGHT, 1)
        cx = self.width() / 2
        cy = self.height() / 2
        bx = cx + (sx - cx - self._pan_offset.x()) / self._zoom
        by = cy + (sy - cy - self._pan_offset.y()) / self._zoom
        lx = min_x + ((bx - self.MARGIN) / usable_w) * span_x
        ly = min_y + ((by - self.MARGIN) / usable_h) * span_y
        return lx, ly

    def _to_screen_coords(self) -> dict[str, QPointF]:
        if not self._positions:
            return {}
        usable_w = self.width() - 2 * self.MARGIN
        usable_h = self.height() - 2 * self.MARGIN - self.LABEL_HEIGHT
        if usable_w < 100 or usable_h < 100:
            return {}
        return {
            key: self._layout_to_screen(x, y)
            for key, (x, y) in self._positions.items()
        }

    def _hit_test(self, point: QPointF) -> str | None:
        screen_pos = self._to_screen_coords()
        r_sq = self.NODE_RADIUS * self.NODE_RADIUS
        for key, pos in screen_pos.items():
            dx = point.x() - pos.x()
            dy = point.y() - pos.y()
            if dx * dx + dy * dy <= r_sq:
                return key
        return None

    def mousePressEvent(self, event) -> None:
        if event.button() != Qt.MouseButton.LeftButton:
            return
        pos = event.position()
        self._press_pos = pos
        self._last_move_pos = pos
        self._press_node = self._hit_test(pos)
        self._drag_mode = None
        if self._press_node is not None:
            screen_pos = self._to_screen_coords().get(self._press_node)
            if screen_pos is not None:
                self._press_node_offset = (
                    pos.x() - screen_pos.x(),
                    pos.y() - screen_pos.y(),
                )

    def mouseMoveEvent(self, event) -> None:
        pos = event.position()
        if self._press_pos is None:
            if self._hit_test(pos) is not None:
                self.setCursor(Qt.CursorShape.PointingHandCursor)
            else:
                self.setCursor(Qt.CursorShape.ArrowCursor)
            return

        if self._drag_mode is None:
            dx = pos.x() - self._press_pos.x()
            dy = pos.y() - self._press_pos.y()
            if dx * dx + dy * dy > self.DRAG_THRESHOLD * self.DRAG_THRESHOLD:
                self._drag_mode = "node" if self._press_node else "pan"
                if self._drag_mode == "pan":
                    self.setCursor(Qt.CursorShape.ClosedHandCursor)
                else:
                    self.setCursor(Qt.CursorShape.SizeAllCursor)

        if self._drag_mode == "node" and self._press_node is not None:
            target_x = pos.x() - self._press_node_offset[0]
            target_y = pos.y() - self._press_node_offset[1]
            lx, ly = self._screen_to_layout(target_x, target_y)
            self._positions[self._press_node] = (lx, ly)
            self.update()
        elif self._drag_mode == "pan" and self._last_move_pos is not None:
            delta = pos - self._last_move_pos
            self._pan_offset = QPointF(
                self._pan_offset.x() + delta.x(),
                self._pan_offset.y() + delta.y(),
            )
            self.update()

        self._last_move_pos = pos

    def mouseReleaseEvent(self, event) -> None:
        if event.button() != Qt.MouseButton.LeftButton:
            return
        was_click = self._drag_mode is None and self._press_node is not None
        clicked_key = self._press_node if was_click else None

        self._press_pos = None
        self._last_move_pos = None
        self._press_node = None
        self._drag_mode = None
        self.setCursor(Qt.CursorShape.ArrowCursor)

        if clicked_key is not None:
            device = self.registry.get_device(clicked_key)
            if device is not None and device.ip:
                self.view_packets_requested.emit(device.ip)

    def mouseDoubleClickEvent(self, event) -> None:
        if event.button() != Qt.MouseButton.LeftButton:
            return
        self.reset_view()

    def reset_view(self) -> None:
        self._zoom = 1.0
        self._pan_offset = QPointF(0, 0)
        self._positions.clear()
        self._recompute_layout()

    def wheelEvent(self, event) -> None:
        delta = event.angleDelta().y()
        if delta == 0:
            return
        old_zoom = self._zoom
        factor = 1.15 if delta > 0 else 1.0 / 1.15
        new_zoom = max(0.2, min(5.0, old_zoom * factor))
        if new_zoom == old_zoom:
            return

        cursor = event.position()
        cx = self.width() / 2
        cy = self.height() / 2
        scale = new_zoom / old_zoom
        self._pan_offset = QPointF(
            (cursor.x() - cx) * (1 - scale) + self._pan_offset.x() * scale,
            (cursor.y() - cy) * (1 - scale) + self._pan_offset.y() * scale,
        )
        self._zoom = new_zoom
        self.update()

    def _draw_node(
        self,
        painter: QPainter,
        pos: QPointF,
        device: Device,
        label: str,
        is_gateway: bool,
        is_self: bool,
    ) -> None:
        color = self._node_color(device, is_gateway, is_self)
        painter.setBrush(color)
        painter.setPen(QPen(QColor(30, 30, 30), 1.5))
        painter.drawEllipse(pos, self.NODE_RADIUS, self.NODE_RADIUS)

        label_rect = QRectF(
            pos.x() - 140,
            pos.y() + self.NODE_RADIUS + 4,
            280,
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
