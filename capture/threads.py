import ipaddress
import queue
import socket
import time
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import ARP, AsyncSniffer, Ether, PcapReader, PcapWriter, srp

from capture.decoder import decode_packet, packet_matches_filter
from capture.files import CAPTURES_DIR, RECENT_CAPTURES_LIMIT, is_private_ip
from capture.nbns import query_nbns_hostname


class CaptureThread(QThread):
    packet_captured = pyqtSignal(dict)
    capture_finished = pyqtSignal()

    def __init__(
        self,
        iface: str,
        target: int | None = None,
        pcap_path: Path | None = None,
        append: bool = False,
        capture_filter: dict | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._iface = iface
        self._target = target
        self._pcap_path = pcap_path
        self._append = append
        self._filter = capture_filter or {}
        self._running = True
        self._count = 0
        self._writer: PcapWriter | None = None

    def run(self):
        if self._pcap_path is not None:
            self._writer = PcapWriter(
                str(self._pcap_path),
                append=self._append,
                sync=True,
            )

        sniffer = AsyncSniffer(
            iface=self._iface,
            prn=self._handle_packet,
            store=False,
        )
        sniffer.start()
        while self._running:
            self.msleep(100)
            if self._target is not None and self._count >= self._target:
                break
        sniffer.stop()

        if self._writer is not None:
            self._writer.close()
            self._writer = None

        self.capture_finished.emit()

    def _handle_packet(self, pkt):
        if self._target is not None and self._count >= self._target:
            return
        decoded = decode_packet(pkt)
        if not packet_matches_filter(decoded, self._filter):
            return
        self._count += 1
        if self._writer is not None:
            self._writer.write(pkt)
        self.packet_captured.emit(decoded)

    def stop(self):
        self._running = False
        self.wait()


class PcapLoaderThread(QThread):
    BATCH_SIZE = 250

    packets_batch_loaded = pyqtSignal(list)
    load_progress = pyqtSignal(int)
    load_finished = pyqtSignal(int)
    load_failed = pyqtSignal(str)

    def __init__(self, path: Path, parent=None):
        super().__init__(parent)
        self._path = path

    def run(self):
        count = 0
        batch: list[dict] = []
        try:
            with PcapReader(str(self._path)) as reader:
                for pkt in reader:
                    decoded = decode_packet(pkt)
                    batch.append(decoded)
                    count += 1
                    if len(batch) >= self.BATCH_SIZE:
                        self.packets_batch_loaded.emit(batch)
                        self.load_progress.emit(count)
                        batch = []
        except Exception as e:
            if batch:
                self.packets_batch_loaded.emit(batch)
            self.load_failed.emit(str(e))
            return
        if batch:
            self.packets_batch_loaded.emit(batch)
        self.load_progress.emit(count)
        self.load_finished.emit(count)


class RecentCapturesScanner(QThread):
    scan_complete = pyqtSignal(list)

    def __init__(self, limit: int = RECENT_CAPTURES_LIMIT, parent=None):
        super().__init__(parent)
        self._limit = limit

    def run(self):
        if not CAPTURES_DIR.exists():
            self.scan_complete.emit([])
            return

        files = sorted(
            CAPTURES_DIR.glob("*.pcap"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[: self._limit]

        results = []
        for path in files:
            try:
                count = 0
                with PcapReader(str(path)) as reader:
                    for _ in reader:
                        count += 1
            except Exception:
                count = -1
            results.append((path, count))

        self.scan_complete.emit(results)


class ArpScannerThread(QThread):
    MAX_HOSTS = 1024
    CHUNK_SIZE = 32
    CHUNK_TIMEOUT = 1

    device_discovered = pyqtSignal(dict)
    scan_progress = pyqtSignal(int, int)
    scan_complete = pyqtSignal(int)
    scan_failed = pyqtSignal(str)

    def __init__(self, iface: str, subnet: str, parent=None):
        super().__init__(parent)
        self._iface = iface
        self._subnet = subnet

    def run(self) -> None:
        try:
            network = ipaddress.ip_network(self._subnet, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        except ValueError as e:
            self.scan_failed.emit(f"Invalid subnet: {e}")
            return

        total = len(hosts)
        if total == 0:
            self.scan_complete.emit(0)
            return
        if total > self.MAX_HOSTS:
            self.scan_failed.emit(
                f"Subnet too large to scan ({total} hosts, limit {self.MAX_HOSTS})"
            )
            return

        self.scan_progress.emit(0, total)

        found = 0
        scanned = 0
        for chunk_start in range(0, total, self.CHUNK_SIZE):
            chunk = hosts[chunk_start : chunk_start + self.CHUNK_SIZE]
            try:
                requests = [
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in chunk
                ]
                answered, _unanswered = srp(
                    requests,
                    iface=self._iface,
                    timeout=self.CHUNK_TIMEOUT,
                    verbose=False,
                )
            except Exception as e:
                self.scan_failed.emit(str(e))
                return

            for _sent, received in answered:
                try:
                    src_ip = str(received.psrc)
                    src_mac = str(received.hwsrc)
                except Exception:
                    continue
                synthetic = {
                    "timestamp": float(time.time()),
                    "src_ip": src_ip,
                    "dst_ip": "",
                    "src_port": None,
                    "dst_port": None,
                    "src_mac": src_mac,
                    "dst_mac": "",
                    "protocol": "ARP",
                    "info": f"ARP scan reply from {src_ip}",
                    "length": len(received),
                    "_raw": received,
                }
                self.device_discovered.emit(synthetic)
                found += 1

            scanned += len(chunk)
            self.scan_progress.emit(scanned, total)

        self.scan_complete.emit(found)


class HostnameResolverThread(QThread):
    hostname_resolved = pyqtSignal(str, str)

    def __init__(self, hostname_cache, parent=None):
        super().__init__(parent)
        self._cache = hostname_cache
        self._queue: queue.Queue = queue.Queue()
        self._running = True
        self._ever_seen: set[str] = set()
        self._ever_resolved: set[str] = set()

    def stats(self) -> tuple[int, int]:
        return len(self._ever_seen), len(self._ever_resolved)

    def record_passive(self, ip: str, hostname: str) -> None:
        if not ip:
            return
        self._ever_seen.add(ip)
        if hostname and hostname != ip:
            self._ever_resolved.add(ip)

    def enqueue(self, ip: str) -> None:
        self._queue.put(ip)

    def pending_count(self) -> int:
        return self._queue.qsize()

    def run(self) -> None:
        while self._running:
            try:
                ip = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if ip is None:
                break

            cached = self._cache.get(ip)
            if cached is not None:
                self.hostname_resolved.emit(ip, cached)
                continue

            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
            except (socket.herror, socket.gaierror, OSError):
                hostname = ""

            if not hostname and is_private_ip(ip):
                try:
                    nbns_name = query_nbns_hostname(ip, timeout=1.5)
                except Exception:
                    nbns_name = ""
                if nbns_name:
                    hostname = nbns_name

            if not hostname:
                hostname = ip

            self._ever_seen.add(ip)
            if hostname and hostname != ip:
                self._ever_resolved.add(ip)
            else:
                self._ever_resolved.discard(ip)
            self.hostname_resolved.emit(ip, hostname)

    def stop(self) -> None:
        self._running = False
        self._queue.put(None)
        if not self.wait(2000):
            self.terminate()
            self.wait()
