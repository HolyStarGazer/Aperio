from PyQt6.QtWidgets import QHeaderView, QTreeWidget, QTreeWidgetItem


LAYER_TOOLTIPS = {
    "Ethernet": (
        "Layer 2 (Data Link) — frames transmitted on the local network "
        "segment, addressed by 48-bit MAC addresses."
    ),
    "IP": (
        "Layer 3 (Network) — IPv4 packets routed between networks by IP "
        "address. Fragmentable, best-effort delivery."
    ),
    "IPv6": "Layer 3 (Network) — IPv6 packets with 128-bit addresses.",
    "TCP": (
        "Layer 4 (Transport) — reliable, ordered, connection-based byte "
        "stream. Uses a three-way handshake (SYN, SYN-ACK, ACK), flow "
        "control via window sizes, and acknowledgments for every byte."
    ),
    "UDP": (
        "Layer 4 (Transport) — unreliable, connectionless datagrams. "
        "Faster and lower-overhead than TCP, but no delivery guarantees, "
        "no ordering, and no retransmission."
    ),
    "ICMP": (
        "Layer 3 control messages. Used by ping (echo request/reply) and "
        "traceroute (TTL-exceeded responses)."
    ),
    "ARP": (
        "Address Resolution Protocol — maps IP addresses to MAC addresses "
        "on the local network. Operates at the Layer 2/3 boundary."
    ),
    "DNS": "Application layer — resolves hostnames to IP addresses.",
    "Raw": (
        "Unparsed payload bytes. Either an unknown protocol Scapy does not "
        "decode, or the actual application data (HTTP body, TLS records, "
        "etc.)."
    ),
    "Padding": "Zero bytes appended to meet minimum frame size on the wire.",
}

FIELD_TOOLTIPS = {
    ("Ethernet", "dst"): (
        "Destination MAC address. ff:ff:ff:ff:ff:ff is broadcast — "
        "delivered to every device on the local segment."
    ),
    ("Ethernet", "src"): (
        "Source MAC address — the hardware address of the sending interface."
    ),
    ("Ethernet", "type"): (
        "EtherType. 0x0800 = IPv4, 0x86dd = IPv6, 0x0806 = ARP, "
        "0x8100 = 802.1Q VLAN tag."
    ),
    ("IP", "version"): "IP version — 4 for IPv4, 6 for IPv6.",
    ("IP", "ihl"): (
        "Internet Header Length, in 32-bit words. Usually 5 (20 bytes)."
    ),
    ("IP", "tos"): (
        "Type of Service (now DSCP + ECN). Marks packets for QoS handling."
    ),
    ("IP", "len"): "Total packet length in bytes, including header and payload.",
    ("IP", "id"): "Identification, used to reassemble fragmented packets.",
    ("IP", "flags"): (
        "Fragmentation flags. DF = Don't Fragment, MF = More Fragments."
    ),
    ("IP", "frag"): "Fragment offset in 8-byte units, used during reassembly.",
    ("IP", "ttl"): (
        "Time To Live — decremented by 1 at each router hop. When it "
        "reaches 0 the packet is discarded. Prevents packets from looping "
        "forever."
    ),
    ("IP", "proto"): (
        "Upper-layer protocol number. 6 = TCP, 17 = UDP, 1 = ICMP, "
        "2 = IGMP."
    ),
    ("IP", "chksum"): (
        "Header checksum (not payload). Recomputed at each router because "
        "the TTL field changes."
    ),
    ("IP", "src"): "Source IP address — the sender.",
    ("IP", "dst"): "Destination IP address — the intended recipient.",
    ("TCP", "sport"): "Source port.",
    ("TCP", "dport"): (
        "Destination port. Well-known: 80 HTTP, 443 HTTPS, 22 SSH, "
        "25 SMTP, 53 DNS, 3389 RDP."
    ),
    ("TCP", "seq"): (
        "Sequence number — position of this segment's first byte in the "
        "sender's byte stream."
    ),
    ("TCP", "ack"): (
        "Acknowledgment number — the next sequence number the sender "
        "expects to receive. Valid only when the ACK flag is set."
    ),
    ("TCP", "dataofs"): (
        "Data offset (TCP header length) in 32-bit words. Usually 5 (20 "
        "bytes) unless TCP options are present."
    ),
    ("TCP", "reserved"): "Reserved for future use, should be 0.",
    ("TCP", "flags"): (
        "TCP flags. SYN initiates a connection, ACK acknowledges received "
        "data, FIN gracefully ends a connection, RST forces a close, PSH "
        "pushes buffered data to the application, URG marks urgent data."
    ),
    ("TCP", "window"): (
        "Window size — how many more bytes the sender is willing to receive. "
        "This is how TCP does flow control."
    ),
    ("TCP", "chksum"): (
        "Checksum over the TCP header, payload, and a pseudo-header "
        "from the IP layer."
    ),
    ("TCP", "urgptr"): (
        "Urgent pointer — offset to urgent data. Valid only when URG is set."
    ),
    ("TCP", "options"): (
        "TCP options: MSS, window scale, SACK, timestamps, etc."
    ),
    ("UDP", "sport"): "Source port.",
    ("UDP", "dport"): (
        "Destination port. Well-known: 53 DNS, 67/68 DHCP, 123 NTP, "
        "5353 mDNS, 1900 SSDP/UPnP."
    ),
    ("UDP", "len"): "Length of UDP header and payload in bytes.",
    ("UDP", "chksum"): (
        "Checksum over UDP header, payload, and a pseudo-header from IP. "
        "Optional in IPv4, mandatory in IPv6."
    ),
    ("ARP", "hwtype"): "Hardware type. 1 = Ethernet.",
    ("ARP", "ptype"): "Protocol type. 0x0800 = IPv4.",
    ("ARP", "hwlen"): "Hardware address length in bytes. 6 for MAC.",
    ("ARP", "plen"): "Protocol address length in bytes. 4 for IPv4.",
    ("ARP", "op"): "Operation. 1 = request (who-has), 2 = reply (is-at).",
    ("ARP", "hwsrc"): "Sender hardware (MAC) address.",
    ("ARP", "psrc"): "Sender protocol (IP) address.",
    ("ARP", "hwdst"): (
        "Target hardware (MAC) address. All zeros in a request (unknown)."
    ),
    ("ARP", "pdst"): (
        "Target protocol (IP) address — the IP being resolved to a MAC."
    ),
    ("ICMP", "type"): (
        "ICMP message type. 0 = echo reply, 3 = destination unreachable, "
        "8 = echo request (ping), 11 = time exceeded (used by traceroute)."
    ),
    ("ICMP", "code"): (
        "Further qualifies the type. For type 3: 0 = network unreachable, "
        "1 = host unreachable, 3 = port unreachable."
    ),
    ("ICMP", "chksum"): "Checksum over the ICMP header and data.",
}


class PacketDetailView(QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Field", "Value"])
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)

        header = self.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.setColumnWidth(0, 220)

        self._show_placeholder("(select a packet)")

    def show_packet(self, packet: dict | None) -> None:
        self.clear()
        if packet is None:
            self._show_placeholder("(select a packet)")
            return
        raw = packet.get("_raw")
        if raw is None:
            self._show_placeholder("(no raw packet data)")
            return
        self._populate(raw)
        self.expandAll()

    def _show_placeholder(self, text: str) -> None:
        self.addTopLevelItem(QTreeWidgetItem([text, ""]))

    def _populate(self, pkt) -> None:
        current = pkt
        while current is not None:
            name = current.name
            if name == "NoPayload":
                break
            if not hasattr(current, "fields_desc"):
                break

            layer_item = QTreeWidgetItem([name, ""])
            layer_tooltip = LAYER_TOOLTIPS.get(name)
            if layer_tooltip:
                layer_item.setToolTip(0, layer_tooltip)
                layer_item.setToolTip(1, layer_tooltip)

            for field in current.fields_desc:
                field_name = field.name
                try:
                    value = current.getfieldval(field_name)
                except Exception:
                    value = None
                value_str = self._format_value(value)
                field_item = QTreeWidgetItem([field_name, value_str])
                field_tooltip = FIELD_TOOLTIPS.get((name, field_name))
                if field_tooltip:
                    field_item.setToolTip(0, field_tooltip)
                    field_item.setToolTip(1, field_tooltip)
                layer_item.addChild(field_item)

            self.addTopLevelItem(layer_item)

            if not hasattr(current, "payload"):
                break
            next_layer = current.payload
            if next_layer is None or next_layer.name == "NoPayload":
                break
            current = next_layer

    @staticmethod
    def _format_value(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            if not value:
                return ""
            if len(value) > 32:
                return value[:32].hex(" ") + f" … ({len(value)} bytes)"
            return value.hex(" ")
        if isinstance(value, (list, tuple)):
            if not value:
                return "[]"
            return ", ".join(str(v) for v in value)
        return str(value)
