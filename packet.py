import socket

from scapy.all import sniff, IP, TCP, UDP

hostname_cache = {}

PORT_NAMES = {
    # (protocol, port): service name
    ("TCP", 20): "FTP Data",
    ("TCP", 21): "FTP Control",
    ("TCP", 22): "SSH/SFTP",
    ("TCP", 23): "Telnet",
    ("TCP", 25): "SMTP",
    ("TCP", 53): "DNS",
    ("UDP", 53): "DNS",
    ("TCP", 67): "DHCP Server",
    ("UDP", 67): "DHCP Server",
    ("TCP", 68): "DHCP Client",
    ("UDP", 68): "DHCP Client",
    ("UDP", 69): "TFTP",
    ("TCP", 80): "HTTP",
    ("TCP", 110): "POP3",
    ("TCP", 123): "NTP",
    ("UDP", 123): "NTP",
    ("TCP", 143): "IMAP",
    ("TCP", 161): "SNMP",
    ("UDP", 161): "SNMP",
    ("UDP", 162): "SNMP Trap",
    ("TCP", 389): "LDAP",
    ("TCP", 443): "HTTPS",
    ("UDP", 443): "QUIC/HTTPS",
    ("TCP", 445): "SMB",
    ("UDP", 514): "Syslog",
    ("TCP", 587): "SMTP TLS",
    ("TCP", 636): "LDAPS",
    ("UDP", 1900): "SSDP/UPnP",
    ("TCP", 1433): "MSSQL",
    ("TCP", 3389): "RDP",
    ("TCP", 5060): "SIP",
    ("TCP", 5061): "SIP TLS",
    ("UDP", 5353): "mDNS",
    ("TCP", 5353): "mDNS",
    ("UDP", 6667): "UPnP",
}

def get_service(protocol, port):
    return PORT_NAMES.get((protocol, port), str(port))

def resolve_hostname(ip):
    if ip in hostname_cache:
        return hostname_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        hostname_cache[ip] = hostname
        return hostname
    except socket.herror:
        hostname_cache[ip] = ip  # cache the failure too
        return ip

def handle_packet(packet):
    if packet.haslayer(IP):
        src_ip = resolve_hostname(packet[IP].src)
        dst_ip = resolve_hostname(packet[IP].dst)
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            src_service = get_service("TCP", src_port)
            dst_service = get_service("TCP", dst_port)
            print(f"TCP | {src_ip}:{src_service} > {dst_ip}:{dst_service} | Flags: {flags}")
            
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            src_service = get_service("UDP", src_port)
            dst_service = get_service("UDP", dst_port)
            print(f"UDP | {src_ip}:{src_service} > {dst_ip}:{dst_service}")
    print("- - -")
    print(packet.summary())

sniff(iface="Ethernet", prn=handle_packet, count=20)