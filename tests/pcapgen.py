"""Kleiner pcap/pcapng-Schreiber fuer die Tests (ohne scapy).

Baut Ethernet-, IPv4-, IPv6-, TCP- und UDP-Header mit korrekten Pruefsummen,
die sich gezielt verfaelschen lassen.
"""
import gzip
import socket
import struct

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload, ethertype=0x0800, src=MAC_A, dst=MAC_B, vlan=None):
    header = dst + src
    if vlan is not None:
        header += struct.pack("!HH", 0x8100, vlan)
    return header + struct.pack("!H", ethertype) + payload


def tcp_segment(src, dst, sport, dport, flags, payload=b"", window=8192,
                seq=1, ack=0, bad_checksum=False, ipv6=False):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                         window, 0, 0)
    segment = header + payload
    pseudo = _pseudo(src, dst, 6, len(segment), ipv6)
    value = checksum(pseudo + segment)
    if bad_checksum:
        value ^= 0x00FF
    return segment[:16] + struct.pack("!H", value) + segment[18:]


def udp_datagram(src, dst, sport, dport, payload=b"", bad_checksum=False,
                 zero_checksum=False, ipv6=False, length=None):
    size = 8 + len(payload) if length is None else length
    datagram = struct.pack("!HHHH", sport, dport, size, 0) + payload
    if zero_checksum:
        return datagram
    value = checksum(_pseudo(src, dst, 17, 8 + len(payload), ipv6) + datagram) or 0xFFFF
    if bad_checksum:
        value ^= 0x00FF
    return datagram[:6] + struct.pack("!H", value) + datagram[8:]


def _pseudo(src, dst, proto, length, ipv6):
    if ipv6:
        return (socket.inet_pton(socket.AF_INET6, src)
                + socket.inet_pton(socket.AF_INET6, dst)
                + struct.pack("!I", length) + b"\x00\x00\x00" + bytes((proto,)))
    return (socket.inet_aton(src) + socket.inet_aton(dst)
            + struct.pack("!BBH", 0, proto, length))


def ipv4(src, dst, proto, payload, ttl=64, total_length=None, bad_checksum=False,
         flags_fragment=0, ihl=5):
    length = 20 + len(payload) if total_length is None else total_length
    header = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, length, 0,
                         flags_fragment, ttl, proto, 0, socket.inet_aton(src),
                         socket.inet_aton(dst))
    value = checksum(header)
    if bad_checksum:
        value ^= 0x00FF
    header = header[:10] + struct.pack("!H", value) + header[12:]
    return header + payload


def ipv6(src, dst, next_header, payload, hop_limit=64):
    return (struct.pack("!IHBB", 6 << 28, len(payload), next_header, hop_limit)
            + socket.inet_pton(socket.AF_INET6, src)
            + socket.inet_pton(socket.AF_INET6, dst) + payload)


def tcp_packet(src, dst, sport, dport, flags, payload=b"", **kwargs):
    """Ethernet + IPv4 + TCP mit korrekten Pruefsummen."""
    ip_kwargs = {key: kwargs.pop(key) for key in
                 ("ttl", "total_length", "flags_fragment") if key in kwargs}
    bad_ip = kwargs.pop("bad_ip_checksum", False)
    segment = tcp_segment(src, dst, sport, dport, flags, payload, **kwargs)
    return ethernet(ipv4(src, dst, 6, segment, bad_checksum=bad_ip, **ip_kwargs))


def udp_packet(src, dst, sport, dport, payload=b"", **kwargs):
    ip_kwargs = {key: kwargs.pop(key) for key in ("ttl",) if key in kwargs}
    datagram = udp_datagram(src, dst, sport, dport, payload, **kwargs)
    return ethernet(ipv4(src, dst, 17, datagram, **ip_kwargs))


def write_pcap(path, records, linktype=1, nanoseconds=False, endian="<",
               snaplen=65535, compress=False):
    """records: Liste aus (Zeit in s, Bytes) oder (Zeit, Bytes, orig_len)."""
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    scale = 1_000_000_000 if nanoseconds else 1_000_000
    chunks = [struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)]
    for record in records:
        ts, data = record[0], record[1]
        orig_len = record[2] if len(record) > 2 else len(data)
        ticks = round(ts * scale)
        seconds, fraction = divmod(ticks, scale)
        chunks.append(struct.pack(endian + "IIII", seconds, fraction, len(data),
                                  orig_len) + data)
    blob = b"".join(chunks)
    opener = gzip.open if compress else open
    with opener(path, "wb") as handle:
        handle.write(blob)


def _block(block_type, body):
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def write_pcapng(path, records, linktype=1, tsresol=9, tsoffset=0):
    """pcapng mit einem Interface; records wie bei write_pcap (Zeit in s)."""
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    options = struct.pack("<HHB", 9, 1, tsresol) + b"\x00\x00\x00"
    if tsoffset:
        options += struct.pack("<HHq", 14, 8, tsoffset)
    options += struct.pack("<HH", 0, 0)
    idb = _block(1, struct.pack("<HHI", linktype, 0, 262144) + options)
    blocks = [shb, idb]
    scale = 10 ** tsresol
    for record in records:
        ts, data = record[0], record[1]
        orig_len = record[2] if len(record) > 2 else len(data)
        ticks = round((ts - tsoffset) * scale)
        blocks.append(_block(6, struct.pack("<IIIII", 0, ticks >> 32,
                                            ticks & 0xFFFFFFFF, len(data),
                                            orig_len) + data))
    with open(path, "wb") as handle:
        handle.write(b"".join(blocks))


def tcp_connection(client, server, cport, sport, start, gap=0.01, payload=b"x" * 100):
    """Vollstaendige TCP-Verbindung: Handshake, Daten, beidseitiges FIN."""
    sequence = [
        (client, server, cport, sport, 0x02, b""),
        (server, client, sport, cport, 0x12, b""),
        (client, server, cport, sport, 0x10, b""),
        (client, server, cport, sport, 0x18, payload),
        (client, server, cport, sport, 0x11, b""),
        (server, client, sport, cport, 0x11, b""),
        (client, server, cport, sport, 0x10, b""),
    ]
    return [(start + index * gap, tcp_packet(src, dst, a, b, flags, data))
            for index, (src, dst, a, b, flags, data) in enumerate(sequence)]
