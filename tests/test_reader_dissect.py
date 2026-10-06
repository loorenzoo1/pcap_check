"""Lesen von pcap/pcapng und Zerlegen der Header."""
import random
import struct

import pytest

import pcap_check as pc
import pcapgen as g


def read_all(path):
    reader = pc.CaptureReader(path)
    records = list(reader)
    reader.finish()
    return reader, records


@pytest.mark.parametrize("nanoseconds", [False, True])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcap_variants(tmp_path, nanoseconds, endian):
    path = tmp_path / "a.pcap"
    packet = g.tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, 0x02)
    g.write_pcap(path, [(1500000000.123456, packet)], nanoseconds=nanoseconds,
                 endian=endian)
    reader, records = read_all(str(path))
    assert reader.format == "pcap"
    assert reader.resolutions == {"ns" if nanoseconds else "us"}
    assert reader.link_types == {1}
    assert len(records) == 1
    linktype, ts, wirelen, data, fcs = records[0]
    assert ts == 1500000000123456000
    assert data == packet and wirelen == len(packet)
    assert len(reader.sha256) == 64


def test_pcapng_resolution_and_offset(tmp_path):
    path = tmp_path / "a.pcapng"
    packet = g.tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, 0x02)
    g.write_pcapng(path, [(1600000000.000000123, packet)], tsresol=9)
    reader, records = read_all(str(path))
    assert reader.format == "pcapng"
    assert reader.snaplen == 262144
    assert records[0][1] // 1000 == 1600000000000000      # ns-genau bis auf float
    g.write_pcapng(path, [(1000.5, packet)], tsresol=6, tsoffset=1000)
    _, records = read_all(str(path))
    assert records[0][1] == 1000_500_000_000


def test_gzip_and_hash_covers_whole_file(tmp_path):
    import hashlib
    path = tmp_path / "a.pcap.gz"
    packets = [(i, g.tcp_packet("10.0.0.1", "10.0.0.2", 1000 + i, 80, 0x02))
               for i in range(5)]
    g.write_pcap(path, packets, compress=True)
    reader, records = read_all(str(path))
    assert reader.compressed and len(records) == 5
    assert reader.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_hash_with_read_limit(tmp_path):
    import hashlib
    path = tmp_path / "a.pcap"
    g.write_pcap(path, [(i, g.tcp_packet("10.0.0.1", "10.0.0.2", 1, 80, 0x02))
                        for i in range(50)])
    analysis = pc.analyze(str(path), pc.Options(max_packets=3))
    assert analysis.read_limited and analysis.records == 3
    assert analysis.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_truncated_file_is_reported(tmp_path):
    path = tmp_path / "a.pcap"
    g.write_pcap(path, [(1, g.tcp_packet("10.0.0.1", "10.0.0.2", 1, 80, 0x02))] * 3)
    path.write_bytes(path.read_bytes()[:-10])
    reader, records = read_all(str(path))
    assert len(records) == 2
    assert reader.issues["datei_endet_im_record"] == 1


def test_unknown_format(tmp_path):
    path = tmp_path / "a.pcap"
    path.write_bytes(b"hello world, kein pcap")
    analysis = pc.analyze(str(path), pc.Options())
    assert analysis.error and "unbekanntes Dateiformat" in analysis.error


def test_dissect_ipv4_tcp_with_vlan():
    segment = g.tcp_segment("10.0.0.1", "10.0.0.2", 40000, 80, 0x18, b"hello")
    frame = g.ethernet(g.ipv4("10.0.0.1", "10.0.0.2", 6, segment), vlan=7)
    packet = pc.dissect(1, frame)
    assert packet.l2 == "ethernet" and packet.vlan == 1
    assert packet.l3 == "ipv4" and packet.proto == 6
    assert (packet.sport, packet.dport) == (40000, 80)
    assert packet.tcp_flags == 0x18 and packet.payload_len == 5
    assert packet.ip_checksum_ok and packet.l4_checksum_ok
    assert not packet.structure_errors


def test_dissect_bad_checksums():
    frame = g.tcp_packet("10.0.0.1", "10.0.0.2", 1, 80, 0x02,
                         bad_checksum=True, bad_ip_checksum=True)
    packet = pc.dissect(1, frame)
    assert packet.ip_checksum_ok is False
    assert packet.l4_checksum_ok is False
    assert packet.l4_expected is not None


def test_udp_zero_checksum_ipv4_allowed_ipv6_not():
    frame = g.udp_packet("10.0.0.1", "10.0.0.2", 5000, 53, b"abc", zero_checksum=True)
    packet = pc.dissect(1, frame)
    assert packet.udp_zero_checksum and packet.l4_checksum_ok is None
    assert not packet.structure_errors
    datagram = g.udp_datagram("fe80::1", "fe80::2", 5000, 53, b"abc",
                              zero_checksum=True, ipv6=True)
    frame6 = g.ethernet(g.ipv6("fe80::1", "fe80::2", 17, datagram), ethertype=0x86DD)
    packet6 = pc.dissect(1, frame6)
    assert "udp_pruefsumme_null_bei_ipv6" in packet6.structure_errors


def test_ipv6_udp_checksum_and_hop_by_hop():
    datagram = g.udp_datagram("2001:db8::1", "2001:db8::2", 5683, 5683, b"coap",
                              ipv6=True)
    # Hop-by-Hop-Header (8 Byte) vor UDP; Pseudo-Header nutzt next=17
    hop = bytes((17, 0)) + b"\x00" * 6
    frame = g.ethernet(g.ipv6("2001:db8::1", "2001:db8::2", 0, hop + datagram),
                       ethertype=0x86DD)
    packet = pc.dissect(1, frame)
    assert packet.l3 == "ipv6" and packet.proto == 17
    assert packet.l4_checksum_ok is True
    assert packet.total_len == 40 + 8 + len(datagram)


def test_dissect_raw_and_sll():
    ip_packet = g.ipv4("10.0.0.1", "10.0.0.2", 17,
                       g.udp_datagram("10.0.0.1", "10.0.0.2", 1, 2, b"x"))
    raw = pc.dissect(101, ip_packet)
    assert raw.l2 == "raw" and raw.l3 == "ipv4" and raw.l4_checksum_ok
    sll = struct.pack("!HHH8sH", 0, 1, 6, b"\x02" * 6 + b"\x00\x00", 0x0800) + ip_packet
    packet = pc.dissect(113, sll)
    assert packet.l2 == "sll" and packet.l3 == "ipv4" and packet.src_mac == b"\x02" * 6


def test_structure_errors():
    # IHL < 5
    bad = bytearray(g.ipv4("10.0.0.1", "10.0.0.2", 6, b"\x00" * 20))
    bad[0] = 0x44
    assert "ipv4_ihl_kleiner_5" in pc.dissect(101, bytes(bad)).structure_errors
    # UDP-Laengenfeld passt nicht zur IP-Laenge
    datagram = g.udp_datagram("10.0.0.1", "10.0.0.2", 1, 2, b"abcd", length=20)
    packet = pc.dissect(101, g.ipv4("10.0.0.1", "10.0.0.2", 17, datagram))
    assert "udp_laenge_passt_nicht_zur_ip_laenge" in packet.structure_errors
    # TTL 0
    packet = pc.dissect(101, g.ipv4("10.0.0.1", "10.0.0.2", 17,
                                    g.udp_datagram("10.0.0.1", "10.0.0.2", 1, 2), ttl=0))
    assert "ttl_null" in packet.structure_errors


def test_fcs_is_stripped_only_for_complete_records():
    frame = g.tcp_packet("10.0.0.1", "10.0.0.2", 1, 80, 0x02) + b"\xde\xad\xbe\xef"
    packet = pc.dissect(1, frame, fcs_len=4)
    assert packet.present_len == packet.total_len


def test_checksum_functions_match_reference():
    rng = random.Random(1)
    for size in (1, 2, 3, 20, 21, 1500):
        data = bytes(rng.randrange(256) for _ in range(size))
        assert pc.internet_checksum(data) == g.checksum(data)
        padded = data + (b"\x00" if size % 2 else b"")
        value = g.checksum(padded)
        assert pc.checksum_ok(padded + struct.pack("!H", value))


def test_against_scapy():
    scapy = pytest.importorskip("scapy.all")
    rng = random.Random(7)
    for index in range(200):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        if index % 3 == 0:
            layer = scapy.UDP(sport=rng.randrange(1, 65535), dport=53)
        elif index % 3 == 1:
            layer = scapy.TCP(sport=rng.randrange(1, 65535), dport=80,
                              flags=rng.choice(["S", "SA", "PA", "FA"]),
                              options=[("MSS", 1460)] if index % 2 else [])
        else:
            layer = scapy.ICMP()
        frame = bytes(scapy.Ether() / scapy.IP(src="192.168.1.%d" % (index % 250 + 1),
                                                dst="10.1.2.3", ttl=rng.randrange(1, 255))
                      / layer / scapy.Raw(payload))
        packet = pc.dissect(1, frame)
        assert packet.ip_checksum_ok is True
        assert packet.l4_checksum_ok is True, index
        # gezielt verfaelschen: letztes Nutzlastbyte kippen
        if payload:
            broken = bytearray(frame)
            broken[-1] ^= 0xFF
            again = pc.dissect(1, bytes(broken))
            assert again.l4_checksum_ok is False
            fixed = scapy.Ether(bytes(broken))
            transport = fixed.getlayer(type(layer))
            del transport.chksum
            expected = scapy.Ether(bytes(fixed)).getlayer(type(layer)).chksum
            assert again.l4_expected == expected
