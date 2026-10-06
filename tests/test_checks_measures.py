"""Einzelpruefungen, Distanzmasse und Flusslogik."""
import random

import pytest

import pcap_check as pc


# --- Einzelpruefungen --------------------------------------------------------

@pytest.mark.parametrize("address,expected", [
    ("224.0.0.251", "multicast"), ("255.255.255.255", "broadcast"),
    ("255.1.2.3", "reserviert"), ("0.1.2.3", "null-netz"),
    ("240.0.0.1", "reserviert"), ("127.0.0.1", "loopback"),
    ("10.1.2.3", "privat"), ("172.16.0.1", "privat"), ("172.32.0.1", "oeffentlich"),
    ("192.168.10.5", "privat"), ("169.254.1.1", "link-lokal"),
    ("100.64.0.1", "cgnat"), ("192.0.2.7", "dokumentation"),
    ("198.18.0.1", "benchmark"), ("8.8.8.8", "oeffentlich"),
    ("ff02::1", "multicast"), ("fe80::1", "link-lokal"), ("fd00::1", "privat"),
    ("::", "unspezifiziert"), ("::1", "loopback"), ("2001:db8::1", "dokumentation"),
    ("2a00:1450::1", "oeffentlich"), ("kein.ip", "ungueltig"),
])
def test_classify_ip(address, expected):
    assert pc.classify_ip(address) == expected


def test_p1_follows_yin():
    assert pc.check_address_validity("10.0.0.1", "10.0.0.2")
    assert not pc.check_address_validity("224.0.0.1", "10.0.0.2")
    assert not pc.check_address_validity("255.0.0.1", "10.0.0.2")
    assert not pc.check_address_validity("10.0.0.1", "0.0.0.5")
    # Quelle 0.0.0.0 ist erlaubt (DHCP-Discover)
    assert pc.check_address_validity("0.0.0.0", "255.255.255.255")


def test_p3_port_protocol():
    assert pc.check_port_protocol(80, 6) is True
    assert pc.check_port_protocol(80, 17) is False
    assert pc.check_port_protocol(123, 17) is True
    assert pc.check_port_protocol(53, 17) is None
    assert pc.check_port_protocol(443, 17) is None      # QUIC
    assert pc.check_port_protocol(12345, 6) is None


def test_p4_minimum_length():
    assert pc.check_minimum_length(6, 40) is True
    assert pc.check_minimum_length(6, 39) is False
    assert pc.check_minimum_length(17, 28) is True
    assert pc.check_minimum_length(6, 59, ipv6=True) is False
    assert pc.check_minimum_length(47, 10) is None


def test_e1_direction():
    assert pc.check_length_consistency(100, 90) == (pc.LENGTH_MISMATCH, 10)
    assert pc.check_length_consistency(46, 60) == (pc.LENGTH_PADDING, -14)
    assert pc.check_length_consistency(60, 60) == (pc.LENGTH_OK, 0)


def test_e2_udp_multicast_is_valid_tcp_is_not():
    assert pc.check_destination_class(17, "multicast")
    assert pc.check_destination_class(17, "broadcast")
    assert pc.check_destination_class(1, "broadcast")
    assert not pc.check_destination_class(6, "multicast")
    assert not pc.check_destination_class(6, "broadcast")
    assert not pc.check_destination_class(17, "reserviert")
    assert pc.check_destination_class(6, "privat")


@pytest.mark.parametrize("flags,expected", [
    (0x02, None), (0x12, None), (0x10, None), (0x18, None), (0x11, None),
    (0x04, None), (0x14, None), (0x00, "NULL (keine Flags)"),
    (0x03, "SYN+FIN"), (0x06, "SYN+RST"), (0x05, "FIN+RST"),
    (0x01, "FIN ohne ACK"), (0x29, "Xmas (FIN+PSH+URG)"),
    (0x08, "PSH/URG ohne ACK"), (0xC2, None),
])
def test_e9_tcp_flags(flags, expected):
    assert pc.check_tcp_flags(flags) == expected


def test_tcp_flag_text_like_scapy():
    assert pc.tcp_flag_text(0x12) == "SA"
    assert pc.tcp_flag_text(0x18) == "PA"
    assert pc.tcp_flag_text(0x11) == "FA"
    assert pc.tcp_flag_text(0) == "0"


def test_e5_degeneration():
    passed, stats = pc.check_size_degeneration({64: 95, 1518: 5}, 100)
    assert not passed and stats["belegte_klassen"] == 2
    passed, _ = pc.check_size_degeneration({64: 30, 512: 30, 1518: 40}, 100)
    assert passed


def test_size_class_boundaries():
    assert pc.SIZE_CLASSES[pc.size_class_index(64)] == 64
    assert pc.SIZE_CLASSES[pc.size_class_index(65)] == 128
    assert pc.size_class_index(0) is None


def test_is_truncated():
    assert pc.is_truncated(1500, 96)
    assert not pc.is_truncated(96, 96)


def test_port_range():
    assert pc.port_range(80) == "0-1023"
    assert pc.port_range(40000) == "32768-49151"
    assert pc.port_range(50000) == "49152-60999"
    assert pc.port_range(64000) == "61000-65535"


# --- Reservoir ---------------------------------------------------------------

def test_reservoir_is_reproducible_and_uniform():
    first = pc.ExampleReservoir(5, random.Random(1))
    second = pc.ExampleReservoir(5, random.Random(1))
    for item in range(1000):
        first.offer(item)
        second.offer(item)
    assert first.items == second.items
    assert max(first.items) > 100          # nicht nur der Dateianfang


def test_value_sample_keeps_exact_extremes():
    sample = pc.ValueSample(10, random.Random(3))
    for value in range(1000):
        sample.add(float(value))
    distribution = sample.distribution()
    assert distribution.minimum == 0 and distribution.maximum == 999
    assert not distribution.exact and distribution.population == 1000
    assert distribution.total == 10


# --- Distanzmasse -------------------------------------------------------------

def dist(values):
    return pc.Distribution.from_values(values)


def test_ks_and_wasserstein_simple():
    a, b = dist([0, 1, 2]), dist([0, 1, 2])
    assert pc.ks_distance(a, b) == 0 and pc.wasserstein_distance(a, b) == 0
    a, b = dist([0.0]), dist([10.0])
    assert pc.ks_distance(a, b) == 1
    assert pc.wasserstein_distance(a, b) == pytest.approx(10)
    a, b = dist([1, 2, 3, 4]), dist([3, 4, 5, 6])
    assert pc.ks_distance(a, b) == pytest.approx(0.5)
    assert pc.wasserstein_distance(a, b) == pytest.approx(2)


def test_measures_against_scipy():
    stats = pytest.importorskip("scipy.stats")
    distance = pytest.importorskip("scipy.spatial.distance")
    rng = random.Random(5)
    for _ in range(20):
        a = [rng.gauss(0, 1) for _ in range(rng.randrange(5, 300))]
        b = [rng.expovariate(1) for _ in range(rng.randrange(5, 300))]
        a += a[:3]                                 # Bindungen
        da, db = dist(a), dist(b)
        assert pc.ks_distance(da, db) == pytest.approx(stats.ks_2samp(a, b).statistic)
        assert pc.wasserstein_distance(da, db) == pytest.approx(
            stats.wasserstein_distance(a, b))
    counter = pc.Distribution.from_counter({40: 3, 1500: 1})
    assert pc.wasserstein_distance(counter, dist([40, 40, 40, 1500])) == pytest.approx(0)
    p = {"TCP": 70, "UDP": 25, "ICMP": 5}
    q = {"TCP": 10, "UDP": 80, "GRE": 10}
    keys = sorted(set(p) | set(q))
    expected = distance.jensenshannon([p.get(k, 0) for k in keys],
                                      [q.get(k, 0) for k in keys], base=2) ** 2
    assert pc.jensen_shannon(p, q) == pytest.approx(expected)


def test_jsd_bounds():
    assert pc.jensen_shannon({"a": 1}, {"a": 5}) == 0
    assert pc.jensen_shannon({"a": 1}, {"b": 1}) == pytest.approx(1)
    assert pc.jensen_shannon({}, {"b": 1}) is None


def test_quantiles_weighted():
    distribution = pc.Distribution.from_counter({1: 1, 2: 1, 3: 2})
    quantiles = distribution.quantiles((0.25, 0.5, 0.75, 0.99))
    assert quantiles == {0.25: 1, 0.5: 2, 0.75: 3, 0.99: 3}
    assert distribution.mean() == pytest.approx(2.25)


def test_relative_deviation():
    assert pc.relative_deviation(110, 100) == pytest.approx(0.1)
    assert pc.relative_deviation(1, 0) is None


# --- Fluesse ------------------------------------------------------------------

S, SA, A, F, R = pc.SIDE_SYN, pc.SIDE_SYNACK, pc.SIDE_ACK, pc.SIDE_FIN, pc.SIDE_RST
SEEN = pc.SIDE_SEEN


@pytest.mark.parametrize("orig,resp,state", [
    (SEEN | S | A | F, SEEN | SA | A | F, "SF"),
    (SEEN | S, 0, "S0"),
    (SEEN | S, SEEN | R, "REJ"),
    (SEEN | S | A, SEEN | SA | A, "S1"),
    (SEEN | S | A | F, SEEN | SA | A, "S2"),
    (SEEN | S | A, SEEN | SA | A | F, "S3"),
    (SEEN | S | R, SEEN | SA, "RSTO"),
    (SEEN | S | A, SEEN | SA | R, "RSTR"),
    (SEEN | S | R, 0, "RSTOS0"),
    (SEEN | S | F, 0, "SH"),
    (SEEN | A, SEEN | A, "OTH"),
    (SEEN | A, SEEN | SA | F, "SHR"),
    (SEEN | A, SEEN | SA | R, "RSTRH"),
])
def test_tcp_states(orig, resp, state):
    assert pc.classify_tcp_state(orig, resp) == state


def make_table(timeout=10.0):
    finished = []
    table = pc.FlowTable(timeout, 1000, lambda key, flow, at_end:
                         finished.append((key, list(flow), at_end)))
    return table, finished


A_IP, B_IP = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])


def test_flow_key_is_bidirectional():
    forward = pc.flow_key(A_IP, 1000, B_IP, 80, 6)
    backward = pc.flow_key(B_IP, 80, A_IP, 1000, 6)
    assert forward[0] == backward[0] and forward[1] != backward[1]
    assert pc.describe_flow(forward[0]) == "10.0.0.1:1000 <-> 10.0.0.2:80 TCP"


def test_final_ack_after_fin_does_not_split():
    table, finished = make_table()
    ns = pc.NS
    for ts, src, dst, sport, dport, flags in [
            (0, A_IP, B_IP, 1000, 80, 0x02), (1, B_IP, A_IP, 80, 1000, 0x12),
            (2, A_IP, B_IP, 1000, 80, 0x11), (3, B_IP, A_IP, 80, 1000, 0x11),
            (4, A_IP, B_IP, 1000, 80, 0x10)]:
        table.observe(ts * ns, src, sport, dst, dport, 6, 40, flags)
    table.finish_all()
    assert len(finished) == 1
    _, flow, _ = finished[0]
    assert flow[pc.F_PKTS_A] + flow[pc.F_PKTS_B] == 5


def test_timeout_and_reuse_split_flows():
    table, finished = make_table(timeout=10.0)
    ns = pc.NS
    table.observe(0, A_IP, 1000, B_IP, 80, 17, 30, None)
    table.observe(30 * ns, A_IP, 1000, B_IP, 80, 17, 30, None)   # nach Timeout
    table.observe(31 * ns, A_IP, 2000, B_IP, 80, 6, 40, 0x02)
    table.observe(31 * ns, B_IP, 80, A_IP, 2000, 6, 40, 0x14)    # RST
    table.observe(32 * ns, A_IP, 2000, B_IP, 80, 6, 40, 0x02)    # neues SYN
    table.finish_all()
    assert len(finished) == 4
    assert table.reused_after_close == 1


def test_sweep_bounds_active_flows():
    table, finished = make_table(timeout=1.0)
    for index in range(100):
        table.observe(index * pc.NS, A_IP, 1000 + index, B_IP, 80, 17, 30, None)
    assert len(table.flows) <= 3
    assert len(finished) >= 97
