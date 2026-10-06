"""Analyse ganzer Mitschnitte, Sollwert, Ebene 4 und Kommandozeile."""
import json
import random

import pytest

import pcap_check as pc
import pcapgen as g

CLIENT, SERVER = "10.0.0.5", "10.0.1.1"


def connections(count, start=1_500_000_000.0, seed=1, port_base=40000):
    rng = random.Random(seed)
    records = []
    ts = start
    for index in range(count):
        records += g.tcp_connection(CLIENT, SERVER, port_base + index, 80, ts,
                                    payload=b"x" * rng.randrange(10, 1200))
        ts += rng.uniform(0.05, 0.5)
    records.sort(key=lambda record: record[0])
    return records


def analyze_records(tmp_path, records, name="a.pcap", **options):
    path = tmp_path / name
    g.write_pcap(path, records)
    return pc.analyze(str(path), pc.Options(**options))


def test_clean_capture_passes(tmp_path):
    analysis = analyze_records(tmp_path, connections(20))
    for key in ("P1", "P3", "P4", "E1", "E2", "E3", "E6", "E7", "E8", "E9", "E10", "E4"):
        assert analysis.checks[key].status == pc.STATUS_OK, key
    assert analysis.checks["P2"].status == pc.STATUS_NA
    assert analysis.flow_count == 20
    assert analysis.checks["E4"].extra["zustaende"] == {"SF": 20}
    assert analysis.protocol_fidelity["anteil_fehlerhaft"] == 0
    assert analysis.scalars["anteil_unvollstaendige_tcp"] == 0


def test_e1_mismatch_and_snaplen_skip(tmp_path):
    frame = g.tcp_packet(CLIENT, SERVER, 1000, 80, 0x18, b"y" * 100, total_length=400)
    truncated = g.tcp_packet(CLIENT, SERVER, 1001, 80, 0x18, b"y" * 500)
    analysis = analyze_records(tmp_path, [
        (1.0, frame),
        (2.0, truncated[:96], len(truncated)),      # Snaplen 96
    ])
    e1 = analysis.checks["E1"]
    assert e1.violations == 1 and e1.skipped == 1
    assert e1.examples.items[0]["differenz"] == 400 - 140
    # abgeschnittener Record und ueberhoehtes Laengenfeld: Pruefsumme nicht
    # nachrechenbar, beide als uebersprungen gefuehrt
    assert analysis.checks["E8"].skipped == 2
    assert analysis.checks["E8"].checked == 0


def test_defect_share_counts_packets_once(tmp_path):
    bad = g.tcp_packet("224.0.0.1", SERVER, 1000, 80, 0x03,
                       bad_checksum=True, bad_ip_checksum=True)
    analysis = analyze_records(tmp_path, [(1.0, bad), *connections(1, start=2.0)])
    fidelity = analysis.protocol_fidelity
    assert fidelity["fehlerhaft_gesamt"] == 1
    assert fidelity["fehlerhaft_header"] == 1 and fidelity["fehlerhaft_pruefsumme"] == 1
    assert analysis.checks["P1"].violations == 1
    assert analysis.checks["E9"].violations == 1


def test_e2_ignores_udp_multicast(tmp_path):
    analysis = analyze_records(tmp_path, [
        (1.0, g.udp_packet("10.0.0.7", "224.0.0.251", 5353, 5353, b"mdns")),
        (2.0, g.udp_packet("10.0.0.7", "239.255.255.250", 40000, 1900, b"ssdp")),
        (3.0, g.tcp_packet("10.0.0.7", "224.0.0.9", 40000, 80, 0x02)),
    ])
    e2 = analysis.checks["E2"]
    assert e2.checked == 3 and e2.violations == 1


@pytest.mark.parametrize("facet,status", [
    (None, pc.STATUS_WARN), ("D1", pc.STATUS_INFO),
    ("D2", pc.STATUS_WARN), ("D3", pc.STATUS_FAIL)])
def test_e4_follows_facet_d(tmp_path, facet, status):
    records = connections(5, start=1000.0)
    # SYN-Flood mitten im Mitschnitt: unbeantwortete SYNs, kein Randfluss
    records += [(1001.0 + i * 0.001, g.tcp_packet("10.9.9.9", SERVER, 2000 + i, 80, 0x02))
                for i in range(10)]
    records += connections(5, start=2000.0, seed=2, port_base=41000)
    records.sort(key=lambda record: record[0])
    analysis = analyze_records(tmp_path, records, facet_d=facet, edge_margin=5.0)
    e4 = analysis.checks["E4"]
    assert e4.extra["unvollstaendig_nach_zustand"] == {"S0": 10}
    assert e4.status == status


def test_edge_flows_are_not_incomplete(tmp_path):
    midstream = [(100.0 + i * 0.1, g.tcp_packet(CLIENT, SERVER, 5555, 80, 0x18, b"d"))
                 for i in range(3)]
    tail = [(300.0, g.tcp_packet(CLIENT, SERVER, 6666, 80, 0x02))]
    records = midstream + connections(3, start=150.0) + tail
    analysis = analyze_records(tmp_path, records, edge_margin=10.0)
    e4 = analysis.checks["E4"].extra
    assert e4["randfluesse_nach_zustand"] == {"OTH": 1, "S0": 1}
    assert e4["unvollstaendig"] == 0
    analysis = analyze_records(tmp_path, records, edge_margin=0.0, name="b.pcap")
    assert analysis.checks["E4"].extra["unvollstaendig"] == 2


def test_throughput_and_concurrency_include_empty_bins(tmp_path):
    records = [(0.0, g.udp_packet("10.0.0.1", "10.0.0.2", 1, 2, b"a")),
               (0.5, g.udp_packet("10.0.0.3", "10.0.0.2", 1, 2, b"a")),
               (3.2, g.udp_packet("10.0.0.1", "10.0.0.2", 1, 2, b"a"))]
    analysis = analyze_records(tmp_path, records, flow_timeout=1.0)
    packets = analysis.features["durchsatz_pakete"]
    assert dict(zip(packets.values, packets.weights)) == {0: 2, 1: 1, 2: 1}
    concurrency = analysis.features["gleichzeitige_fluesse"]
    assert dict(zip(concurrency.values, concurrency.weights)) == {0: 2, 1: 1, 2: 1}


def test_artifacts(tmp_path):
    records = []
    for index in range(60):                 # fortlaufende, gefaelschte Quellen
        src = f"10.5.0.{index + 1}"
        records.append((index * 0.01, g.tcp_packet(src, SERVER, 7777, 80, 0x02,
                                                   payload=b"\x00" * 20)))
    for index in range(60):                 # dieselben Tupel noch einmal
        src = f"10.5.0.{index + 1}"
        records.append((200 + index * 0.01, g.tcp_packet(src, SERVER, 7777, 80, 0x02,
                                                         payload=b"\x00" * 20)))
    analysis = analyze_records(tmp_path, records, flow_timeout=10.0)
    checks = analysis.checks
    assert checks["AF1"].status == pc.STATUS_WARN          # 61 Quellen, eine TTL
    assert checks["AF2"].status == pc.STATUS_WARN
    assert checks["AF3"].extra["wiederholte_fuenf_tupel"] == 60
    assert checks["AF3"].status == pc.STATUS_WARN
    assert checks["AF5"].extra["effektive_aufloesung"] == "10 ms"
    assert checks["AF5"].status == pc.STATUS_WARN
    assert checks["AF6"].status == pc.STATUS_WARN
    assert checks["AF7"].status == pc.STATUS_WARN
    assert checks["AF4"].status == pc.STATUS_OK


def test_sequence_steps(tmp_path):
    records = connections(2, start=10.0)
    records.append((20.0, g.udp_packet(CLIENT, "10.0.1.53", 5000, 53, b"q")))
    spec_steps = [
        {"name": "Web", "filter": {"proto": "TCP", "dst_port": 80, "tcp_flags": "S"}},
        {"name": "DNS", "filter": {"proto": "udp", "port": 53, "dst": "10.0.1.0/24"}},
        {"name": "SSH", "filter": {"dst_port": 22}},
    ]
    analysis = analyze_records(tmp_path, records, sequence=spec_steps)
    sequence = analysis.sequence
    assert sequence["gefunden"] == 2 and sequence["schritte"] == 3
    assert sequence["reihenfolge_eingehalten"] is True
    with pytest.raises(pc.SpecError):
        pc.SequenceStep(0, {"filter": {"unbekannt": 1}})


def write_spec(tmp_path, spec):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec))
    return str(path)


def test_spec_loading_and_target(tmp_path):
    spec = {
        "beschreibung": "Test",
        "verteilungen": {
            "paketgroesse": {"typ": "konstant", "wert": 40},
            "zwischenankunftszeit": {"typ": "exponentiell", "mittelwert": 0.01},
            "protokolle": {"typ": "kategorial", "anteile": {"tcp": 1.0}},
            "zielports": {"typ": "kategorial", "anteile": {"80/TCP": 1.0}},
        },
        "skalare": {"durchsatz_pakete_pro_s": 100},
    }
    loaded = pc.load_spec(write_spec(tmp_path, spec))
    target = pc.build_target(None, loaded, seed=1, sample_size=1000)
    assert target.kind == "konfiguration"
    assert target.features["protokolle"] == {"TCP": 1.0}
    assert target.features["zielports"] == {"80/tcp": 1.0}
    assert target.features["zwischenankunftszeit"].total == 1000
    assert set(target.assured) == {"paketgroesse", "zwischenankunftszeit",
                                   "protokolle", "zielports", "durchsatz_pakete_pro_s"}
    for broken in ({"verteilungen": {"gibtsnicht": {"typ": "konstant", "wert": 1}}},
                   {"verteilungen": {"protokolle": {"typ": "normal"}}},
                   {"falsch": 1}):
        with pytest.raises(pc.SpecError):
            pc.load_spec(write_spec(tmp_path, broken))


def test_compare_runs_thresholds(tmp_path):
    runs = []
    for index in range(3):
        analysis = analyze_records(tmp_path, connections(30, seed=index + 1),
                                   name=f"r{index}.pcap")
        analysis.label = f"L{index + 1}"
        runs.append(analysis)
    target = pc.Target()
    target.kind = "konfiguration"
    target.features["paketgroesse"] = pc.Distribution.from_counter({1500: 1})
    target.scalars["fluesse"] = 30
    result = pc.compare_runs(runs, target, ["paketgroesse"])
    size = result["merkmale"]["paketgroesse"]
    assert len(size["eigenstreuung"]["paare"]) == 3
    assert size["zugesichert"] is True
    assert size["sollabweichung"]["laeufe_ueber_schwelle"] == {"D": 3, "W1_norm": 3}
    assert result["abweichungen_ueber_schwelle"][0]["merkmal"] == "paketgroesse"
    flows = result["skalare"]["fluesse"]
    assert flows["abweichung_relativ"] == {"L1": 0, "L2": 0, "L3": 0}
    assert flows["ueber_schwelle"] == {"L1": False, "L2": False, "L3": False}


def test_background_conflicts_and_collisions(tmp_path):
    attack = g.tcp_connection("10.0.0.66", SERVER, 4444, 80, 1000.0)
    other = g.tcp_connection("10.0.0.77", SERVER, 5555, 80, 1000.5)
    run_path = tmp_path / "run.pcap"
    g.write_pcap(run_path, sorted(attack + other))
    background = sorted(g.tcp_connection("10.0.0.8", SERVER, 2222, 80, 995.0)
                        + g.tcp_connection("10.0.0.66", SERVER, 4444, 80, 1010.0)
                        + g.tcp_connection("10.0.0.9", SERVER, 3333, 80, 5000.0))
    background_path = tmp_path / "bg.pcap"
    g.write_pcap(background_path, background)
    options = pc.Options()
    run = pc.analyze(str(run_path), options, "L1", collect_flow_keys=True)
    bg = pc.analyze(str(background_path), options, "Hintergrund",
                    watch=set(run.flow_keys))
    result = pc.compare_background([run], bg, window_seconds=60)
    labels = result["label_integritaet"]["L1"]
    assert labels["pakete_in_fluessen"] == 14
    assert labels["konflikte_zeitunabhaengig"] == 7
    assert labels["konflikte_im_zeitfenster"] == 7
    result = pc.compare_background([run], bg, window_seconds=1)
    assert result["label_integritaet"]["L1"]["konflikte_im_zeitfenster"] == 0
    assert result["adresskollisionen"]["L1"]["kollisionen"] == 2   # .66 und Server
    assert result["sicherungsschicht"]["einheitlich"] is True
    assert result["angriffsanteil"]["L1"]["je_paket"] == pytest.approx(14 / 35)


# --- Kommandozeile und Ergebnisdatei -----------------------------------------

def test_cli_writes_yaml_and_json(tmp_path, capsys):
    paths = []
    for index in range(2):
        path = tmp_path / f"lauf{index}.pcap"
        g.write_pcap(path, connections(10, seed=index))
        paths.append(str(path))
    output = tmp_path / "erg" / "werkzeug.yaml"
    code = pc.main(paths + ["--tool", "Demo", "-o", str(output),
                            "--json", str(tmp_path / "werkzeug.json"), "--no-color"])
    assert code == 0
    data = json.loads((tmp_path / "werkzeug.json").read_text())
    assert data["meta"]["werkzeug"] == "Demo"
    assert list(data["laeufe_kurz"]) == ["L1", "L2"]
    assert data["bewertung"]["status"] == "warnung"     # nur zwei Laeufe
    yaml = pytest.importorskip("yaml")
    loaded = yaml.safe_load(output.read_text())
    assert json.loads(json.dumps(loaded)) == data
    assert "Werkzeug-Diskrepanz" in capsys.readouterr().out


def test_cli_exit_codes(tmp_path):
    path = tmp_path / "kaputt.pcap"
    g.write_pcap(path, connections(2) + [
        (1e9 + 50, g.tcp_packet(CLIENT, SERVER, 1, 80, 0x10, bad_checksum=True))])
    assert pc.main([str(path), "--no-output", "--quiet"]) == 1
    clean = tmp_path / "sauber.pcap"
    g.write_pcap(clean, connections(5))
    assert pc.main([str(clean), "--no-output", "--quiet"]) == 0
    assert pc.main([str(clean), "--no-output", "--quiet", "--strict"]) == 1
    assert pc.main([str(tmp_path / "fehlt.pcap"), "--no-output", "--quiet"]) == 1


def test_cli_rejects_bad_spec(tmp_path):
    clean = tmp_path / "sauber.pcap"
    g.write_pcap(clean, connections(2))
    spec = write_spec(tmp_path, {"verteilungen": {"x": {}}})
    with pytest.raises(SystemExit) as error:
        pc.main([str(clean), "--spec", spec, "--no-output"])
    assert error.value.code == 2


@pytest.mark.parametrize("value", [
    "yes", "No", "null", "080", "1e5", "a: b", "-x", "x #y", "", " lead",
    "trail ", "[a]", "{b}", "a,b", "2026-10-06", "1:20", "@at", "%p", "ok",
    "L1-L2", "80/tcp", "/abs/path", "äöü", 'quote"d', "tab\there", "new\nline",
    1e-05, 1e16, -0.0, 123, True, None, 0.1,
])
def test_yaml_scalars_roundtrip(value):
    yaml = pytest.importorskip("yaml")
    document = {"key": value, "liste": [value, value], "map": {"k": value}}
    text = pc.to_yaml(document)
    assert yaml.safe_load(text) == document


def test_p3_checks_service_port_only(tmp_path):
    records = [
        # Resolver mit zufaelligem Quellport 1883 -> DNS: kein Verstoss
        (1.0, g.udp_packet("10.0.0.3", "8.8.8.8", 1883, 53, b"q")),
        (1.1, g.udp_packet("8.8.8.8", "10.0.0.3", 53, 1883, b"a")),
        # TCP-Client mit Quellport 3306 -> HTTP: kein Verstoss
        (2.0, g.tcp_packet("10.0.0.3", "10.0.1.1", 3306, 80, 0x02)),
        (2.1, g.tcp_packet("10.0.1.1", "10.0.0.3", 80, 3306, 0x12)),
        # UDP an den MQTT-Port: Verstoss
        (3.0, g.udp_packet("10.0.0.3", "10.0.1.1", 40000, 1883, b"x")),
    ]
    analysis = analyze_records(tmp_path, records)
    p3 = analysis.checks["P3"]
    assert p3.checked == 3 and p3.violations == 1
    assert p3.examples.items[0].startswith("port=1883 proto=UDP")
