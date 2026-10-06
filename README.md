# pcap_check

Generatorunabhängiges Prüf- und Evaluationswerkzeug für synthetische
PCAP-Mitschnitte. Ein Aufruf je Werkzeug liefert:

| Teil | Inhalt | Bezug zur Konzeption |
|---|---|---|
| Validierung | Format, Protokolltreue, Zeitstempel, Sicherungsschicht je Lauf | Ebene 3 Protokolltreue, Ebene 4 |
| Merkmale | Paketgröße, Zwischenankunftszeit, Durchsatz, Flussgrößen, Flussdauer, gleichzeitige Flüsse, Protokolle, Ports | Ebenen 1 und 2, Tabelle 1.4 |
| Werkzeug-Diskrepanz | Eigenstreuung (paarweise), Sollabweichung je Lauf, Schwelle = Maximum der Eigenstreuung | Abschnitt 1.3.1 |
| Ablauf | Strukturelle Vollständigkeit gegen zugesicherte Schritte | Ebene 3 |
| Artefakte | Prüfliste (TTL, fortlaufende Adressen, Quellports, MAC-Präfixe, Zeitquantisierung, Taktung, Nullnutzlast) | Ebene 3 Erzeugungsartefakte |
| Hintergrund | Link-Type, Adresskollisionen, Label-Konflikte (Fünf-Tupel im Zeitfenster), Angriffsanteil | Ebenen 3 und 4 |

Das Skript braucht nur die Python-Standardbibliothek (≥ 3.8). Die vollständige
Dokumentation der Prüfungen steht im Docstring von `pcap_check.py`
(`python pcap_check.py --help`).

## Schnellstart

```bash
# ein Mitschnitt: nur Validierung und Merkmale
python pcap_check.py lauf1.pcap

# ein Werkzeug, fünf Läufe, Sollwert aus dem Eingangsmitschnitt (ID2T, Facette E4)
python pcap_check.py id2t_l1.pcap id2t_l2.pcap id2t_l3.pcap id2t_l4.pcap id2t_l5.pcap \
    --tool ID2T --reference eingang.pcap --facet-d D1 --facet-e E4 \
    -o ergebnisse/id2t.yaml --jobs 6

# Sollwert aus der Konfiguration (Facette E2) mit Ablauf, dazu Ebene 4
python pcap_check.py caldera_l*.pcap --tool Caldera --spec caldera_soll.json \
    --facet-d D3 --facet-e E2 --background cicids2017_montag.pcap \
    -o ergebnisse/caldera.yaml
```

Die Läufe heißen in der Reihenfolge der Kommandozeile `L1 … Ln` (wie in
Abbildung 1.1). Ohne `-o` wird `pcap_check_<werkzeug>.yaml` im aktuellen
Verzeichnis geschrieben; `-o x.json` oder zusätzlich `--json x.json` liefert
dasselbe als JSON.

Rückgabewert: `0` ohne Fehler, `1` bei mindestens einem Fehler in einem Lauf
oder einer unlesbaren Datei (mit `--strict` auch bei Warnungen), `2` bei
ungültigem Aufruf. Befunde von Referenz und Hintergrund werden berichtet,
ändern den Rückgabewert aber nicht.

## Ergebnisdatei

YAML, weil es ohne Klammerrauschen lesbar ist und von jeder Sprache und jedem
Sprachmodell gelesen wird. Der Schreiber ist eingebaut (keine Abhängigkeit),
die Datei lässt sich mit jedem YAML-Parser lesen und ist inhaltsgleich zur
JSON-Ausgabe (durch Tests abgesichert). Schlüssel sind deutsch und ohne
Umlaute.

```
lesehilfe        Erklärung aller Status, Maße und Felder (auch für KI-Leser)
meta             Werkzeug, Version, Aufruf, Parameter, Facetten, Reichweite,
                 Zuordnung L1..Ln -> Datei + SHA-256
bewertung        Gesamtstatus, Fehler/Warnungen, alle Validator-Meldungen
laeufe_kurz      eine Zeile je Lauf (Status, Pakete, Dauer, fehlerhafte Prüfungen)
protokolltreue   Anteil fehlerhafter Pakete je Lauf (Header, Prüfsummen, gesamt)
diskrepanz       je Merkmal: Eigenstreuung (Paare, Median, Max) und
                 Sollabweichung (je Lauf, ueber_D / ueber_W1_norm / ueber_JSD);
                 Skalare mit relativer Abweichung; strukturelle Vollständigkeit
hintergrund      nur mit --background (Ebene 4)
sollwert         Art des Sollwerts, Spezifikation, vollständige Referenzanalyse
laeufe           alle Details je Lauf: Format, Zeitraum, Schichten, Hosts,
                 Dienste, IoT-Dienste, Nutzdaten, TCP-Zustände, Prüfungen
                 mit Beispielen, Merkmalszusammenfassungen (Quantile)
```

Mehrere Werkzeuge einlesen, etwa für die Vergleichstabelle:

```python
import glob, yaml

for pfad in sorted(glob.glob("ergebnisse/*.yaml")):
    erg = yaml.safe_load(open(pfad, encoding="utf-8"))
    werkzeug = erg["meta"]["werkzeug"]
    groesse = erg["diskrepanz"]["merkmale"]["paketgroesse"]
    print(werkzeug,
          erg["bewertung"]["status"],
          {lauf: z["anteil_fehlerhaft"] for lauf, z in erg["protokolltreue"].items()},
          groesse["eigenstreuung"]["D"],
          groesse.get("sollabweichung", {}).get("D"))
```

## Prüfungen

Status: `ok`, `warnung` (auffällig, Deutung nötig), `fehler`, `info`
(erwartbar, etwa nach Facette D), `n/a`.

| ID | Prüfung | bei Verstoß | Herkunft |
|---|---|---|---|
| P1 | Quelle nicht Multicast/255.x, Ziel nicht 0.x (IPv6 sinngemäß) | fehler | Yin et al. |
| P2 | Byte- zu Paketzahl (nur Flussdaten) | n/a | Yin et al. |
| P3 | Dienstport passt zum Protokoll | fehler | Yin et al. |
| P4 | Mindestgröße TCP 40 / UDP 28 Byte (IPv6 60/48) | fehler | Yin et al. |
| E1 | IP-Längenfeld ≤ vorhandene Bytes (abgeschnittene Records ausgenommen) | fehler | eigen |
| E2 | TCP nur an Unicast; kein Ziel 0.x/reserviert | fehler | eigen |
| E3 | Ethernet-Header vorhanden | fehler | eigen |
| E4 | TCP-Verbindungszustände (Zeek-ähnlich), ohne Randflüsse | nach Facette D: D1 info, D3 fehler, sonst warnung | eigen |
| E5 | Paketgrößen nicht degeneriert (≥ 3 Klassen, keine > 90 %) | warnung | eigen |
| E6 | Zeitstempel monoton und plausibel | fehler (Rücksprung), warnung (vor 1990/Zukunft) | eigen |
| E7 | IPv4-Header-Prüfsumme | fehler | eigen |
| E8 | TCP/UDP/ICMP/ICMPv6-Prüfsumme mit Pseudo-Header | fehler | eigen |
| E9 | TCP-Flags widerspruchsfrei (NULL, SYN+FIN, Xmas …) | fehler | eigen |
| E10 | Header-Struktur (IHL, Data Offset, UDP-Länge, TTL 0, Version) | fehler | eigen |
| AF1–AF7 | Erzeugungsartefakte der Prüfliste | warnung („auffällig“) | Konzeption 1.5.3 |

„Anteil fehlerhafter Pakete“ (Messgröße der Protokolltreue) = Anteil der
IP-Pakete mit mindestens einem Verstoß gegen P1, P3, P4, E1, E2, E9, E10
(Header) oder E7, E8 (Prüfsummen); beide Teilanteile werden mit ausgewiesen.

## Merkmale und Distanzmaße

Alle Verteilungen beziehen sich auf IP-Pakete (Schicht 3), damit Mitschnitte
mit und ohne Ethernet-Header vergleichbar bleiben.

| Merkmal | Ebene | Typ | Maß |
|---|---|---|---|
| `paketgroesse` (IP-Gesamtlänge) | 1 | stetig | D, W1, W1_norm |
| `zwischenankunftszeit` | 1 | stetig | D, W1, W1_norm |
| `durchsatz_bytes`, `durchsatz_pakete` (je `--bin`, leere Intervalle zählen mit) | 1 | stetig | D, W1, W1_norm |
| `fluss_pakete`, `fluss_bytes`, `fluss_dauer` | 2 | stetig | D, W1, W1_norm |
| `gleichzeitige_fluesse` (je `--bin`) | 2 | stetig | D, W1, W1_norm |
| `protokolle`, `zielports` (je Fluss, `80/tcp`) | 2 | kategorial | JSD |
| `quellport_bereiche`, `ttl`, `tcp_fenster` | Zusatz | kategorial/stetig | JSD bzw. D, W1 |

W1_norm = W1 / (x_max − x_min) über alle Läufe und den Sollwert (Gl. 1.1).
Keine p-Werte. Skalare (`pakete`, `dauer_s`, mittlerer Durchsatz,
`anteil_unvollstaendige_tcp`, …) erhalten die relative Abweichung vom
Sollwert; als Schwelle dient der größte Abstand zweier Läufe, bezogen auf den
Sollwert.

Bis `--sample-cap` Werte (Standard 500 000) je Merkmal ist alles exakt,
darüber zieht ein Reservoir eine gleichmäßige Stichprobe (fester Startwert);
Minimum und Maximum bleiben exakt. Paketgröße, TTL, Fenster, Durchsatz und
gleichzeitige Flüsse sind immer exakte Histogramme.

## Sollwert-Spezifikation (`--spec`, Facette E2)

JSON, Beispiel in [`beispiele/sollwert_beispiel.json`](beispiele/sollwert_beispiel.json).

```json
{
  "beschreibung": "Freitext",
  "reichweite": ["paketgroesse", "zielports", "durchsatz_pakete_pro_s"],
  "verteilungen": {
    "paketgroesse": {"typ": "konstant", "wert": 60},
    "zwischenankunftszeit": {"typ": "exponentiell", "mittelwert": 0.001},
    "fluss_dauer": {"typ": "gleichverteilt", "min": 1, "max": 5},
    "fluss_bytes": {"typ": "lognormal", "mu": 6, "sigma": 1.2},
    "fluss_pakete": {"typ": "normal", "mittelwert": 20, "std": 4, "min_clip": 1},
    "tcp_fenster": {"typ": "empirisch", "werte": [8192, 65535], "gewichte": [3, 1]},
    "protokolle": {"typ": "kategorial", "anteile": {"TCP": 0.9, "UDP": 0.1}},
    "zielports": {"typ": "kategorial", "anteile": {"80/tcp": 1.0}}
  },
  "skalare": {"durchsatz_pakete_pro_s": 1000, "dauer_s": 60},
  "ablauf": [
    {"name": "Scan", "filter": {"proto": "TCP", "dst_port": [22, 80], "tcp_flags": "S"}},
    {"name": "C2", "filter": {"dst": "10.0.0.0/24", "port": 4444}, "min_pakete": 5}
  ]
}
```

Einheiten wie in der Merkmalstabelle (Byte, Sekunden, Pakete). Analytische
Verteilungen werden mit `--sample-cap` Werten und festem Startwert gezogen.
Filterfelder im Ablauf: `proto`, `src`, `dst` (Adresse oder Netz),
`src_port`, `dst_port`, `port` (Zahl, Liste oder `"1000-2000"`), `tcp_flags`
(alle genannten Flags gesetzt, Buchstaben `FSRPAUECN`). `reichweite` fehlt →
alle in der Spezifikation genannten Merkmale gelten als zugesichert;
`--assured` überschreibt. Fehler in der Spezifikation werden mit Klartext
abgewiesen.

Mit `--reference` (E3/E4) wird der Referenzmitschnitt mit genau derselben
Auswertung extrahiert wie die Läufe. Beide Quellen lassen sich kombinieren;
die Spezifikation hat dann je Merkmal Vorrang.

## Flussbildung

Bidirektionales Fünf-Tupel. Ein Fluss endet nach `--flow-timeout` Sekunden
Leerlauf (Standard 120) oder wenn nach FIN/RST ein neues SYN dasselbe Tupel
nutzt. Das abschließende ACK nach einem FIN erzeugt bewusst keinen neuen Fluss
(der von Engelen et al. an CICFlowMeter gezeigte Fehler). Randflüsse: fehlt
der Verbindungsaufbau und liegt der Flussbeginn innerhalb `--edge-margin` nach
Mitschnittbeginn, bzw. fehlt der Abbau und liegt das letzte Paket innerhalb
`--edge-margin` vor dem Ende, zählt der Fluss nicht als unvollständig
(Konzeption 1.5.2). Standard ist der Flow-Timeout; bei sehr kurzen
Mitschnitten kleiner wählen, sonst ist fast alles Randfluss.

## Änderungen gegenüber der Vorfassung

Für die Umsetzungsbeschreibung in der Arbeit relevant:

1. **Eigener pcap/pcapng-Leser statt scapy.** Keine Abhängigkeit mehr,
   ca. 35 000 Pakete/s je Prozess, mit `--jobs` parallel über Läufe. Die
   Prüfsummen werden direkt auf den Rohbytes nachgerechnet; ein Gegentest
   gegen scapy liegt in `tests/`. Die erzwungenen Speicherbereinigungen
   (Referenzzyklen der scapy-Objekte) entfallen.
2. **E2:** UDP an Multicast/Broadcast ist kein Verstoß mehr (mDNS, SSDP, DHCP,
   CoAP-Multicast sind gerade in IoT-Netzen alltäglich); TCP an
   Nicht-Unicast und Ziele aus 0.x/240.0.0.0/4 bleiben Verstöße.
3. **P3 prüft den Dienstport** statt beider Ports. Zufällige Quellports (DNS-
   Resolver randomisieren über 1024–65535) trafen sonst Tabelleneinträge wie
   1883 oder 3306. In der Port-Tabelle sind 443 (QUIC), 3389 (RDP über UDP),
   514 (Syslog über TCP) und 5683 (CoAP über TCP, RFC 8323) als mehrdeutig
   markiert; 502 (Modbus) und 8883 (MQTT/TLS) sind neu.
4. **Adressklassen als feste Tabelle** statt `ipaddress.is_private`, dessen
   Einstufung sich zwischen Python-Versionen geändert hat. Broadcast ist nur
   noch 255.255.255.255; übrige 255.x gelten als reserviert (P1 bleibt bei
   der Lesart „Quelle nicht 255.x“).
5. **E4** klassifiziert TCP-Verbindungen nach Zeek-ähnlichen Zuständen,
   schließt Randflüsse aus und wird nach Facette D gedeutet. Einseitige
   Flüsse stehen weiter in den Details.
6. **E5** ist ein Befund (`warnung`) statt `fehler`: bei Flood-Angriffen ist
   eine schmale Größenverteilung Angriffsinhalt.
7. **Neu:** E8–E10, AF1–AF7, alle Merkmale und Distanzmaße, Sollwert,
   Ablauf, Ebene 4, Validator-Meldungen, YAML-Ausgabe, SHA-256 je Datei.

Hinweis zur Benennung: Die Prüfungen E1–E10 (Eigenleistung) teilen sich die
Bezeichner mit den Werten der Facette E (E1–E4, Referenzbedarf). Im Skript
sind sie durch den Kontext getrennt; für den Text der Arbeit kann eine
Umbenennung (etwa `K1`–`K10`) Verwechslungen vermeiden.

## Grenzen

- Keine IP-Reassemblierung: Folgefragmente gehen in Paketmerkmale ein, aber
  keinem Fluss zu.
- Dienst- und IoT-Erkennung über Ports; ein Dienst auf einem Nichtstandardport
  wird nicht erkannt.
- TCP-Zustände aus dem Auftreten der Flags, nicht aus ihrer Reihenfolge:
  eine Näherung an Zeek, keine Nachbildung.
- Label-Konflikte werden auf Flussebene bestimmt (alle Pakete eines Flusses,
  dessen Fünf-Tupel im Zeitfenster auch im Hintergrund vorkommt). Das
  Zeitfenster setzt ausgerichtete Zeitachsen voraus; überlappen sie nicht,
  wird nur der zeitunabhängige Wert berichtet.
- Die Schwellen der Artefakte (AF) sind Lesehilfen, keine
  Signifikanzkriterien.

## Tests

```bash
pip install pytest pyyaml          # optional zusätzlich: scapy scipy
python -m pytest tests
```

Die Tests erzeugen ihre Mitschnitte selbst (`tests/pcapgen.py`). Mit scapy
werden die Prüfsummen, mit scipy D-Wert, Wasserstein-Distanz und
Jensen-Shannon-Divergenz gegengeprüft; ohne diese Pakete werden die
betreffenden Tests übersprungen.
