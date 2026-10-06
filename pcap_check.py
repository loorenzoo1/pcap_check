#!/usr/bin/env python3
"""
pcap_check.py — generatorunabhaengige Pruefung und Evaluation synthetischer
PCAP-Dateien (All-in-one-Werkzeug der Evaluation).

Das Werkzeug ist aus Analysen von NetShare entstanden, aber bewusst NICHT
NetShare-spezifisch: es nimmt beliebige Mitschnitte (pcap, pcapng, auch
gzip-komprimiert) und ist unveraendert auf ID2T, Caldera, Gotham und weitere
Werkzeuge anwendbar. Es deckt in einem Aufruf je Werkzeug ab:

  * Validierung   jedes Laufs (Format, Protokolltreue, Mitschnittqualitaet)
  * Ebene 1/2     Merkmalsverteilungen je Lauf (Paket- und Flussebene)
  * Diskrepanz    Eigenstreuung (paarweise zwischen den Laeufen) und
                  Sollabweichung (je Lauf gegen den Sollwert)
  * Ebene 3       Protokolltreue, strukturelle Vollstaendigkeit (Ablauf),
                  Erzeugungsartefakte (Pruefliste)
  * Ebene 4       optional gegen den Hintergrundverkehr: Sicherungsschicht,
                  Adresskollisionen, Label-Konflikte, Angriffsanteil

Das Ergebnis wird je Werkzeug in EINE Datei geschrieben (YAML, wahlweise
JSON) und zusaetzlich lesbar auf der Konsole ausgegeben.

PRUEFUNGEN
----------
Gruppe P — uebernommen aus [yin2022], Appendix B ("Protocol-compliant trace
generation"). Diese vier Tests bilden die im Evaluationskonzept festgelegte
Operationalisierung der Protokollkonformitaet.

  P1  Gueltigkeit der IP-Adressen: Quelle nicht Multicast (224.0.0.0/4) oder
      Broadcast (255.x.x.x); Ziel nicht aus 0.x.x.x.
  P2  Verhaeltnis Byte- zu Paketzahl. Nur fuer Flussdaten (NetFlow)
      definiert; auf Paketebene nicht anwendbar und daher als "n/a" gefuehrt.
  P3  Konsistenz von Portnummer und Protokoll (z.B. 123 -> UDP, 80 -> TCP),
      geprueft am Dienstport. Die Vorfassung pruefte beide Ports und zaehlte
      so zufaellige Client-Quellports (etwa eines DNS-Resolvers, der 1883
      zieht) als Verstoss.
  P4  Mindestpaketgroesse: TCP 40 Byte, UDP 28 Byte (IPv6: 60/48).

Gruppe E — Eigenleistung. Ergaenzt Luecken, die im Testlauf gegen NetShare
sichtbar wurden: Gruppe P winkt Faelle durch, die semantisch defekt sind
(E1, E2), und meldet Erfolg fuer Verhalten, das selbst der Defekt ist (E5).

  E1  Laengenkonsistenz: IP-Feld "Total Length" gegen tatsaechlich
      vorhandene Bytes. P4 ist hierfuer blind, weil ein ueberhoehtes
      Laengenfeld die Mindestgroesse formal erfuellt.
  E2  Ziel-Adressklassen: TCP an Multicast/Broadcast/reservierte Ziele ist
      ungueltig (TCP ist reines Unicast, RFC 1122). UDP an Multicast oder
      Broadcast ist dagegen Alltag (mDNS, SSDP, DHCP, CoAP-Multicast) und
      wird nicht beanstandet; reservierte und 0.x-Ziele schon.
  E3  Sicherungsschicht: Link-Type und Ethernet-Praesenz. Ohne L2-Header
      koennen viele IDS und Analysewerkzeuge den Mitschnitt nicht lesen.
  E4  Flussvollstaendigkeit: Zustand jeder TCP-Verbindung (angelehnt an die
      conn_state-Klassen von Zeek), einseitige Fluesse. Wird nach Facette D
      gedeutet: bei D1 sind unvollstaendige Verbindungen zu erwarten, bei D3
      ein Fehler. Randfluesse (am Anfang/Ende des Mitschnitts abgeschnitten)
      zaehlen nicht als unvollstaendig (Konzeption 1.5.2).
  E5  Verteilungsdegeneration: Abdeckung der Paketgroessenklassen und Zahl
      verschiedener Werte. Faengt den Fall ab, dass ein Generator P4 nur
      deshalb besteht, weil er kleine Pakete gar nicht erzeugt.
  E6  Zeitstempel: Monotonie, Duplikate, Nullabstaende, Plausibilitaet.
  E7  IP-Pruefsumme. Fuer NetShare wertlos, wenn die PCAP-Datei von scapy
      geschrieben wurde (scapy prueft dann seine eigene Rechnung). Bei ID2T,
      das Pakete in bestehende Mitschnitte injiziert und Pruefsummen selbst
      setzt, wird die Pruefung aussagekraeftig.
  E8  Transport-Pruefsummen (TCP, UDP, ICMP, ICMPv6) mit Pseudo-Header.
      Gehaeufte Fehler bei genau einer Quelle deuten auf Checksum-Offloading
      beim Mitschnitt auf dem sendenden Host hin, nicht auf den Generator.
  E9  TCP-Flags widerspruchsfrei (SYN+FIN, SYN+RST, FIN+RST, NULL, FIN ohne
      ACK, Xmas). Portscans erzeugen solche Pakete absichtlich; der Befund
      ist dann Angriffsinhalt, kein Generatorfehler.
  E10 Header-Struktur: IHL, TCP-Data-Offset, UDP-Laengenfeld, TTL 0,
      IP-Version passend zum Ethertype, IPv6-Nutzlastlaenge.

Gruppe AF — Erzeugungsartefakte, Pruefliste aus Konzeption 1.5.3. Liefern
Indikatoren, keine Fehler. "auffaellig" ist eine Lesehilfe, kein
Signifikanzkriterium.

  AF1 TTL-Vielfalt: viele Quelladressen, aber nur ein oder zwei TTL-Werte.
  AF2 Fortlaufende Adressen in der Reihenfolge ihres ersten Auftretens.
  AF3 Vorhersagbare Quellports: wiederholte Fuenf-Tupel neuer Verbindungen,
      wiederverwendete Quellports, fortlaufende Ports.
  AF4 MAC-Praefixe der Virtualisierung (VMware, VirtualBox, QEMU, ...).
  AF5 Zeitquantisierung: effektive Aufloesung der Zeitstempel.
  AF6 Gleichfoermige Taktung: Quartilsdispersion der Zwischenankunftszeiten
      (robust gegen einzelne Pausen) und Variationskoeffizient je Fluss.
  AF7 Nullnutzlast: Nutzdaten, die nur aus Nullbytes bestehen.

"Anteil fehlerhafter Pakete" (Guetekriterium Protokolltreue) ist der Anteil
der IP-Pakete mit mindestens einem Verstoss gegen P1, P3, P4, E1, E2, E9 oder
E10 (Header) bzw. E7, E8 (Pruefsummen). Beide Teilanteile werden gesondert
und zusammen ausgewiesen.

MERKMALE UND DISTANZMASSE (Konzeption 1.3.1, Tabelle 1.4)
--------------------------------------------------------
Alle Verteilungsmerkmale beziehen sich auf IP-Pakete (Schicht 3), damit
Mitschnitte mit und ohne Ethernet-Header vergleichbar bleiben.

  Ebene 1  paketgroesse (IP-Gesamtlaenge), zwischenankunftszeit,
           durchsatz_bytes / durchsatz_pakete (je Zeitintervall --bin)
  Ebene 2  fluss_pakete, fluss_bytes, fluss_dauer, gleichzeitige_fluesse,
           protokolle, zielports (je Fluss)
  Zusatz   quellport_bereiche, ttl, tcp_fenster (nicht in Tabelle 1.4; die
           Netzeigenschaften, die etwa ID2T aus dem Hintergrund schaetzt)

Stetige Merkmale erhalten den D-Wert (Kolmogorov-Smirnov-Statistik) und die
Wasserstein-Distanz W1, kategoriale die Jensen-Shannon-Divergenz (Basis 2).
W1 wird je Merkmal durch die gemeinsame Spannweite ueber alle Laeufe und den
Sollwert geteilt (Gleichung 1.1); W1 und D werden stets zusammen berichtet.
p-Werte werden bewusst nicht berechnet (Konzeption: keine Signifikanztests).

Eigenstreuung: alle paarweisen Distanzen der Laeufe (bei fuenf Laeufen zehn),
berichtet werden Median und Maximum. Sollabweichung: Distanz jedes Laufs zum
Sollwert; als Abweichung gilt nur, was das Maximum der Eigenstreuung
uebersteigt. Skalare Groessen erhalten die relative Abweichung vom Sollwert.

Der Sollwert kommt nach Facette E aus einem Mitschnitt (--reference; E3
Trainingsdaten, E4 Eingangsmitschnitt; mit derselben Auswertung extrahiert)
oder aus einer Konfiguration (--spec, JSON; E2). Analytische Verteilungen der
Spezifikation werden als Stichprobe mit festem Startwert gezogen. Ohne
Sollwert (E1) bleibt der Selbstvergleich.

FLUSSBILDUNG
------------
Ein Fluss ist das bidirektionale Fuenf-Tupel. Er endet nach --flow-timeout
Sekunden Leerlauf oder, wenn nach FIN/RST ein neues SYN dasselbe Tupel
wiederverwendet. Ein FIN beendet den Fluss bewusst nicht sofort: das
abschliessende ACK wuerde sonst einen Scheinfluss erzeugen, genau der Fehler,
den Engelen et al. an CICFlowMeter nachweisen.

SPEICHERVERHALTEN
-----------------
Die Pruefungen besitzen unterschiedliche Aggregierbarkeit:

  (a) Skalare und Histogramme (Paketgroesse, TTL, Fenster, Ports, Zaehler)
      werden fliessend und exakt fortgeschrieben; das Paket faellt danach aus
      dem Speicher.
  (b) Fluesse lassen sich nicht auf einen Skalar reduzieren, weil Hin- und
      Rueckrichtung zusammengefuehrt werden muessen. Gefuehrt werden nur die
      gerade AKTIVEN Fluesse (Integer-Schluessel, kurze Liste als Wert);
      abgelaufene Fluesse werden abgeschlossen und gehen nur noch in
      beschraenkte Aggregate ein. Der Speicher waechst daher mit der Zahl
      gleichzeitig aktiver Fluesse, nicht mit der Dateigroesse. Eine harte
      Obergrenze (--max-flows) bleibt; wird sie erreicht, steht das im
      Bericht.
  (c) Stichproben nur dort, wo eine Verteilung nicht als Histogramm passt
      (Zwischenankunftszeiten, Flussgroessen): Reservoir-Sampling
      (Algorithm R) bis --sample-cap Werte. Bis dahin ist alles exakt,
      darueber eine gleichmaessig ueber die Datei verteilte Stichprobe; das
      wird je Merkmal ausgewiesen. Minimum und Maximum werden immer exakt
      gefuehrt, damit die Spannweite fuer W1 nicht von der Stichprobe
      abhaengt. Auch die Beispiele zu Verstoessen werden per Reservoir
      gezogen, damit sie aus der ganzen Datei stammen und nicht nur aus dem
      Anfang.

Der Zufallsgenerator wird mit festem Startwert initialisiert (--seed), damit
wiederholte Laeufe identische Stichproben und Beispiele liefern.

Die Vorfassung las die Pakete mit scapy. Das war zu langsam fuer
Mitschnitte im Gigabyte-Bereich (fuenf Laeufe je Werkzeug plus Sollwert) und
erforderte wegen der Referenzzyklen in scapy-Paketobjekten erzwungene
Speicherbereinigungen. Dieses Werkzeug liest pcap/pcapng selbst und zerlegt
die Header direkt aus den Rohbytes: keine Fremdabhaengigkeit (nur die
Python-Standardbibliothek), exakter Zugriff auf jedes Byte (Pruefsummen,
Laengen) und kein Objektgraph je Paket.

Zeitstempel werden als ganze Nanosekunden gefuehrt. Eine Umwandlung nach
float wuerde bei Unix-Zeit in Nanosekundenaufloesung an die Grenze der
doppelten Genauigkeit stossen und benachbarte Zeitstempel faelschlich als
gleich ausweisen. Die Adressklassen sind als feste Tabelle hinterlegt statt
ueber das Modul ipaddress, dessen Einstufung sich zwischen Python-Versionen
geaendert hat; die Ergebnisse haengen so nicht von der Python-Version ab.

SNAPLEN UND ABGESCHNITTENE MITSCHNITTE
--------------------------------------
Wird ein Mitschnitt mit begrenzter Snapshot-Laenge aufgezeichnet, ist das
IP-Laengenfeld legitim groesser als die gespeicherten Bytes. Der Snaplen aus
dem Dateikopf ist dafuer kein brauchbares Kriterium (nur eine
Absichtserklaerung; libpcap schreibt seit 1.9 standardmaessig 262144). Das
exakte Kriterium steht in jedem Record-Header: orig_len > incl_len heisst,
dieser Record wurde abgeschnitten. E1 und die Pruefsummen (E7 ausgenommen,
der IP-Header ist fast immer vollstaendig) werten nur vollstaendige Records
und fuehren die uebrigen als "uebersprungen". Der Snaplen aus dem Dateikopf
wird nur als Diagnosewert berichtet.

AUFRUF
------
Eigenstaendiges Skript, Python >= 3.8, keine Paketinstallation:

    python pcap_check.py datei.pcap
    python pcap_check.py lauf1.pcap ... lauf5.pcap --tool ID2T \\
        --reference eingang.pcap --facet-d D1 --facet-e E4
    python pcap_check.py lauf*.pcap --tool Caldera --spec sollwert.json \\
        --background montag.pcap -o ergebnisse/caldera.yaml

Ausgabeformat nach Dateiendung: .yaml/.yml (Standard) oder .json.

Rueckgabewert: 0, wenn kein Lauf einen Fehler aufweist; 1 bei mindestens
einem Fehler oder einer unlesbaren Datei; mit --strict auch bei Warnungen;
2 bei ungueltigem Aufruf (etwa fehlerhafte Spezifikation).
Befunde der Referenz und des Hintergrunds werden berichtet, beeinflussen den
Rueckgabewert aber nicht.
"""
import argparse
import array
import bisect
import collections
import concurrent.futures
import datetime
import gzip
import hashlib
import io
import ipaddress
import json
import math
import os
import platform
import random
import re
import socket
import statistics
import struct
import sys
import time

__version__ = "2.0.0"

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

# Portnummern, die eindeutig ein Transportprotokoll implizieren (P3).
# Bewusst knapp gehalten: nur Faelle ohne Mehrdeutigkeit. None heisst
# "mehrdeutig, nicht pruefen".
PORT_PROTOCOL = {
    20: 6, 21: 6, 22: 6, 23: 6, 25: 6, 80: 6, 110: 6, 143: 6,
    445: 6, 993: 6, 995: 6, 3306: 6,
    53: None,          # DNS: TCP und UDP beide zulaessig
    443: None,         # HTTPS/TCP, aber QUIC bzw. HTTP/3 laeuft auf UDP 443
    3389: None,        # RDP nutzt seit Version 8 zusaetzlich UDP 3389
    514: None,         # Syslog: UDP 514, in der Praxis auch TCP 514
    67: 17, 68: 17, 69: 17, 123: 17, 161: 17, 162: 17,
    1900: 17, 5353: 17,
    1883: 6,           # MQTT
    8883: 6,           # MQTT ueber TLS
    502: 6,            # Modbus/TCP
    5683: None,        # CoAP: UDP, laut RFC 8323 aber auch TCP 5683
}

# minimale Gesamtlaenge in Bytes, die ein gueltiges Paket fuer das jeweilige
# Protokoll haben muss (P4); IPv6 mit 40 statt 20 Byte Grundheader
MINIMUM_TOTAL_LENGTH = {
    6: 40,   # TCP
    17: 28,  # UDP
    1: 28,   # ICMP
}
MINIMUM_TOTAL_LENGTH_V6 = {6: 60, 17: 48, 58: 48}

SIZE_CLASSES = [0, 64, 128, 256, 512, 768, 1024, 1280, 1518, 65535]

# Zielklassen, die fuer eine gerichtete Unicast-Verbindung nicht plausibel sind
NON_UNICAST_CLASSES = ("multicast", "broadcast", "null-netz", "reserviert",
                       "unspezifiziert")
# Zielklassen, die fuer kein Protokoll gueltig sind
INVALID_DESTINATION_CLASSES = ("null-netz", "reserviert", "unspezifiziert")

# Ergebnisse von check_length_consistency (E1)
LENGTH_OK = "ok"
LENGTH_PADDING = "padding"
LENGTH_MISMATCH = "mismatch"

EXAMPLE_CAPACITY = 5     # Deckelung: 100 % Verstossrate auf einer
                         # Millionen-Paket-Datei wuerde sonst die Datei fluten
DEFAULT_SEED = 20260101  # feste Vorgabe -> reproduzierbare Stichproben
DEFAULT_FLOW_LIMIT = 2_000_000   # gleichzeitig aktive Fluesse
DEFAULT_SAMPLE_CAP = 500_000     # Werte je Stichprobenmerkmal
DEFAULT_HOST_LIMIT = 200_000     # verschiedene Adressen je Zaehler
DEFAULT_BIN = 1.0                # Sekunden je Durchsatzintervall
DEFAULT_FLOW_TIMEOUT = 120.0     # Sekunden Leerlauf bis Flussende
DEFAULT_LABEL_WINDOW = 60.0      # Sekunden Zeitfenster fuer Label-Konflikte
RECOMMENDED_RUNS = 5             # Konzeption 1.3.1: fuenf Laeufe je Werkzeug

NS = 1_000_000_000
MAX_RECORD = 0x10000000  # 256 MiB; groessere Records sind kaputte Header

# Status je Pruefung, von gut nach schlecht
STATUS_OK = "ok"
STATUS_INFO = "info"
STATUS_NA = "n/a"
STATUS_WARN = "warnung"
STATUS_FAIL = "fehler"
STATUS_RANK = {STATUS_NA: 0, STATUS_OK: 0, STATUS_INFO: 0,
               STATUS_WARN: 1, STATUS_FAIL: 2}

GROUPS = collections.OrderedDict([
    ("protokolltreue", "Protokolltreue (Header und Pruefsummen)"),
    ("mitschnitt", "Mitschnitt (Format und Zeitstempel)"),
    ("befund", "Befunde (Deutung erforderlich)"),
    ("artefakt", "Erzeugungsartefakte (Pruefliste, Indikatoren)"),
])

PROTOCOL_NAMES = {
    1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM",
    112: "VRRP", 132: "SCTP",
}
PROTOCOL_NUMBERS = {name.lower(): number
                    for number, name in PROTOCOL_NAMES.items()}

LINKTYPE_NAMES = {
    0: "BSD-Loopback", 1: "Ethernet", 12: "Raw-IP", 14: "Raw-IP",
    101: "Raw-IP", 108: "OpenBSD-Loopback", 113: "Linux-SLL",
    127: "802.11-Radiotap", 228: "Raw-IPv4", 229: "Raw-IPv6",
    276: "Linux-SLL2",
}

ETHERTYPE_NAMES = {
    0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x88CC: "LLDP",
    0x8035: "RARP", 0x888E: "EAPOL", 0x88E5: "MACsec", 0x8847: "MPLS",
    0x8863: "PPPoE-Discovery", 0x8864: "PPPoE-Session",
}

# Dienstnamen fuer die Uebersicht (nur zur Lesbarkeit)
SERVICE_NAMES = {
    "20/tcp": "ftp-data", "21/tcp": "ftp", "22/tcp": "ssh",
    "23/tcp": "telnet", "25/tcp": "smtp", "53/udp": "dns", "53/tcp": "dns",
    "67/udp": "dhcp", "68/udp": "dhcp", "69/udp": "tftp", "80/tcp": "http",
    "110/tcp": "pop3", "123/udp": "ntp", "137/udp": "netbios-ns",
    "138/udp": "netbios-dgm", "139/tcp": "netbios-ssn", "143/tcp": "imap",
    "161/udp": "snmp", "162/udp": "snmp-trap", "389/tcp": "ldap",
    "443/tcp": "https", "443/udp": "quic", "445/tcp": "smb",
    "465/tcp": "smtps", "502/tcp": "modbus", "514/udp": "syslog",
    "554/tcp": "rtsp", "587/tcp": "submission", "993/tcp": "imaps",
    "995/tcp": "pop3s", "1883/tcp": "mqtt", "1900/udp": "ssdp",
    "2323/tcp": "telnet-alt", "3306/tcp": "mysql", "3389/tcp": "rdp",
    "5353/udp": "mdns", "5355/udp": "llmnr", "5683/udp": "coap",
    "5684/udp": "coaps", "8080/tcp": "http-alt", "8443/tcp": "https-alt",
    "8883/tcp": "mqtts", "20000/tcp": "dnp3", "47808/udp": "bacnet",
    "5672/tcp": "amqp", "5222/tcp": "xmpp", "102/tcp": "s7comm",
    "44818/tcp": "ethernet-ip",
}

# IoT-typische Dienste (portbasierte Heuristik, fuer die IoT-Eignung)
IOT_SERVICES = collections.OrderedDict([
    ("MQTT", ("1883/tcp", "8883/tcp")),
    ("CoAP", ("5683/udp", "5684/udp", "5683/tcp")),
    ("Modbus", ("502/tcp",)),
    ("RTSP", ("554/tcp",)),
    ("Telnet", ("23/tcp", "2323/tcp")),
    ("DNP3", ("20000/tcp",)),
    ("BACnet", ("47808/udp",)),
    ("AMQP", ("5672/tcp",)),
    ("XMPP", ("5222/tcp",)),
    ("S7comm", ("102/tcp",)),
    ("EtherNet/IP", ("44818/tcp",)),
    ("SSDP/UPnP", ("1900/udp",)),
    ("mDNS", ("5353/udp",)),
])

# OUI-Praefixe der Virtualisierung (AF4)
VIRTUAL_OUIS = {
    b"\x00\x05\x69": "VMware", b"\x00\x0c\x29": "VMware",
    b"\x00\x1c\x14": "VMware", b"\x00\x50\x56": "VMware",
    b"\x08\x00\x27": "VirtualBox", b"\x0a\x00\x27": "VirtualBox",
    b"\x52\x54\x00": "QEMU/KVM", b"\x00\x16\x3e": "Xen",
    b"\x00\x15\x5d": "Hyper-V", b"\x00\x1c\x42": "Parallels",
    b"\x00\x03\xff": "Virtual PC", b"\x00\x21\xf6": "Oracle VM",
}
DOCKER_PREFIX = b"\x02\x42"

# TCP-Flags
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS_FLAG = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x100)
TCP_FLAG_LETTERS = "FSRPAUECN"   # gleiche Reihenfolge wie scapy

# Bitfeld je Flussrichtung (acht Bit je Seite)
SIDE_SEEN = 0x01      # in dieser Richtung wurde gesendet
SIDE_SYN = 0x02       # reines SYN (ohne ACK)
SIDE_SYNACK = 0x04    # SYN+ACK
SIDE_FIN = 0x08
SIDE_RST = 0x10
SIDE_ACK = 0x20       # ACK ohne SYN (Verbindung in Benutzung)
SIDE_SHIFT = 8

# Verbindungszustaende (angelehnt an Zeek conn_state)
TCP_STATE_TEXT = collections.OrderedDict([
    ("SF", "aufgebaut und regulaer beendet"),
    ("RSTO", "aufgebaut, vom Initiator per RST abgebrochen"),
    ("RSTR", "aufgebaut, vom Antwortenden per RST abgebrochen"),
    ("REJ", "Verbindungsversuch abgewiesen (SYN -> RST)"),
    ("S0", "SYN ohne Antwort"),
    ("S1", "aufgebaut, nicht beendet"),
    ("S2", "aufgebaut, nur Initiator hat beendet"),
    ("S3", "aufgebaut, nur Antwortender hat beendet"),
    ("SH", "SYN, dann FIN ohne SYN-ACK"),
    ("SHR", "SYN-ACK ohne gesehenes SYN, dann FIN"),
    ("RSTOS0", "SYN, dann RST des Initiators ohne SYN-ACK"),
    ("RSTRH", "SYN-ACK ohne gesehenes SYN, dann RST"),
    ("OTH", "kein Verbindungsaufbau gesehen (mitten im Strom)"),
])
TCP_COMPLETE = ("SF", "RSTO", "RSTR")
TCP_REJECTED = ("REJ",)
TCP_MISSING_START = ("OTH", "SHR", "RSTRH")
TCP_MISSING_END = ("S0", "S1", "S2", "S3", "OTH")

# Merkmale der Ebenen 1 und 2 (Konzeption Tabelle 1.4 und Abbildung 1.2)
FEATURES = collections.OrderedDict([
    ("paketgroesse", {"ebene": 1, "typ": "stetig", "einheit": "Byte",
                      "konzept": True,
                      "text": "IP-Gesamtlaenge je Paket"}),
    ("zwischenankunftszeit", {"ebene": 1, "typ": "stetig", "einheit": "s",
                              "konzept": True,
                              "text": "Abstand aufeinanderfolgender IP-Pakete"}),
    ("durchsatz_bytes", {"ebene": 1, "typ": "stetig", "einheit": "Byte/Intervall",
                         "konzept": True,
                         "text": "IP-Bytes je Zeitintervall (Durchsatz im Verlauf)"}),
    ("durchsatz_pakete", {"ebene": 1, "typ": "stetig",
                          "einheit": "Pakete/Intervall", "konzept": True,
                          "text": "IP-Pakete je Zeitintervall"}),
    ("fluss_pakete", {"ebene": 2, "typ": "stetig", "einheit": "Pakete",
                      "konzept": True, "text": "Pakete je Fluss"}),
    ("fluss_bytes", {"ebene": 2, "typ": "stetig", "einheit": "Byte",
                     "konzept": True, "text": "IP-Bytes je Fluss"}),
    ("fluss_dauer", {"ebene": 2, "typ": "stetig", "einheit": "s",
                     "konzept": True, "text": "Dauer je Fluss"}),
    ("gleichzeitige_fluesse", {"ebene": 2, "typ": "stetig",
                               "einheit": "Fluesse", "konzept": True,
                               "text": "aktive Fluesse je Zeitintervall"}),
    ("protokolle", {"ebene": 2, "typ": "kategorial", "einheit": None,
                    "konzept": True, "text": "Transportprotokoll je Fluss"}),
    ("zielports", {"ebene": 2, "typ": "kategorial", "einheit": None,
                   "konzept": True,
                   "text": "Dienstport des Antwortenden je Fluss (port/proto)"}),
    ("quellport_bereiche", {"ebene": 2, "typ": "kategorial", "einheit": None,
                            "konzept": False,
                            "text": "Quellport des Initiators nach Bereich"}),
    ("ttl", {"ebene": 1, "typ": "kategorial", "einheit": None,
             "konzept": False, "text": "TTL bzw. Hop Limit je Paket"}),
    ("tcp_fenster", {"ebene": 1, "typ": "stetig", "einheit": "Byte",
                     "konzept": False, "text": "TCP-Fenstergroesse je Segment"}),
])

# Skalare Groessen (keine Verteilung; relative Abweichung vom Sollwert)
SCALARS = collections.OrderedDict([
    ("pakete", "IP-Pakete"),
    ("dauer_s", "Dauer des Mitschnitts in s"),
    ("durchsatz_pakete_pro_s", "mittlerer Durchsatz in IP-Paketen/s"),
    ("durchsatz_bytes_pro_s", "mittlerer Durchsatz in IP-Bytes/s"),
    ("fluesse", "abgeschlossene Fluesse"),
    ("anteil_unvollstaendige_tcp",
     "Anteil unvollstaendiger TCP-Verbindungen (ohne Randfluesse)"),
    ("anteil_einseitige_fluesse", "Anteil einseitiger Fluesse"),
    ("anteil_fehlerhafte_pakete", "Anteil fehlerhafter Pakete (Protokolltreue)"),
])

QUANTILES = (0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99)


# ---------------------------------------------------------------------------
# Lesen: pcap und pcapng
#
# Eigener Leser statt scapy: liefert je Record nur Link-Type, Zeitstempel in
# ganzen Nanosekunden, Drahtlaenge (orig_len) und die gespeicherten Bytes.
# Die SHA-256-Pruefsumme der Datei entsteht nebenbei beim Lesen; sie
# dokumentiert, welche Datei genau ausgewertet wurde.
# ---------------------------------------------------------------------------

class CaptureFormatError(Exception):
    """Datei ist kein lesbarer Mitschnitt."""


class _HashingRaw(io.RawIOBase):
    """Rohdatei, die alles Gelesene in eine SHA-256 einspeist."""

    def __init__(self, path):
        super().__init__()
        self._file = open(path, "rb", buffering=0)
        self.digest = hashlib.sha256()

    def readable(self):
        return True

    def readinto(self, buffer):
        count = self._file.readinto(buffer)
        if count:
            self.digest.update(memoryview(buffer)[:count])
        return count

    def finish(self):
        """Rest der Datei lesen, damit der Hash immer die ganze Datei deckt."""
        while True:
            chunk = self._file.read(1 << 20)
            if not chunk:
                break
            self.digest.update(chunk)
        return self.digest.hexdigest()

    def close(self):
        handle = getattr(self, "_file", None)
        if handle is not None:
            handle.close()
        super().close()


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000, "us"),   # little-endian, Mikrosekunden
    b"\xa1\xb2\xc3\xd4": (">", 1000, "us"),
    b"\x4d\x3c\xb2\xa1": ("<", 1, "ns"),      # Nanosekunden
    b"\xa1\xb2\x3c\x4d": (">", 1, "ns"),
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


class _Interface:
    """Interface Description Block (pcapng)."""
    __slots__ = ("linktype", "snaplen", "multiplier", "divisor", "shift",
                 "offset_ns", "fcs_len", "resolution")

    def __init__(self, linktype, snaplen):
        self.linktype = linktype
        self.snaplen = snaplen
        self.multiplier = 1000      # Standard: Mikrosekunden
        self.divisor = 1
        self.shift = 0
        self.offset_ns = 0
        self.fcs_len = 0
        self.resolution = "us"

    def set_resolution(self, value):
        exponent = value & 0x7F
        if value & 0x80:            # Zweierpotenz
            self.multiplier, self.divisor, self.shift = NS, 1, exponent
            self.resolution = f"2^-{exponent} s"
        elif exponent <= 9:
            self.multiplier, self.divisor, self.shift = 10 ** (9 - exponent), 1, 0
            self.resolution = {6: "us", 9: "ns", 3: "ms", 0: "s"}.get(
                exponent, f"1e-{exponent} s")
        else:
            self.multiplier, self.divisor, self.shift = 1, 10 ** (exponent - 9), 0
            self.resolution = f"1e-{exponent} s"

    def to_ns(self, ticks):
        value = ticks * self.multiplier
        if self.shift:
            value >>= self.shift
        if self.divisor != 1:
            value //= self.divisor
        return value + self.offset_ns


class CaptureReader:
    """Iteriert ueber (linktype, ts_ns, wirelen, data, fcs_len).

    ts_ns ist None, wenn der Record keinen Zeitstempel traegt (pcapng Simple
    Packet Block). Strukturfehler der Datei werden in `issues` gezaehlt statt
    eine Ausnahme zu werfen, damit eine teilweise lesbare Datei trotzdem
    ausgewertet und der Defekt berichtet wird.
    """

    def __init__(self, path):
        self.path = path
        self._raw = _HashingRaw(path)
        stream = io.BufferedReader(self._raw, buffer_size=1 << 20)
        self.compressed = stream.peek(2)[:2] == b"\x1f\x8b"
        if self.compressed:
            stream = io.BufferedReader(gzip.GzipFile(fileobj=stream),
                                       buffer_size=1 << 20)
        self._stream = stream
        self.format = None
        self.byte_order = None
        self.version = None
        self.snaplens = []
        self.link_types = set()
        self.resolutions = set()
        self.issues = collections.Counter()
        self.sha256 = None
        self.interfaces = []

        try:
            head = stream.peek(4)[:4]
        except (OSError, EOFError) as error:
            self.close()
            raise CaptureFormatError(f"Datei nicht lesbar: {error}")
        if head in PCAP_MAGICS:
            self._open_pcap()
        elif head == PCAPNG_SHB:
            self.format = "pcapng"
        else:
            self.close()
            raise CaptureFormatError(
                "unbekanntes Dateiformat (Magic "
                f"{head.hex() or 'leer'}; erwartet pcap oder pcapng)")

    # --- pcap ---------------------------------------------------------------

    def _open_pcap(self):
        header = self._stream.read(24)
        if len(header) < 24:
            self.close()
            raise CaptureFormatError("pcap-Dateikopf unvollstaendig")
        endian, tick_ns, resolution = PCAP_MAGICS[header[:4]]
        major, minor, _zone, _sigfigs, snaplen, network = struct.unpack(
            endian + "HHiIII", header[4:])
        self.format = "pcap"
        self.byte_order = "little" if endian == "<" else "big"
        self.version = f"{major}.{minor}"
        self._endian = endian
        self._tick_ns = tick_ns
        self.resolutions.add(resolution)
        self.snaplens.append(snaplen)
        # Unteres 16-Bit-Wort: Link-Type; Bit 26: FCS vorhanden, Bits 28-31:
        # FCS-Laenge in 16-Bit-Worten (draft-ietf-opsawg-pcap)
        self._linktype = network & 0xFFFF
        self._fcs_len = ((network >> 28) & 0xF) * 2 if network & (1 << 26) else 0
        self.link_types.add(self._linktype)

    def _iter_pcap(self):
        read = self._stream.read
        unpack = struct.Struct(self._endian + "IIII").unpack
        linktype, fcs_len, tick_ns = self._linktype, self._fcs_len, self._tick_ns
        fraction_limit = NS // tick_ns
        while True:
            header = read(16)
            if not header:
                return
            if len(header) < 16:
                self.issues["datei_endet_im_record_header"] += 1
                return
            seconds, fraction, incl_len, orig_len = unpack(header)
            if incl_len > MAX_RECORD:
                self.issues["record_laenge_unplausibel"] += 1
                return
            data = read(incl_len)
            if len(data) < incl_len:
                self.issues["datei_endet_im_record"] += 1
                return
            if fraction >= fraction_limit:
                self.issues["zeitstempel_bruchteil_ungueltig"] += 1
            yield linktype, seconds * NS + fraction * tick_ns, orig_len, data, fcs_len

    # --- pcapng -------------------------------------------------------------

    def _iter_pcapng(self):
        read = self._stream.read
        endian = "<"
        interfaces = []
        while True:
            head = read(8)
            if not head:
                return
            if len(head) < 8:
                self.issues["datei_endet_im_block_header"] += 1
                return
            if head[:4] == PCAPNG_SHB:
                magic = read(4)
                if magic == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif magic == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    self.issues["pcapng_byte_order_ungueltig"] += 1
                    return
                self.byte_order = "little" if endian == "<" else "big"
                length = struct.unpack(endian + "I", head[4:])[0]
                if length < 28 or length > MAX_RECORD:
                    self.issues["pcapng_block_laenge_unplausibel"] += 1
                    return
                rest = read(length - 12)
                if len(rest) < length - 12:
                    self.issues["datei_endet_im_block"] += 1
                    return
                major, minor = struct.unpack(endian + "HH", rest[:4])
                self.version = f"{major}.{minor}"
                interfaces = []          # neue Sektion, neue Interfaces
                self.interfaces = interfaces
                continue

            block_type, length = struct.unpack(endian + "II", head)
            if length < 12 or length % 4 or length > MAX_RECORD:
                self.issues["pcapng_block_laenge_unplausibel"] += 1
                return
            body = read(length - 8)
            if len(body) < length - 8:
                self.issues["datei_endet_im_block"] += 1
                return
            body = body[:-4]

            if block_type == 1:                       # Interface Description
                interfaces.append(self._parse_idb(body, endian))
            elif block_type == 6:                     # Enhanced Packet
                if len(body) < 20:
                    self.issues["pcapng_epb_zu_kurz"] += 1
                    continue
                iface_id, high, low, incl_len, orig_len = struct.unpack(
                    endian + "IIIII", body[:20])
                if iface_id >= len(interfaces):
                    self.issues["pcapng_interface_unbekannt"] += 1
                    continue
                iface = interfaces[iface_id]
                data = body[20:20 + incl_len]
                if len(data) < incl_len:
                    self.issues["pcapng_epb_daten_unvollstaendig"] += 1
                yield (iface.linktype, iface.to_ns((high << 32) | low),
                       orig_len, data, iface.fcs_len)
            elif block_type == 3:                     # Simple Packet
                if not interfaces or len(body) < 4:
                    self.issues["pcapng_spb_ohne_interface"] += 1
                    continue
                iface = interfaces[0]
                orig_len = struct.unpack(endian + "I", body[:4])[0]
                captured = orig_len
                if iface.snaplen:
                    captured = min(captured, iface.snaplen)
                self.issues["pcapng_spb_ohne_zeitstempel"] += 1
                yield (iface.linktype, None, orig_len, body[4:4 + captured],
                       iface.fcs_len)
            elif block_type == 2:                     # Packet Block (veraltet)
                if len(body) < 20:
                    continue
                iface_id, _drops, high, low, incl_len, orig_len = struct.unpack(
                    endian + "HHIIII", body[:20])
                if iface_id >= len(interfaces):
                    self.issues["pcapng_interface_unbekannt"] += 1
                    continue
                iface = interfaces[iface_id]
                yield (iface.linktype, iface.to_ns((high << 32) | low),
                       orig_len, body[20:20 + incl_len], iface.fcs_len)
            # alle anderen Bloecke (Statistik, Namensaufloesung, ...) tragen
            # keine Pakete und werden uebersprungen

    def _parse_idb(self, body, endian):
        if len(body) < 8:
            self.issues["pcapng_idb_zu_kurz"] += 1
            return _Interface(0, 0)
        linktype, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
        iface = _Interface(linktype, snaplen)
        position = 8
        while position + 4 <= len(body):
            code, size = struct.unpack(endian + "HH", body[position:position + 4])
            value = body[position + 4:position + 4 + size]
            position += 4 + ((size + 3) & ~3)
            if code == 0:
                break
            if code == 9 and size >= 1:               # if_tsresol
                iface.set_resolution(value[0])
            elif code == 14 and size >= 8:            # if_tsoffset (Sekunden)
                iface.offset_ns = struct.unpack(endian + "q", value[:8])[0] * NS
            elif code == 13 and size >= 1:            # if_fcslen
                iface.fcs_len = value[0]
        self.link_types.add(linktype)
        self.snaplens.append(snaplen)
        self.resolutions.add(iface.resolution)
        return iface

    # --- gemeinsam ----------------------------------------------------------

    def __iter__(self):
        try:
            if self.format == "pcap":
                yield from self._iter_pcap()
            else:
                yield from self._iter_pcapng()
        except (EOFError, OSError, gzip.BadGzipFile) as error:
            self.issues[f"lesefehler: {type(error).__name__}"] += 1

    @property
    def snaplen(self):
        """Snaplen aus dem Dateikopf. Reine Diagnose, steuert E1 nicht."""
        candidates = [value for value in self.snaplens if value]
        return min(candidates) if candidates else None

    def finish(self):
        """Datei zu Ende hashen und schliessen."""
        try:
            # gepufferte, aber noch nicht verarbeitete Bytes sind bereits
            # gehasht; der Rest wird direkt von der Rohdatei gelesen
            self.sha256 = self._raw.finish()
        finally:
            self.close()
        return self.sha256

    def close(self):
        try:
            self._raw.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


# ---------------------------------------------------------------------------
# Zerlegen der Header
#
# Nur die Felder, die Pruefungen und Merkmale brauchen. Strukturfehler werden
# im Paket vermerkt (structure_errors), nicht als Ausnahme geworfen.
# ---------------------------------------------------------------------------

VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100)
LOOPBACK_IPV4 = (2,)
LOOPBACK_IPV6 = (10, 24, 28, 30)


class Packet:
    """Zerlegtes Paket. Felder, die nicht vorkommen, bleiben None.

    Klassenattribute als Vorgabewerte statt __slots__: ein Paket lebt nur
    fuer einen Schleifendurchlauf, und das Anlegen ist so deutlich billiger
    als 30 Zuweisungen je Paket.
    """
    l2 = src_mac = dst_mac = ethertype = l3 = None
    vlan = 0
    ip_version = header_len = total_len = present_len = ttl = None
    proto = src = dst = fragment = frag_offset = None
    ip_checksum_ok = ip_checksum = None
    sport = dport = tcp_flags = tcp_window = icmp_type = None
    payload_len = payload_present = payload_zero = None
    l4_checksum_ok = l4_checksum_kind = l4_checksum = l4_expected = None
    udp_zero_checksum = None
    structure_errors = None

    def structure_error(self, text):
        if self.structure_errors is None:
            self.structure_errors = []
        self.structure_errors.append(text)

    @property
    def is_ip(self):
        return self.l3 in ("ipv4", "ipv6") and self.total_len is not None


def checksum_ok(data):
    """True, wenn die Einerkomplementsumme ueber data 0xFFFF ergibt.

    Die Einerkomplementsumme von 16-Bit-Worten ist kongruent zum Wert der
    Bytefolge als grosse Zahl modulo 0xFFFF, weil 2^16 = 1 (mod 0xFFFF).
    int.from_bytes rechnet das in C und ist um Groessenordnungen schneller als
    eine Schleife ueber die Worte.
    """
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    return int.from_bytes(data, "big") % 0xFFFF == 0


def internet_checksum(data):
    """Pruefsumme nach RFC 1071 ueber data (Pruefsummenfeld auf null)."""
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    value = int.from_bytes(data, "big")
    if value == 0:
        return 0xFFFF
    remainder = value % 0xFFFF
    return 0xFFFF - remainder if remainder else 0


def _expected_checksum(pseudo, segment, field_offset):
    """Neu berechnete Pruefsumme, nur fuer Beispiele zu Verstoessen."""
    zeroed = bytearray(segment)
    zeroed[field_offset:field_offset + 2] = b"\x00\x00"
    return internet_checksum(pseudo + bytes(zeroed))


def dissect(linktype, data, fcs_len=0, truncated=False):
    """Zerlegt einen Record in ein Packet."""
    packet = Packet()
    if fcs_len and not truncated and len(data) > fcs_len:
        data = data[:-fcs_len]
    length = len(data)
    offset = 0
    ethertype = None

    if linktype == 1:                                   # Ethernet
        if length < 14:
            packet.structure_error("ethernet_header_zu_kurz")
            return packet
        packet.l2 = "ethernet"
        packet.dst_mac = data[0:6]
        packet.src_mac = data[6:12]
        ethertype = (data[12] << 8) | data[13]
        offset = 14
        while ethertype in VLAN_ETHERTYPES and length >= offset + 4:
            packet.vlan += 1
            ethertype = (data[offset + 2] << 8) | data[offset + 3]
            offset += 4
        if ethertype <= 1500:                           # 802.3 mit LLC
            packet.ethertype = ethertype
            packet.l3 = "llc"
            return packet
    elif linktype in (101, 12, 14, 228, 229):           # rohes IP
        packet.l2 = "raw"
        if length == 0:
            return packet
        version = data[0] >> 4
        ethertype = {4: 0x0800, 6: 0x86DD}.get(version)
        if linktype == 228:
            ethertype = 0x0800
        elif linktype == 229:
            ethertype = 0x86DD
    elif linktype == 113:                               # Linux cooked v1
        if length < 16:
            packet.structure_error("sll_header_zu_kurz")
            return packet
        packet.l2 = "sll"
        hatype, address_length = struct.unpack("!HH", data[2:6])
        if hatype == 1 and address_length == 6:
            packet.src_mac = data[6:12]
        ethertype = (data[14] << 8) | data[15]
        offset = 16
    elif linktype == 276:                               # Linux cooked v2
        if length < 20:
            packet.structure_error("sll2_header_zu_kurz")
            return packet
        packet.l2 = "sll"
        ethertype = (data[0] << 8) | data[1]
        if data[8:10] == b"\x00\x01" and data[11] == 6:
            packet.src_mac = data[12:18]
        offset = 20
    elif linktype in (0, 108):                          # BSD-Loopback
        if length < 4:
            return packet
        packet.l2 = "loopback"
        family_le = struct.unpack("<I", data[:4])[0]
        family_be = struct.unpack(">I", data[:4])[0]
        family = family_le if family_le < 256 else family_be
        if family in LOOPBACK_IPV4:
            ethertype = 0x0800
        elif family in LOOPBACK_IPV6:
            ethertype = 0x86DD
        offset = 4
    else:
        return packet                                   # Link-Type unbekannt

    packet.ethertype = ethertype
    if ethertype == 0x0800:
        _dissect_ipv4(packet, data, offset, truncated)
    elif ethertype == 0x86DD:
        _dissect_ipv6(packet, data, offset, truncated)
    elif ethertype == 0x0806:
        packet.l3 = "arp"
    else:
        packet.l3 = "andere"
    return packet


def _dissect_ipv4(packet, data, offset, truncated):
    packet.l3 = "ipv4"
    available = len(data) - offset
    if available < 20:
        if not truncated:
            packet.structure_error("ipv4_header_unvollstaendig")
        return
    first = data[offset]
    packet.ip_version = first >> 4
    header_len = (first & 0x0F) * 4
    if packet.ip_version != 4:
        packet.structure_error("ip_version_passt_nicht_zum_ethertype")
        return
    if header_len < 20:
        packet.structure_error("ipv4_ihl_kleiner_5")
        return
    if header_len > available:
        if not truncated:
            packet.structure_error("ipv4_ihl_ueber_paketende")
        return
    total_len, _ident, flags_fragment, ttl, proto, checksum = struct.unpack(
        "!HHHBBH", data[offset + 2:offset + 12])
    packet.header_len = header_len
    packet.total_len = total_len
    packet.present_len = available
    packet.ttl = ttl
    packet.proto = proto
    packet.src = data[offset + 12:offset + 16]
    packet.dst = data[offset + 16:offset + 20]
    packet.frag_offset = (flags_fragment & 0x1FFF) * 8
    packet.fragment = bool(flags_fragment & 0x2000) or packet.frag_offset > 0
    packet.ip_checksum = checksum
    packet.ip_checksum_ok = checksum_ok(data[offset:offset + header_len])
    if ttl == 0:
        packet.structure_error("ttl_null")
    if total_len < header_len:
        packet.structure_error("ipv4_laenge_kleiner_header")
        return
    if packet.frag_offset:
        return                       # kein Transport-Header in Folgefragmenten
    segment_start = offset + header_len
    segment_len = total_len - header_len
    pseudo = (packet.src + packet.dst + bytes((0, proto))
              + struct.pack("!H", segment_len))
    _dissect_transport(packet, data, segment_start, segment_len, pseudo,
                       truncated, ipv6=False)


IPV6_EXTENSIONS = (0, 43, 44, 60, 51)


def _dissect_ipv6(packet, data, offset, truncated):
    packet.l3 = "ipv6"
    available = len(data) - offset
    if available < 40:
        if not truncated:
            packet.structure_error("ipv6_header_unvollstaendig")
        return
    packet.ip_version = data[offset] >> 4
    if packet.ip_version != 6:
        packet.structure_error("ip_version_passt_nicht_zum_ethertype")
        return
    payload_len, next_header, hop_limit = struct.unpack(
        "!HBB", data[offset + 4:offset + 8])
    packet.header_len = 40
    packet.total_len = 40 + payload_len
    packet.present_len = available
    packet.ttl = hop_limit
    packet.src = data[offset + 8:offset + 24]
    packet.dst = data[offset + 24:offset + 40]
    if hop_limit == 0:
        packet.structure_error("ttl_null")
    position = offset + 40
    end = offset + 40 + payload_len
    # Erweiterungsheader bis zum Transportprotokoll ueberspringen
    for _ in range(8):
        if next_header not in IPV6_EXTENSIONS:
            break
        if position + 8 > len(data):
            packet.proto = next_header
            return
        if next_header == 44:                          # Fragment-Header
            fragment_word = struct.unpack("!H", data[position + 2:position + 4])[0]
            packet.frag_offset = (fragment_word >> 3) * 8
            packet.fragment = True
            next_header = data[position]
            position += 8
            if packet.frag_offset:
                packet.proto = next_header
                return
            continue
        if next_header == 51:                          # AH: Laenge in 4 Byte
            ext_len = (data[position + 1] + 2) * 4
        else:
            ext_len = (data[position + 1] + 1) * 8
        next_header = data[position]
        position += ext_len
    packet.proto = next_header
    if packet.fragment is None:
        packet.fragment = False
    segment_len = end - position
    if segment_len < 0:
        packet.structure_error("ipv6_erweiterungsheader_ueber_nutzlast")
        return
    pseudo = (packet.src + packet.dst + struct.pack("!I", segment_len)
              + b"\x00\x00\x00" + bytes((next_header,)))
    _dissect_transport(packet, data, position, segment_len, pseudo,
                       truncated, ipv6=True)


def _dissect_transport(packet, data, start, declared_len, pseudo, truncated,
                       ipv6):
    """TCP, UDP, ICMP und ICMPv6 ab `start`; declared_len aus dem IP-Header."""
    proto = packet.proto
    present_end = len(data)
    declared_end = start + declared_len
    complete = declared_end <= present_end
    segment_end = min(declared_end, present_end)
    available = segment_end - start
    # Pruefsummen nur ueber vollstaendige, unfragmentierte Segmente
    verifiable = complete and not packet.fragment and not truncated

    if proto == 6:
        if available < 20:
            if complete:
                packet.structure_error("tcp_header_unvollstaendig")
            return
        (packet.sport, packet.dport, _seq, _ack, offset_flags, packet.tcp_window,
         checksum, _urgent) = struct.unpack("!HHIIHHHH", data[start:start + 20])
        data_offset = (offset_flags >> 12) * 4
        packet.tcp_flags = offset_flags & 0x01FF
        if data_offset < 20:
            packet.structure_error("tcp_data_offset_kleiner_5")
            return
        if data_offset > declared_len:
            packet.structure_error("tcp_data_offset_ueber_segment")
            return
        packet.payload_len = declared_len - data_offset
        packet.payload_present = max(segment_end - start - data_offset, 0)
        if packet.payload_len > 0 and packet.payload_present:
            payload = data[start + data_offset:segment_end]
            packet.payload_zero = payload.count(0) == len(payload)
        if verifiable:
            segment = data[start:declared_end]
            packet.l4_checksum_kind = "tcp"
            packet.l4_checksum = checksum
            packet.l4_checksum_ok = checksum_ok(pseudo + segment)
            if not packet.l4_checksum_ok:
                packet.l4_expected = _expected_checksum(pseudo, segment, 16)

    elif proto == 17:
        if available < 8:
            if complete:
                packet.structure_error("udp_header_unvollstaendig")
            return
        packet.sport, packet.dport, udp_len, checksum = struct.unpack(
            "!HHHH", data[start:start + 8])
        if udp_len < 8:
            packet.structure_error("udp_laenge_kleiner_8")
        elif udp_len != declared_len and not packet.fragment:
            packet.structure_error("udp_laenge_passt_nicht_zur_ip_laenge")
        packet.payload_len = max(declared_len - 8, 0)
        packet.payload_present = max(segment_end - start - 8, 0)
        if packet.payload_len > 0 and packet.payload_present:
            payload = data[start + 8:segment_end]
            packet.payload_zero = payload.count(0) == len(payload)
        if checksum == 0:
            if ipv6:
                packet.structure_error("udp_pruefsumme_null_bei_ipv6")
            else:
                packet.udp_zero_checksum = True   # in IPv4 zulaessig
        elif verifiable:
            segment = data[start:declared_end]
            packet.l4_checksum_kind = "udp"
            packet.l4_checksum = checksum
            packet.l4_checksum_ok = checksum_ok(pseudo + segment)
            if not packet.l4_checksum_ok:
                expected = _expected_checksum(pseudo, segment, 6)
                packet.l4_expected = expected or 0xFFFF

    elif proto in (1, 58):
        if available < 4:
            if complete:
                packet.structure_error("icmp_header_unvollstaendig")
            return
        packet.icmp_type = data[start]
        checksum = struct.unpack("!H", data[start + 2:start + 4])[0]
        packet.payload_len = max(declared_len - 8, 0)
        if verifiable:
            segment = data[start:declared_end]
            prefix = pseudo if proto == 58 else b""
            packet.l4_checksum_kind = "icmpv6" if proto == 58 else "icmp"
            packet.l4_checksum = checksum
            packet.l4_checksum_ok = checksum_ok(prefix + segment)
            if not packet.l4_checksum_ok:
                packet.l4_expected = _expected_checksum(prefix, segment, 2)


# ---------------------------------------------------------------------------
# Einzelpruefungen als freistehende Funktionen
#
# Ausgelagert, damit jede Pruefung ohne PCAP-Datei einzeln testbar ist. Die
# Paketschleife ruft sie nur noch auf und fuehrt selbst keine Pruefregel.
# ---------------------------------------------------------------------------

def classify_ipv4_int(value):
    """Grobklassifikation einer IPv4-Adresse als 32-Bit-Zahl.

    Feste Tabelle statt ipaddress.is_private & Co., deren Einstufung sich
    zwischen Python-Versionen geaendert hat.
    """
    first = value >> 24
    if value >> 28 == 0xE:
        return "multicast"
    if value == 0xFFFFFFFF:
        return "broadcast"
    if first == 0:
        return "null-netz"
    if value >> 28 == 0xF:
        return "reserviert"
    if first == 127:
        return "loopback"
    if first == 10 or value >> 20 == 0xAC1 or value >> 16 == 0xC0A8:
        return "privat"
    if value >> 16 == 0xA9FE:
        return "link-lokal"
    if value >> 22 == 0x191:                       # 100.64.0.0/10
        return "cgnat"
    if value >> 8 in (0xC00002, 0xC63364, 0xCB0071):
        return "dokumentation"                     # RFC 5737
    if value >> 17 == 0x6309:                      # 198.18.0.0/15
        return "benchmark"
    return "oeffentlich"


def classify_ipv6_bytes(raw):
    """Grobklassifikation einer IPv6-Adresse (16 Byte)."""
    if raw == b"\x00" * 16:
        return "unspezifiziert"
    if raw == b"\x00" * 15 + b"\x01":
        return "loopback"
    if raw[0] == 0xFF:
        return "multicast"
    if raw[0] == 0xFE and raw[1] & 0xC0 == 0x80:
        return "link-lokal"
    if raw[0] & 0xFE == 0xFC:
        return "privat"
    if raw[:4] == b"\x20\x01\x0d\xb8":
        return "dokumentation"
    if raw[:12] == b"\x00" * 10 + b"\xff\xff":
        return "ipv4-abgebildet"
    return "oeffentlich"


def classify_ip(address):
    """Grobklassifikation einer IP-Adresse in Textform (IPv4 oder IPv6)."""
    try:
        if ":" in address:
            return classify_ipv6_bytes(socket.inet_pton(socket.AF_INET6, address))
        return classify_ipv4_int(struct.unpack("!I", socket.inet_aton(address))[0])
    except (OSError, ValueError, TypeError):
        return "ungueltig"


def check_address_validity(source, destination):
    """P1 nach [yin2022]: Quelle nicht Multicast/Broadcast, Ziel nicht 0.x."""
    try:
        source_int = struct.unpack("!I", socket.inet_aton(source))[0]
        destination_int = struct.unpack("!I", socket.inet_aton(destination))[0]
    except (OSError, TypeError):
        return False
    return address_valid_v4(source_int, destination_int)


def address_valid_v4(source_int, destination_int):
    """P1 auf Zahlen: Quelle nicht 224.0.0.0/4 und nicht 255.x, Ziel nicht 0.x."""
    if source_int >> 28 == 0xE or source_int >> 24 == 0xFF:
        return False
    return destination_int >> 24 != 0


def address_valid_v6(source_raw, destination_raw):
    """P1 sinngemaess fuer IPv6: Quelle nicht Multicast, Ziel nicht '::'."""
    return source_raw[0] != 0xFF and destination_raw != b"\x00" * 16


def check_port_protocol(port, protocol):
    """P3. Rueckgabe None, wenn der Port kein Protokoll impliziert."""
    expected = PORT_PROTOCOL.get(port)
    if expected is None:
        return None
    return protocol == expected


def check_minimum_length(protocol, total_length, ipv6=False):
    """P4. Rueckgabe None fuer Protokolle ohne festgelegtes Minimum."""
    table = MINIMUM_TOTAL_LENGTH_V6 if ipv6 else MINIMUM_TOTAL_LENGTH
    minimum = table.get(protocol)
    if minimum is None:
        return None
    # >= : sowohl reine Kontrollpakete als auch Pakete mit Daten
    return total_length >= minimum


def check_length_consistency(declared_length, present_bytes):
    """E1. Liefert (Befundart, Differenz).

    Die Richtung ist entscheidend: nur declared_length > tatsaechliche Bytes
    ist ein Defekt — der Header behauptet Daten, die nicht da sind. Der
    umgekehrte Fall ist meist Ethernet-Padding und kein Defekt: Frames unter
    60 Byte werden aufgefuellt, das Padding zaehlt zu den Bytes, nicht zu
    ip.len. Waere das ein Defekt, fiele jeder reale Mitschnitt durch und die
    Pruefung waere wertlos.
    """
    difference = declared_length - present_bytes
    if difference > 0:
        return LENGTH_MISMATCH, difference
    if difference < 0:
        return LENGTH_PADDING, difference
    return LENGTH_OK, 0


def check_destination_class(protocol, destination_class):
    """E2. TCP braucht ein Unicast-Ziel; 0.x/reserviert ist nie gueltig.

    UDP an Multicast oder Broadcast ist regulaerer Verkehr (mDNS, SSDP,
    DHCP, NetBIOS, CoAP-Multicast) und gerade in IoT-Netzen haeufig; die
    Vorfassung hat das als Verstoss gewertet. ICMP an Broadcast ist
    ebenfalls unauffaellig.
    """
    if destination_class in INVALID_DESTINATION_CLASSES:
        return False
    if protocol == 6 and destination_class in NON_UNICAST_CLASSES:
        return False
    return True


def size_class_index(total_length):
    """Index der oberen Klassengrenze in SIZE_CLASSES, sonst None.

    Entspricht dem Intervall SIZE_CLASSES[i-1] < laenge <= SIZE_CLASSES[i].
    """
    index = bisect.bisect_left(SIZE_CLASSES, total_length)
    if index == 0 or index >= len(SIZE_CLASSES):
        return None
    return index


def check_size_degeneration(class_counts, total):
    """E5. Liefert (bestanden, Kennzahlen).

    Degeneriert, wenn zwei oder weniger Klassen belegt sind oder eine Klasse
    mehr als 90 Prozent aufnimmt.
    """
    if not class_counts or total <= 0:
        return False, {"belegte_klassen": 0,
                       "klassen_gesamt": len(SIZE_CLASSES) - 1,
                       "groesster_klassenanteil": None,
                       "verteilung": {}}
    occupied = len(class_counts)
    largest_share = max(class_counts.values()) / total
    passed = occupied > 2 and largest_share <= 0.9
    return passed, {
        "belegte_klassen": occupied,
        "klassen_gesamt": len(SIZE_CLASSES) - 1,
        "groesster_klassenanteil": round(largest_share, 4),
        "verteilung": {f"bis {k}": round(v / total, 4)
                       for k, v in sorted(class_counts.items())},
    }


def check_tcp_flags(flags):
    """E9. None, wenn die Flag-Kombination widerspruchsfrei ist, sonst Name."""
    core = flags & 0x3F                      # ECE, CWR, NS sind unabhaengig
    if core == 0:
        return "NULL (keine Flags)"
    if core & SYN and core & FIN:
        return "SYN+FIN"
    if core & SYN and core & RST:
        return "SYN+RST"
    if core & FIN and core & RST:
        return "FIN+RST"
    if not core & ACK:
        if core & (FIN | PSH | URG) == FIN | PSH | URG:
            return "Xmas (FIN+PSH+URG)"
        if core & FIN:
            return "FIN ohne ACK"
        if core & (PSH | URG):
            return "PSH/URG ohne ACK"
    return None


def tcp_flag_text(flags):
    """Flags als Buchstaben wie bei scapy, etwa 'SA' fuer SYN-ACK."""
    text = "".join(letter for bit, letter in enumerate(TCP_FLAG_LETTERS)
                   if flags & (1 << bit))
    return text or "0"


def is_truncated(wirelen, caplen):
    """True, wenn der Record abgeschnitten gespeichert wurde.

    Exaktes Kriterium fuer Snaplen-Effekte: der Record-Header fuehrt orig_len
    (Draht) und incl_len (Datei). Ist orig_len groesser, fehlen Daten, und
    E1 sowie die Transport-Pruefsummen duerfen nicht als Verstoss werten.
    """
    if wirelen is None:
        return False
    return wirelen > caplen


def port_range(port):
    """Quellport-Bereich (IANA, ergaenzt um die Ephemeral-Bereiche der OS).

    0-1023 well-known; 1024-32767 registriert; 32768-49151 nur Linux-
    ephemer; 49152-60999 Linux- und Windows-ephemer; 61000-65535 nur
    Windows/IANA-dynamisch.
    """
    if port < 1024:
        return "0-1023"
    if port < 32768:
        return "1024-32767"
    if port < 49152:
        return "32768-49151"
    if port < 61000:
        return "49152-60999"
    return "61000-65535"


def format_address(raw):
    """Adresse aus Rohbytes als Text."""
    if raw is None:
        return None
    if len(raw) == 4:
        return socket.inet_ntoa(raw)
    return socket.inet_ntop(socket.AF_INET6, raw)


def format_mac(raw):
    return ":".join(f"{byte:02x}" for byte in raw)


def protocol_name(number):
    return PROTOCOL_NAMES.get(number, str(number))


def service_key(port, proto):
    """Dienstbezeichnung je Fluss, etwa '80/tcp'; sonst Protokollname."""
    if proto == 6:
        return f"{port}/tcp"
    if proto == 17:
        return f"{port}/udp"
    return protocol_name(proto).lower()


def mac_vendor(raw):
    """Virtualisierungshersteller zur MAC oder None."""
    vendor = VIRTUAL_OUIS.get(raw[:3])
    if vendor:
        return vendor
    if raw[:2] == DOCKER_PREFIX:
        return "Docker"
    return None


# ---------------------------------------------------------------------------
# Hilfsstrukturen
# ---------------------------------------------------------------------------

class ExampleReservoir:
    """Reservoir-Sampling (Algorithm R) fuer Beispiele zu Verstoessen.

    Haelt hoechstens `capacity` Elemente und ersetzt danach mit
    Wahrscheinlichkeit capacity/n, sodass jedes angebotene Element mit gleicher
    Wahrscheinlichkeit im Reservoir landet. Damit stammen die Beispiele aus der
    gesamten Datei statt nur aus deren Anfang. Der Zufallsgenerator wird von
    aussen gesetzt, damit die Auswahl bei gleichem Startwert reproduzierbar ist.
    """

    def __init__(self, capacity, rng):
        self.capacity = capacity
        self.rng = rng
        self.items = []
        self.seen = 0

    def offer(self, item):
        self.seen += 1
        if len(self.items) < self.capacity:
            self.items.append(item)
            return
        index = self.rng.randrange(self.seen)
        if index < self.capacity:
            self.items[index] = item


class Check:
    """Eine Pruefung mit Zaehlern, Beispielen und Status.

    `severity` ist der Status, der bei Verstoessen gilt: "fehler" fuer harte
    Pruefungen, "warnung" fuer Befunde. Pruefungen, deren Status sich erst aus
    dem Zusammenhang ergibt (E4 nach Facette D, Artefakte), setzen ihn ueber
    `status_override`.
    """

    def __init__(self, key, name, group, rng, severity=STATUS_FAIL,
                 applicable=True, origin="Eigenleistung"):
        self.key = key
        self.name = name
        self.group = group
        self.severity = severity
        self.applicable = applicable
        self.origin = origin
        self.checked = 0
        self.violations = 0
        self.skipped = 0
        self.examples = ExampleReservoir(EXAMPLE_CAPACITY, rng)
        self.extra = collections.OrderedDict()
        self.status_override = None
        self.note = None

    def record(self, passed, example=None):
        """Einzelbefund verbuchen."""
        self.checked += 1
        if not passed:
            self.violations += 1
            if example is not None:
                self.examples.offer(example)

    def skip(self, count=1):
        """Records, fuer die die Pruefung nicht entscheidbar ist."""
        self.skipped += count

    def set_result(self, passed, checked=1, violations=None):
        """Aggregierte Pruefungen, die erst nach der Schleife feststehen."""
        self.checked = checked
        if violations is None:
            self.violations = 0 if passed else 1
        else:
            self.violations = violations

    @property
    def decidable(self):
        """False, wenn nichts geprueft werden konnte (etwa alles skipped)."""
        return self.applicable and self.checked > 0

    @property
    def pass_ratio(self):
        if self.checked == 0:
            return None
        return (self.checked - self.violations) / self.checked

    @property
    def status(self):
        if self.status_override is not None:
            return self.status_override
        if not self.decidable:
            return STATUS_NA
        if self.violations == 0:
            return STATUS_OK
        return self.severity

    def to_dict(self):
        data = collections.OrderedDict([
            ("id", self.key),
            ("name", self.name),
            ("gruppe", self.group),
            ("herkunft", self.origin),
            ("status", self.status),
            ("geprueft", self.checked),
            ("verstoesse", self.violations),
            ("uebersprungen", self.skipped),
            ("anteil_ok", None if self.pass_ratio is None
             else round(self.pass_ratio, 6)),
        ])
        if self.note:
            data["hinweis"] = self.note
        if self.examples.items:
            data["beispiele"] = list(self.examples.items)
        if self.extra:
            data["details"] = self.extra
        return data


class RunningStats:
    """Mittelwert und Streuung fliessend (Welford), exakt ueber alle Werte."""
    __slots__ = ("count", "mean", "m2")

    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0

    def add(self, value):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def std(self):
        return math.sqrt(self.m2 / self.count) if self.count else None

    @property
    def cv(self):
        """Variationskoeffizient (Standardabweichung / Mittelwert)."""
        if not self.count or self.mean <= 0:
            return None
        return self.std / self.mean


class ValueSample:
    """Reservoir (Algorithm R) fuer Zahlenwerte, Minimum/Maximum exakt."""

    def __init__(self, capacity, rng):
        self.capacity = capacity
        self.rng = rng
        self.values = array.array("d")
        self.seen = 0
        self.minimum = None
        self.maximum = None

    def add(self, value):
        self.seen += 1
        if self.minimum is None or value < self.minimum:
            self.minimum = value
        if self.maximum is None or value > self.maximum:
            self.maximum = value
        if len(self.values) < self.capacity:
            self.values.append(value)
            return
        index = self.rng.randrange(self.seen)
        if index < self.capacity:
            self.values[index] = value

    def distribution(self, scale=1.0):
        return Distribution.from_values(
            self.values, scale=scale, population=self.seen,
            minimum=None if self.minimum is None else self.minimum * scale,
            maximum=None if self.maximum is None else self.maximum * scale)


class Distribution:
    """Gewichtete empirische Verteilung: sortierte, eindeutige Werte mit
    Haeufigkeiten. Grundlage fuer D-Wert und Wasserstein-Distanz.

    `exact` ist False, wenn die Werte eine Reservoir-Stichprobe sind;
    `population` ist dann die Zahl aller beobachteten Werte. minimum und
    maximum sind immer die exakten Grenzen aller beobachteten Werte.
    """
    __slots__ = ("values", "weights", "total", "population", "exact",
                 "minimum", "maximum")

    def __init__(self, values, weights, population=None, minimum=None,
                 maximum=None):
        self.values = values
        self.weights = weights
        self.total = math.fsum(weights)
        self.population = self.total if population is None else population
        self.exact = population is None or population <= self.total
        if values:
            self.minimum = values[0] if minimum is None else minimum
            self.maximum = values[-1] if maximum is None else maximum
        else:
            self.minimum = minimum
            self.maximum = maximum

    @classmethod
    def from_counter(cls, counter, scale=1.0):
        items = sorted((float(k) * scale, float(v))
                       for k, v in counter.items() if v > 0)
        return cls(array.array("d", (k for k, _ in items)),
                   array.array("d", (v for _, v in items)))

    @classmethod
    def from_values(cls, values, scale=1.0, population=None, minimum=None,
                    maximum=None):
        ordered = sorted(values)
        unique = array.array("d")
        weights = array.array("d")
        previous = None
        for value in ordered:
            if value == previous:
                weights[-1] += 1.0
            else:
                unique.append(value * scale)
                weights.append(1.0)
                previous = value
        return cls(unique, weights, population, minimum, maximum)

    @property
    def empty(self):
        return self.total <= 0

    def mean(self):
        if self.empty:
            return None
        return math.fsum(v * w for v, w in zip(self.values, self.weights)) / self.total

    def std(self):
        if self.empty:
            return None
        mean = self.mean()
        variance = math.fsum(w * (v - mean) ** 2
                             for v, w in zip(self.values, self.weights)) / self.total
        return math.sqrt(max(variance, 0.0))

    def quantiles(self, levels=QUANTILES):
        """Untere empirische Quantile: kleinster Wert mit F(x) >= q."""
        result = {}
        if self.empty:
            return result
        targets = sorted(levels)
        cumulative = 0.0
        index = 0
        for value, weight in zip(self.values, self.weights):
            cumulative += weight
            while index < len(targets) and cumulative >= targets[index] * self.total - 1e-9:
                result[targets[index]] = value
                index += 1
            if index == len(targets):
                break
        while index < len(targets):
            result[targets[index]] = self.values[-1]
            index += 1
        return result

    def mode_share(self):
        """Anteil des haeufigsten Werts."""
        if self.empty:
            return None
        return max(self.weights) / self.total

    def summary(self, unit=None, digits=6):
        if self.empty:
            return collections.OrderedDict([("n", 0)])
        data = collections.OrderedDict()
        data["n"] = int(self.population)
        data["exakt"] = self.exact
        if not self.exact:
            data["stichprobe"] = int(self.total)
        data["verschiedene_werte"] = len(self.values)
        data["min"] = _round(self.minimum, digits)
        data["max"] = _round(self.maximum, digits)
        data["mittel"] = _round(self.mean(), digits)
        data["std"] = _round(self.std(), digits)
        data["quantile"] = collections.OrderedDict(
            (f"p{int(level * 100):02d}", _round(value, digits))
            for level, value in sorted(self.quantiles().items()))
        if unit:
            data["einheit"] = unit
        return data


class CappedCounter:
    """Zaehler mit Obergrenze an verschiedenen Schluesseln.

    add() liefert 1 fuer einen neuen Schluessel, 0 fuer einen bekannten und
    -1, wenn der Schluessel wegen der Obergrenze nicht aufgenommen wurde.
    """

    def __init__(self, limit):
        self.limit = limit
        self.counts = {}
        self.overflow = 0

    def add(self, key, amount=1):
        counts = self.counts
        if key in counts:
            counts[key] += amount
            return 0
        if len(counts) >= self.limit:
            self.overflow += amount
            return -1
        counts[key] = amount
        return 1

    def __len__(self):
        return len(self.counts)

    @property
    def complete(self):
        return self.overflow == 0

    def most_common(self, count):
        return sorted(self.counts.items(), key=lambda item: (-item[1], item[0]))[:count]


class CappedSet:
    """Menge mit Obergrenze; seen_before() traegt neue Elemente ein."""

    def __init__(self, limit):
        self.limit = limit
        self.items = set()
        self.full = False

    def seen_before(self, item):
        if item in self.items:
            return True
        if len(self.items) < self.limit:
            self.items.add(item)
        else:
            self.full = True
        return False


def _round(value, digits=6):
    """Auf `digits` signifikante Stellen runden; ganze Zahlen bleiben ganz."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if math.isnan(value) or math.isinf(value):
        return None
    if value == int(value) and abs(value) < 1e15:
        return int(value)
    if value == 0:
        return 0.0
    return float(f"{value:.{digits}g}")


def _share(part, whole, digits=6):
    if not whole:
        return None
    return _round(part / whole, digits)


# ---------------------------------------------------------------------------
# Fluesse
# ---------------------------------------------------------------------------

# Indizes der Flussliste. Eine Liste statt eines Objekts je Fluss, weil sie
# kleiner und schneller ist; die Namen halten den Code trotzdem lesbar.
(F_FIRST, F_LAST, F_BITS, F_PKTS_A, F_PKTS_B, F_BYTES_A, F_BYTES_B,
 F_ORIG, F_IAT_N, F_IAT_MEAN, F_IAT_M2) = range(11)


def flow_key(source, source_port, destination, destination_port, protocol):
    """Bidirektionaler Integer-Schluessel und Seite des Absenders.

    Der Schluessel ist das kanonisch sortierte Endpunktpaar (Adresse + Port)
    plus IP-Version und Protokollnummer, als Integer gelesen. Sortiert wird,
    damit Hin- und Rueckrichtung auf denselben Eintrag fallen. Kollisionen
    sind ausgeschlossen, weil der Integer alle Bits traegt und nicht gehasht
    wird. Seite 0 heisst: der Absender ist der kleinere Endpunkt.
    """
    forward = source + source_port.to_bytes(2, "big")
    backward = destination + destination_port.to_bytes(2, "big")
    if forward <= backward:
        packed, side = forward + backward, 0
    else:
        packed, side = backward + forward, 1
    ipv6 = 1 if len(source) == 16 else 0
    key = (int.from_bytes(packed, "big") << 9) | (ipv6 << 8) | protocol
    return key, side, forward == backward


def describe_flow(key):
    """Schluessel wieder in eine lesbare Flussbeschreibung uebersetzen."""
    protocol = key & 0xFF
    ipv6 = (key >> 8) & 1
    size = 36 if ipv6 else 12
    packed = (key >> 9).to_bytes(size, "big")
    half = size // 2
    first, second = packed[:half], packed[half:]
    first_port = int.from_bytes(first[-2:], "big")
    second_port = int.from_bytes(second[-2:], "big")
    name = protocol_name(protocol)
    if ipv6:
        return (f"[{format_address(first[:-2])}]:{first_port} <-> "
                f"[{format_address(second[:-2])}]:{second_port} {name}")
    return (f"{format_address(first[:-2])}:{first_port} <-> "
            f"{format_address(second[:-2])}:{second_port} {name}")


def flow_endpoints(key):
    """(Endpunkt Seite 0, Endpunkt Seite 1) als (Adresse, Port)."""
    ipv6 = (key >> 8) & 1
    size = 36 if ipv6 else 12
    packed = (key >> 9).to_bytes(size, "big")
    half = size // 2
    return ((packed[:half - 2], int.from_bytes(packed[half - 2:half], "big")),
            (packed[half:-2], int.from_bytes(packed[-2:], "big")))


def classify_tcp_state(orig, resp):
    """Verbindungszustand aus den Richtungsbits, angelehnt an Zeek conn_state.

    Die Reihenfolge der Ereignisse wird nicht gefuehrt, nur ihr Auftreten;
    die Einstufung ist daher eine Naeherung an Zeek, keine Nachbildung.
    """
    if not orig & SIDE_SYN:
        if resp & SIDE_SYNACK:
            if resp & SIDE_RST:
                return "RSTRH"
            if resp & SIDE_FIN:
                return "SHR"
        return "OTH"
    if not resp & SIDE_SYNACK:
        if resp & SIDE_RST:
            return "REJ"
        if orig & SIDE_RST:
            return "RSTOS0"
        if orig & SIDE_FIN:
            return "SH"
        if resp & SIDE_SEEN:
            return "OTH"
        return "S0"
    if orig & SIDE_RST:
        return "RSTO"
    if resp & SIDE_RST:
        return "RSTR"
    if orig & SIDE_FIN and resp & SIDE_FIN:
        return "SF"
    if orig & SIDE_FIN:
        return "S2"
    if resp & SIDE_FIN:
        return "S3"
    return "S1"


def tcp_side_bits(flags):
    """TCP-Flags eines Pakets in Richtungsbits uebersetzen."""
    bits = SIDE_SEEN
    if flags & SYN:
        bits |= SIDE_SYNACK if flags & ACK else SIDE_SYN
    elif flags & ACK:
        bits |= SIDE_ACK
    if flags & FIN:
        bits |= SIDE_FIN
    if flags & RST:
        bits |= SIDE_RST
    return bits


def service_port(packet, flow=None):
    """Port des Dienstes (Antwortenden) fuer P3.

    SYN zeigt auf den Zielport, SYN-ACK kommt vom Dienstport. Sonst gilt die
    Seite, die den Fluss nicht begonnen hat; ohne Flusszuordnung der
    kleinere Port (Dienste liegen meist unter den Quellports der Clients).
    """
    flags = packet.tcp_flags
    if flags is not None:
        if flags & (SYN | ACK) == SYN:
            return packet.dport
        if flags & (SYN | ACK) == SYN | ACK:
            return packet.sport
    if flow is not None:
        _key, state, _new, side = flow
        return packet.dport if side == state[F_ORIG] else packet.sport
    return min(packet.sport, packet.dport)


class FlowTable:
    """Tabelle der AKTIVEN Fluesse mit Leerlauf-Timeout.

    Ein Fluss endet, wenn
      * laenger als `timeout` Sekunden kein Paket kam (beim naechsten Paket
        desselben Tupels oder bei der periodischen Durchsicht), oder
      * nach FIN beider Seiten bzw. RST ein neues reines SYN dasselbe Tupel
        wiederverwendet.
    Abgeschlossene Fluesse gehen an `on_finish(key, flow, at_end)` und
    verlassen die Tabelle. Der Speicher waechst so mit der Zahl gleichzeitig
    aktiver Fluesse, nicht mit der Laenge des Mitschnitts.
    """

    def __init__(self, timeout_seconds, limit, on_finish):
        self.timeout_ns = int(timeout_seconds * NS)
        self.limit = limit
        self.flows = {}
        self.on_finish = on_finish
        self.dropped_packets = 0
        self.reused_after_close = 0
        self.max_active = 0
        self._next_sweep = None

    def observe(self, ts, source, source_port, destination, destination_port,
                protocol, size, tcp_flags):
        """Ein Paket einsortieren. Liefert (key, flow, neu, seite) oder None."""
        key, side, degenerate = flow_key(source, source_port, destination,
                                         destination_port, protocol)
        flows = self.flows
        flow = flows.get(key)
        if flow is not None:
            if ts - flow[F_LAST] > self.timeout_ns:
                self._finish(key, flows.pop(key), False)
                flow = None
            elif (protocol == 6 and tcp_flags is not None
                  and tcp_flags & (SYN | ACK) == SYN and _flow_closed(flow)):
                self.reused_after_close += 1
                self._finish(key, flows.pop(key), False)
                flow = None
        is_new = flow is None
        if is_new:
            if len(flows) >= self.limit:
                self.dropped_packets += 1
                return None
            flow = [ts, ts, 0, 0, 0, 0, 0, side, 0, 0.0, 0.0]
            flows[key] = flow
            if len(flows) > self.max_active:
                self.max_active = len(flows)
        else:
            gap = ts - flow[F_LAST]
            if gap >= 0:
                count = flow[F_IAT_N] + 1
                delta = gap - flow[F_IAT_MEAN]
                mean = flow[F_IAT_MEAN] + delta / count
                flow[F_IAT_M2] += delta * (gap - mean)
                flow[F_IAT_MEAN] = mean
                flow[F_IAT_N] = count
                flow[F_LAST] = ts
            elif ts < flow[F_FIRST]:
                flow[F_FIRST] = ts

        bits = tcp_side_bits(tcp_flags) if (protocol == 6 and tcp_flags is not None) else SIDE_SEEN
        if degenerate:
            # Gleiche Adresse und gleicher Port in beide Richtungen (etwa ein
            # LAND-Angriff): die Rueckrichtung ist mit der Hinrichtung
            # identisch, der Fluss gilt als beidseitig.
            flow[F_BITS] |= bits | (bits << SIDE_SHIFT)
        else:
            flow[F_BITS] |= bits << (SIDE_SHIFT * side)
        if side == 0:
            flow[F_PKTS_A] += 1
            flow[F_BYTES_A] += size
        else:
            flow[F_PKTS_B] += 1
            flow[F_BYTES_B] += size

        if self._next_sweep is None:
            self._next_sweep = ts + self.timeout_ns
        elif ts >= self._next_sweep:
            self.sweep(ts)
        return key, flow, is_new, side

    def sweep(self, now):
        """Abgelaufene Fluesse abschliessen (periodisch, nach Mitschnittzeit)."""
        threshold = now - self.timeout_ns
        expired = [key for key, flow in self.flows.items() if flow[F_LAST] < threshold]
        for key in expired:
            self._finish(key, self.flows.pop(key), False)
        self._next_sweep = now + self.timeout_ns

    def finish_all(self):
        """Am Mitschnittende: alle noch aktiven Fluesse abschliessen."""
        for key in list(self.flows):
            self._finish(key, self.flows.pop(key), True)

    def _finish(self, key, flow, at_end):
        self.on_finish(key, flow, at_end)


def _flow_closed(flow):
    bits = flow[F_BITS]
    side_a, side_b = bits & 0xFF, (bits >> SIDE_SHIFT) & 0xFF
    if (side_a | side_b) & SIDE_RST:
        return True
    return bool(side_a & SIDE_FIN and side_b & SIDE_FIN)


# ---------------------------------------------------------------------------
# Ablauf (strukturelle Vollstaendigkeit, Konzeption 1.5.3)
#
# Werkzeuge wie Caldera sichern keine Verteilung zu, sondern einen
# Angriffsablauf. Die Spezifikation beschreibt jeden Schritt als Paketfilter;
# geprueft wird, ob jeder Schritt im Mitschnitt vorkommt und ob die ersten
# Vorkommen in der zugesicherten Reihenfolge liegen.
# ---------------------------------------------------------------------------

class SpecError(Exception):
    """Fehler in der Sollwert-Spezifikation."""


def _parse_protocol(value):
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if text.isdigit():
        return int(text)
    if text in PROTOCOL_NUMBERS:
        return PROTOCOL_NUMBERS[text]
    raise SpecError(f"unbekanntes Protokoll '{value}'")


def _parse_ports(value):
    values = value if isinstance(value, list) else [value]
    ports = set()
    for item in values:
        if isinstance(item, str) and "-" in item:
            low, high = item.split("-", 1)
            ports.update(range(int(low), int(high) + 1))
        else:
            ports.add(int(item))
    return ports


def _parse_network(value):
    try:
        network = ipaddress.ip_network(str(value), strict=False)
    except ValueError as error:
        raise SpecError(f"ungueltige Adresse '{value}': {error}")
    bits = network.max_prefixlen
    shift = bits - network.prefixlen
    return (bits // 8, int(network.network_address) >> shift, shift)


def _network_matches(network, raw):
    size, prefix, shift = network
    return raw is not None and len(raw) == size and \
        int.from_bytes(raw, "big") >> shift == prefix


class SequenceStep:
    """Ein Schritt des zugesicherten Ablaufs mit Paketfilter."""

    FIELDS = ("proto", "src", "dst", "src_port", "dst_port", "port",
              "tcp_flags")

    def __init__(self, index, entry):
        if not isinstance(entry, dict):
            raise SpecError(f"Ablaufschritt {index + 1} ist kein Objekt")
        self.index = index
        self.name = str(entry.get("name") or f"Schritt {index + 1}")
        conditions = entry.get("filter", {})
        unknown = set(conditions) - set(self.FIELDS)
        if unknown:
            raise SpecError(f"Ablaufschritt '{self.name}': unbekannte "
                            f"Filterfelder {sorted(unknown)}; erlaubt sind "
                            f"{list(self.FIELDS)}")
        self.proto = (_parse_protocol(conditions["proto"])
                      if "proto" in conditions else None)
        self.src = _parse_network(conditions["src"]) if "src" in conditions else None
        self.dst = _parse_network(conditions["dst"]) if "dst" in conditions else None
        self.src_ports = (_parse_ports(conditions["src_port"])
                          if "src_port" in conditions else None)
        self.dst_ports = (_parse_ports(conditions["dst_port"])
                          if "dst_port" in conditions else None)
        self.ports = _parse_ports(conditions["port"]) if "port" in conditions else None
        self.flag_mask = None
        if "tcp_flags" in conditions:
            mask = 0
            for letter in str(conditions["tcp_flags"]).upper():
                position = TCP_FLAG_LETTERS.find(letter)
                if position < 0:
                    raise SpecError(f"Ablaufschritt '{self.name}': "
                                    f"unbekanntes TCP-Flag '{letter}'")
                mask |= 1 << position
            self.flag_mask = mask
        self.minimum = int(entry.get("min_pakete", 1))
        self.count = 0
        self.first_ts = None

    def observe(self, packet, ts):
        if self.proto is not None and packet.proto != self.proto:
            return
        if self.src is not None and not _network_matches(self.src, packet.src):
            return
        if self.dst is not None and not _network_matches(self.dst, packet.dst):
            return
        if self.src_ports is not None and packet.sport not in self.src_ports:
            return
        if self.dst_ports is not None and packet.dport not in self.dst_ports:
            return
        if self.ports is not None and packet.sport not in self.ports \
                and packet.dport not in self.ports:
            return
        if self.flag_mask is not None and (
                packet.tcp_flags is None
                or packet.tcp_flags & self.flag_mask != self.flag_mask):
            return
        self.count += 1
        if ts is not None and (self.first_ts is None or ts < self.first_ts):
            self.first_ts = ts

    @property
    def found(self):
        return self.count >= self.minimum


def evaluate_sequence(steps):
    """Ergebnis der strukturellen Vollstaendigkeit fuer einen Lauf."""
    found = [step for step in steps if step.found]
    times = [step.first_ts for step in found if step.first_ts is not None]
    in_order = all(earlier <= later for earlier, later in zip(times, times[1:]))
    return collections.OrderedDict([
        ("schritte", len(steps)),
        ("gefunden", len(found)),
        ("anteil", _share(len(found), len(steps))),
        ("reihenfolge_eingehalten", in_order if len(times) > 1 else None),
        ("details", [collections.OrderedDict([
            ("name", step.name),
            ("gefunden", step.found),
            ("pakete", step.count),
            ("erstes_auftreten_utc", _iso(step.first_ts)),
        ]) for step in steps]),
    ])


def _iso(ts_ns):
    """Nanosekunden seit Epoche als ISO-8601 in UTC (Mikrosekunden)."""
    if ts_ns is None:
        return None
    try:
        seconds, rest = divmod(ts_ns, NS)
        moment = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
        return moment.strftime("%Y-%m-%dT%H:%M:%S") + f".{rest // 1000:06d}Z"
    except (OverflowError, OSError, ValueError):
        return f"ungueltig ({ts_ns} ns)"


# ---------------------------------------------------------------------------
# Analyse eines Mitschnitts
# ---------------------------------------------------------------------------

QUANT_UNITS = (1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, NS)
QUANT_LABELS = ("1 us", "10 us", "100 us", "1 ms", "10 ms", "100 ms", "1 s")
PLAUSIBLE_FROM_NS = 631_152_000 * NS     # 1990-01-01


class Options:
    """Parameter einer Analyse (aus der Kommandozeile)."""

    def __init__(self, max_packets=None, flow_limit=DEFAULT_FLOW_LIMIT,
                 seed=DEFAULT_SEED, sample_cap=DEFAULT_SAMPLE_CAP,
                 host_limit=DEFAULT_HOST_LIMIT, bin_seconds=DEFAULT_BIN,
                 flow_timeout=DEFAULT_FLOW_TIMEOUT, edge_margin=None,
                 facet_d=None, sequence=None):
        self.max_packets = max_packets
        self.flow_limit = flow_limit
        self.seed = seed
        self.sample_cap = sample_cap
        self.host_limit = host_limit
        self.bin_seconds = bin_seconds
        self.flow_timeout = flow_timeout
        self.edge_margin = flow_timeout if edge_margin is None else edge_margin
        self.facet_d = facet_d
        self.sequence = sequence or []

    def to_dict(self):
        return collections.OrderedDict([
            ("seed", self.seed),
            ("bin_s", self.bin_seconds),
            ("flow_timeout_s", self.flow_timeout),
            ("edge_margin_s", self.edge_margin),
            ("sample_cap", self.sample_cap),
            ("max_flows", self.flow_limit),
            ("host_limit", self.host_limit),
            ("max_packets", self.max_packets),
        ])


class Analysis:
    """Ergebnis der Analyse eines Mitschnitts."""

    def __init__(self, label, path):
        self.label = label
        self.path = path
        self.error = None
        self.sha256 = None
        self.file_size = os.path.getsize(path) if os.path.isfile(path) else None
        self.checks = collections.OrderedDict()
        self.features = {}
        self.scalars = collections.OrderedDict()
        self.overview = collections.OrderedDict()
        self.protocol_fidelity = collections.OrderedDict()
        self.sequence = None
        self.issues = collections.Counter()
        self.read_limited = False
        self.records = 0
        self.ip_packets = 0
        self.link_types = set()
        self.resolutions = set()
        self.effective_resolution = None
        self.ts_range = (None, None)
        self.addresses = set()
        self.addresses_complete = True
        self.macs = set()
        self.flow_keys = None
        self.flow_keys_complete = True
        self.watch_hits = None
        self.flow_count = 0
        self.seconds = None

    def worst_status(self):
        worst = STATUS_OK
        for check in self.checks.values():
            if STATUS_RANK[check.status] > STATUS_RANK[worst]:
                worst = check.status
        return worst


class Analyzer:
    """Fliessende Auswertung: feed() je Record, finish() am Ende."""

    def __init__(self, label, path, options, collect_flow_keys=False,
                 watch=None):
        self.label = label
        self.path = path
        self.options = options
        self.rng = rng = random.Random(options.seed)
        self.checks = collections.OrderedDict()

        def new(key, name, group, severity=STATUS_FAIL, applicable=True,
                origin="Eigenleistung"):
            check = Check(key, name, group, rng, severity, applicable, origin)
            self.checks[key] = check
            return check

        self.p1 = new("P1", "Gueltigkeit der IP-Adressen", "protokolltreue",
                      origin="[yin2022]")
        self.p2 = new("P2", "Verhaeltnis Byte- zu Paketzahl", "protokolltreue",
                      applicable=False, origin="[yin2022]")
        self.p2.note = ("Nur fuer Flussdatensaetze definiert; auf Paketebene "
                        "nicht anwendbar.")
        self.p3 = new("P3", "Portnummer und Protokoll konsistent",
                      "protokolltreue", origin="[yin2022]")
        self.p4 = new("P4", "Mindestpaketgroesse", "protokolltreue",
                      origin="[yin2022]")
        self.e1 = new("E1", "Laengenkonsistenz IP.len gegen Ist-Bytes",
                      "protokolltreue")
        self.e2 = new("E2", "Ziel-Adressklasse plausibel", "protokolltreue")
        self.e7 = new("E7", "IP-Pruefsumme korrekt", "protokolltreue")
        self.e8 = new("E8", "Transport-Pruefsummen korrekt", "protokolltreue")
        self.e9 = new("E9", "TCP-Flags widerspruchsfrei", "protokolltreue")
        self.e10 = new("E10", "Header-Struktur gueltig", "protokolltreue")
        self.e3 = new("E3", "Sicherungsschicht vorhanden", "mitschnitt")
        self.e6 = new("E6", "Zeitstempel konsistent", "mitschnitt")
        self.e4 = new("E4", "Flussvollstaendigkeit (TCP)", "befund",
                      severity=STATUS_WARN)
        self.e5 = new("E5", "Verteilungsdegeneration Paketgroesse", "befund",
                      severity=STATUS_WARN)
        self.af = [
            new("AF1", "TTL-Vielfalt bei vielen Quellen", "artefakt", STATUS_WARN),
            new("AF2", "Fortlaufende Adressen", "artefakt", STATUS_WARN),
            new("AF3", "Vorhersagbare Quellports", "artefakt", STATUS_WARN),
            new("AF4", "MAC-Praefixe der Virtualisierung", "artefakt", STATUS_WARN),
            new("AF5", "Zeitquantisierung", "artefakt", STATUS_WARN),
            new("AF6", "Gleichfoermige Taktung", "artefakt", STATUS_WARN),
            new("AF7", "Nullnutzlast", "artefakt", STATUS_WARN),
        ]

        # Datei und Schichten
        self.total = 0
        self.wire_bytes = 0
        self.captured_bytes = 0
        self.max_caplen = 0
        self.truncated_records = 0
        self.incl_greater_orig = 0
        self.link_type_counts = collections.Counter()
        self.l2_counts = collections.Counter()
        self.l3_counts = collections.Counter()
        self.other_ethertypes = collections.Counter()
        self.vlan_frames = 0
        self.macs = CappedCounter(options.host_limit)

        # Zeitstempel (alle Records)
        self.ts_min = None
        self.ts_max = None
        self.prev_ts = None
        self.ts_pairs = 0
        self.non_monotonic = 0
        self.zero_gaps = 0
        self.max_gap = 0
        self.missing_ts = 0
        self.implausible_ts = 0
        self.plausible_until = (int(time.time()) + 86400) * NS
        self.quant_counts = [0] * len(QUANT_UNITS)
        self.quant_total = 0

        # IP-Ebene
        self.ip_records = 0
        self.ip_packets = 0
        self.ip_bytes = 0
        self.proto_packets = collections.Counter()
        self.src_classes = collections.Counter()
        self.dst_classes = collections.Counter()
        self.sources = CappedCounter(options.host_limit)
        self.destinations = CappedCounter(options.host_limit)
        self.padding_cases = 0
        self.fragments = 0
        self.defect_header = 0
        self.defect_checksum = 0
        self.defect_any = 0
        self.structure_counts = collections.Counter()
        self.flag_anomalies = collections.Counter()
        self.tcp_flag_counts = collections.Counter()
        self.checksum_kinds = collections.Counter()
        self.checksum_error_sources = CappedCounter(10_000)
        self.udp_without_checksum = 0
        self.transport_packets = 0
        self.payload_packets = 0
        self.payload_declared = 0
        self.payload_present = 0
        self.payload_inspected = 0
        self.zero_payload = 0

        # Merkmale
        self.sizes = collections.Counter()
        self.size_classes = collections.Counter()
        self.ttls = collections.Counter()
        self.windows = collections.Counter()
        self.iat = ValueSample(options.sample_cap, rng)
        self.iat_stats = RunningStats()
        self.negative_iat = 0
        self.prev_ip_ts = None
        self.ip_t0 = None
        self.ip_ts_min = None
        self.ip_ts_max = None
        self.bin_ns = max(int(options.bin_seconds * NS), 1)
        self.bins = {}

        # Artefakte
        self.last_new_src = None
        self.src_transitions = 0
        self.sequential_src = 0
        self.last_new_dst = None
        self.dst_transitions = 0
        self.sequential_dst = 0
        self.syn_connections = 0
        self.syn_tuples = CappedSet(options.sample_cap)
        self.syn_ports = CappedSet(options.sample_cap)
        self.tuple_repeats = 0
        self.port_reuse = 0
        self.last_port_by_src = {}
        self.port_transitions = 0
        self.sequential_ports = 0

        # Fluesse
        self.flows = FlowTable(options.flow_timeout, options.flow_limit,
                               self._flow_finished)
        self.edge_margin_ns = int(options.edge_margin * NS)
        self.flow_count = 0
        self.flow_packets = ValueSample(options.sample_cap, rng)
        self.flow_bytes = ValueSample(options.sample_cap, rng)
        self.flow_duration = ValueSample(options.sample_cap, rng)
        self.flow_protocols = collections.Counter()
        self.flow_services = collections.Counter()
        self.flow_port_ranges = collections.Counter()
        self.one_sided = 0
        self.one_sided_examples = ExampleReservoir(EXAMPLE_CAPACITY, rng)
        self.tcp_states = collections.Counter()
        self.tcp_incomplete = collections.Counter()
        self.tcp_edge = collections.Counter()
        self.flows_timed = 0
        self.flows_regular = 0
        self.concurrency = collections.Counter()
        self.unassigned_fragments = 0
        self.flow_keys = {} if collect_flow_keys else None
        self.flow_keys_dropped = 0
        self.watch = watch
        self.watch_hits = {} if watch is not None else None

        self.steps = [SequenceStep(index, entry)
                      for index, entry in enumerate(options.sequence)]

    # --- je Record ----------------------------------------------------------

    def feed(self, linktype, ts, wirelen, data, fcs_len):
        self.total += 1
        caplen = len(data)
        self.wire_bytes += wirelen
        self.captured_bytes += caplen
        if caplen > self.max_caplen:
            self.max_caplen = caplen
        truncated = wirelen > caplen
        if truncated:
            self.truncated_records += 1
        elif wirelen < caplen:
            self.incl_greater_orig += 1
        self.link_type_counts[linktype] += 1

        packet = dissect(linktype, data, fcs_len, truncated)

        # --- E3: Sicherungsschicht -------------------------------------
        # Bewusst vor der IP-Pruefung, da ARP- und andere Nicht-IP-Pakete
        # zwar keinen IP-Layer, aber einen Ethernet-Layer besitzen.
        self.e3.record(packet.l2 == "ethernet")
        self.l2_counts[packet.l2 or f"unbekannt ({linktype})"] += 1
        if packet.vlan:
            self.vlan_frames += 1
        if packet.src_mac is not None:
            self.macs.add(packet.src_mac)
        l3 = packet.l3 or "unbekannt"
        self.l3_counts[l3] += 1
        if l3 in ("andere", "llc") and packet.ethertype is not None:
            self.other_ethertypes[packet.ethertype] += 1

        if ts is None:
            self.missing_ts += 1
        else:
            self._timestamp(ts)

        if l3 in ("ipv4", "ipv6"):
            self._ip_packet(packet, ts, truncated)
        elif packet.structure_errors:
            self.e10.record(False, example=", ".join(packet.structure_errors))
            for error in packet.structure_errors:
                self.structure_counts[error] += 1

    def _timestamp(self, ts):
        if self.ts_min is None or ts < self.ts_min:
            self.ts_min = ts
        if self.ts_max is None or ts > self.ts_max:
            self.ts_max = ts
        previous = self.prev_ts
        if previous is not None:
            self.ts_pairs += 1
            if ts < previous:
                self.non_monotonic += 1
                self.e6.examples.offer(f"{_iso(previous)} -> {_iso(ts)}")
            elif ts == previous:
                self.zero_gaps += 1
            elif ts - previous > self.max_gap:
                self.max_gap = ts - previous
        self.prev_ts = ts
        if ts < PLAUSIBLE_FROM_NS or ts > self.plausible_until:
            self.implausible_ts += 1
        # AF5: Teilbarkeit durch immer groebere Einheiten; wer durch 1 ms
        # teilbar ist, ist es auch durch 100 us, daher Abbruch beim ersten Rest
        self.quant_total += 1
        counts = self.quant_counts
        for index, unit in enumerate(QUANT_UNITS):
            if ts % unit:
                break
            counts[index] += 1

    def _ip_packet(self, packet, ts, truncated):
        self.ip_records += 1
        errors = packet.structure_errors
        if packet.total_len is None:
            # IP-Header nicht auswertbar: zaehlt als fehlerhaftes Paket
            if errors:
                self.e10.record(False, example=", ".join(errors))
                for error in errors:
                    self.structure_counts[error] += 1
                self.defect_header += 1
                self.defect_any += 1
            else:
                self.e10.skip()           # vom Snaplen abgeschnitten
            return

        ipv6 = packet.l3 == "ipv6"
        proto = packet.proto
        size = packet.total_len
        src, dst = packet.src, packet.dst
        self.ip_packets += 1
        self.ip_bytes += size
        self.proto_packets[proto] += 1
        header_defect = bool(errors)
        checksum_defect = False

        if ipv6:
            src_class = classify_ipv6_bytes(src)
            dst_class = classify_ipv6_bytes(dst)
            p1_ok = address_valid_v6(src, dst)
        else:
            src_int = int.from_bytes(src, "big")
            dst_int = int.from_bytes(dst, "big")
            src_class = classify_ipv4_int(src_int)
            dst_class = classify_ipv4_int(dst_int)
            p1_ok = address_valid_v4(src_int, dst_int)
        self.src_classes[src_class] += 1
        self.dst_classes[dst_class] += 1

        # --- P1: IP-Gueltigkeit (Paper: Quelle) ------------------------
        if not p1_ok:
            header_defect = True
        self.p1.record(p1_ok, example=None if p1_ok else
                       f"{format_address(src)} -> {format_address(dst)}")

        # --- E2: Zielklasse (Luecke von P1) ----------------------------
        e2_ok = check_destination_class(proto, dst_class)
        if not e2_ok:
            header_defect = True
        self.e2.record(e2_ok, example=None if e2_ok else
                       f"{format_address(src)} -> {format_address(dst)} "
                       f"({dst_class}, {protocol_name(proto)})")

        # --- E1: Laengenkonsistenz -------------------------------------
        if truncated:
            # Snaplen-Fall: die fehlenden Bytes sind ein Artefakt der
            # Aufzeichnung, kein Defekt des Generators.
            self.e1.skip()
        else:
            verdict, difference = check_length_consistency(size, packet.present_len)
            if verdict == LENGTH_MISMATCH:
                header_defect = True
                self.e1.record(False, example=collections.OrderedDict([
                    ("deklariert", size), ("vorhanden", packet.present_len),
                    ("differenz", difference)]))
            else:
                if verdict == LENGTH_PADDING:
                    self.padding_cases += 1
                self.e1.record(True)

        # --- P4: Mindestpaketgroesse (nicht fuer Folgefragmente) -------
        if not packet.frag_offset:
            p4_ok = check_minimum_length(proto, size, ipv6)
            if p4_ok is not None:
                if not p4_ok:
                    header_defect = True
                self.p4.record(p4_ok, example=None if p4_ok else
                               f"{protocol_name(proto)} len={size}")

        sport, dport = packet.sport, packet.dport

        # --- E7: IP-Pruefsumme (nur IPv4 hat eine) ---------------------
        if not ipv6:
            ok = packet.ip_checksum_ok
            if not ok:
                checksum_defect = True
            self.e7.record(ok, example=None if ok else
                           f"Feld 0x{packet.ip_checksum:04x}, "
                           f"{format_address(src)} -> {format_address(dst)}")

        # --- E8: Transport-Pruefsummen ---------------------------------
        if packet.l4_checksum_ok is not None:
            ok = packet.l4_checksum_ok
            self.checksum_kinds[packet.l4_checksum_kind] += 1
            if not ok:
                checksum_defect = True
                self.checksum_error_sources.add(src)
            self.e8.record(ok, example=None if ok else
                           f"{packet.l4_checksum_kind} Feld 0x{packet.l4_checksum:04x}, "
                           f"erwartet 0x{packet.l4_expected:04x}, "
                           f"{format_address(src)}:{sport} -> {format_address(dst)}:{dport}")
        elif proto in (1, 6, 17, 58) and not packet.udp_zero_checksum:
            # abgeschnitten, fragmentiert oder Laengenfeld groesser als die
            # vorhandenen Bytes (E1): Pruefsumme nicht nachrechenbar
            self.e8.skip()
        if packet.udp_zero_checksum:
            self.udp_without_checksum += 1

        # --- E9: TCP-Flags ---------------------------------------------
        flags = packet.tcp_flags
        if proto == 6 and flags is not None:
            self.tcp_flag_counts[tcp_flag_text(flags)] += 1
            self.windows[packet.tcp_window] += 1
            anomaly = check_tcp_flags(flags)
            if anomaly:
                header_defect = True
                self.flag_anomalies[anomaly] += 1
            self.e9.record(anomaly is None, example=None if anomaly is None else
                           f"{anomaly}: {format_address(src)}:{sport} -> "
                           f"{format_address(dst)}:{dport}")

        # --- E10: Header-Struktur --------------------------------------
        self.e10.record(not errors, example=", ".join(errors) if errors else None)
        if errors:
            for error in errors:
                self.structure_counts[error] += 1

        # --- fliessende Aggregation statt Listen -----------------------
        self.sizes[size] += 1
        class_index = size_class_index(size)
        if class_index is not None:
            self.size_classes[SIZE_CLASSES[class_index]] += 1
        if packet.ttl is not None:
            self.ttls[packet.ttl] += 1
        if packet.fragment:
            self.fragments += 1
        if packet.payload_len is not None and proto in (6, 17):
            self.transport_packets += 1
            self.payload_declared += packet.payload_len
            if packet.payload_len > 0:
                self.payload_packets += 1
                self.payload_present += packet.payload_present or 0
            if packet.payload_zero is not None:
                self.payload_inspected += 1
                if packet.payload_zero:
                    self.zero_payload += 1

        # AF2: Reihenfolge des ersten Auftretens neuer Adressen
        if self.sources.add(src) == 1:
            value = int.from_bytes(src, "big")
            if self.last_new_src is not None:
                self.src_transitions += 1
                if value == self.last_new_src + 1:
                    self.sequential_src += 1
            self.last_new_src = value
        if self.destinations.add(dst) == 1:
            value = int.from_bytes(dst, "big")
            if self.last_new_dst is not None:
                self.dst_transitions += 1
                if value == self.last_new_dst + 1:
                    self.sequential_dst += 1
            self.last_new_dst = value

        for step in self.steps:
            step.observe(packet, ts)

        flow = None
        if ts is not None:
            self._ip_time(ts, size)
            if packet.frag_offset:
                # Folgefragmente tragen keine Ports; ohne Reassemblierung
                # sind sie keinem Fluss zuzuordnen
                self.unassigned_fragments += 1
            else:
                flow = self.flows.observe(ts, src, sport or 0, dst, dport or 0,
                                          proto, size, flags if proto == 6 else None)

        # --- P3: Port und Protokoll (Dienstport) -----------------------
        # Geprueft wird nur der Port des Dienstes, nicht der Quellport des
        # Clients: Resolver und viele Anwendungen waehlen Quellports
        # zufaellig aus 1024-65535 und treffen dabei etwa 1883 oder 3306.
        # Beide Ports zu pruefen haette solche Zufallstreffer als Verstoss
        # gezaehlt.
        if sport is not None and proto in (6, 17):
            port = service_port(packet, flow)
            p3_ok = check_port_protocol(port, proto)
            if p3_ok is not None:
                if not p3_ok:
                    header_defect = True
                self.p3.record(p3_ok, example=None if p3_ok else
                               f"port={port} proto={protocol_name(proto)} "
                               f"(erwartet {protocol_name(PORT_PROTOCOL[port])}), "
                               f"{format_address(src)}:{sport} -> "
                               f"{format_address(dst)}:{dport}")

        if header_defect:
            self.defect_header += 1
        if checksum_defect:
            self.defect_checksum += 1
        if header_defect or checksum_defect:
            self.defect_any += 1

        if flow is not None and flow[2] and proto == 6 and flags is not None \
                and flags & (SYN | ACK) == SYN:
            self._new_connection(flow[0], src, sport)

    def _ip_time(self, ts, size):
        """Zeitmerkmale der IP-Pakete: Intervalle und Zwischenankunftszeit."""
        if self.ip_t0 is None:
            self.ip_t0 = ts
        if self.ip_ts_min is None or ts < self.ip_ts_min:
            self.ip_ts_min = ts
        if self.ip_ts_max is None or ts > self.ip_ts_max:
            self.ip_ts_max = ts
        bin_index = (ts - self.ip_t0) // self.bin_ns
        entry = self.bins.get(bin_index)
        if entry is None:
            self.bins[bin_index] = [1, size]
        else:
            entry[0] += 1
            entry[1] += size
        previous = self.prev_ip_ts
        if previous is not None:
            gap = ts - previous
            if gap >= 0:
                self.iat.add(gap)
                self.iat_stats.add(gap)
            else:
                self.negative_iat += 1
        self.prev_ip_ts = ts

    def _new_connection(self, key, src, sport):
        """AF3: neue TCP-Verbindung, deren erstes Paket ein reines SYN ist."""
        self.syn_connections += 1
        if self.syn_tuples.seen_before(key):
            self.tuple_repeats += 1
        if self.syn_ports.seen_before(src + sport.to_bytes(2, "big")):
            self.port_reuse += 1
        last = self.last_port_by_src.get(src)
        if last is not None:
            self.port_transitions += 1
            if sport == last + 1:
                self.sequential_ports += 1
        if last is not None or len(self.last_port_by_src) < self.options.host_limit:
            self.last_port_by_src[src] = sport

    # --- je abgeschlossenem Fluss -------------------------------------------

    def _flow_finished(self, key, flow, at_end):
        protocol = key & 0xFF
        bits = flow[F_BITS]
        sides = (bits & 0xFF, (bits >> SIDE_SHIFT) & 0xFF)
        orig = flow[F_ORIG]
        # Initiator ist die Seite des ersten Pakets; hat aber nur die
        # Gegenseite ein reines SYN gesendet, war das erste Paket eine Antwort
        if protocol == 6 and not sides[orig] & SIDE_SYN and sides[1 - orig] & SIDE_SYN:
            orig = 1 - orig
        endpoints = flow_endpoints(key)
        orig_port = endpoints[orig][1]
        resp_port = endpoints[1 - orig][1]
        packets = flow[F_PKTS_A] + flow[F_PKTS_B]
        size = flow[F_BYTES_A] + flow[F_BYTES_B]

        self.flow_count += 1
        self.flow_packets.add(packets)
        self.flow_bytes.add(size)
        self.flow_duration.add(flow[F_LAST] - flow[F_FIRST])
        self.flow_protocols[protocol_name(protocol)] += 1
        self.flow_services[service_key(resp_port, protocol)] += 1
        if protocol in (6, 17):
            self.flow_port_ranges[port_range(orig_port)] += 1

        if not (sides[0] & SIDE_SEEN and sides[1] & SIDE_SEEN):
            self.one_sided += 1
            self.one_sided_examples.offer(describe_flow(key))

        if protocol == 6:
            state = classify_tcp_state(sides[orig], sides[1 - orig])
            self.tcp_states[state] += 1
            if state not in TCP_COMPLETE and state not in TCP_REJECTED:
                if self._is_edge(state, flow, at_end):
                    self.tcp_edge[state] += 1
                else:
                    self.tcp_incomplete[state] += 1
                    self.e4.examples.offer(f"{describe_flow(key)} [{state}]")

        # AF6: Taktung je Fluss ab zehn Paketen
        gaps = flow[F_IAT_N]
        if gaps >= 9 and flow[F_IAT_MEAN] > 0:
            self.flows_timed += 1
            cv = math.sqrt(flow[F_IAT_M2] / gaps) / flow[F_IAT_MEAN]
            if cv < 0.1:
                self.flows_regular += 1

        # gleichzeitig aktive Fluesse: Differenzen je Intervall
        if self.ip_t0 is not None:
            start_bin = (flow[F_FIRST] - self.ip_t0) // self.bin_ns
            end_bin = (flow[F_LAST] - self.ip_t0) // self.bin_ns + 1
            self.concurrency[start_bin] += 1
            self.concurrency[end_bin] -= 1

        if self.flow_keys is not None:
            if key in self.flow_keys or len(self.flow_keys) < self.options.flow_limit:
                self.flow_keys.setdefault(key, []).append(
                    (flow[F_FIRST], flow[F_LAST], packets))
            else:
                self.flow_keys_dropped += 1
        if self.watch is not None and key in self.watch:
            self.watch_hits.setdefault(key, []).append((flow[F_FIRST], flow[F_LAST]))

    def _is_edge(self, state, flow, at_end):
        """Randfluss: Beginn oder Ende liegt vermutlich ausserhalb des
        Mitschnitts (Konzeption 1.5.2: zaehlt nicht als unvollstaendig)."""
        margin = self.edge_margin_ns
        if state in TCP_MISSING_START and self.ts_min is not None \
                and flow[F_FIRST] - self.ts_min < margin:
            return True
        if state in TCP_MISSING_END and at_end and self.ts_max is not None \
                and self.ts_max - flow[F_LAST] < margin:
            return True
        return False

    # --- am Dateiende ---------------------------------------------------------

    def finish(self, reader, read_limited):
        self.flows.finish_all()
        analysis = Analysis(self.label, self.path)
        analysis.checks = self.checks
        analysis.read_limited = read_limited
        analysis.records = self.total
        analysis.ip_packets = self.ip_packets
        analysis.issues = collections.Counter(reader.issues)
        if self.incl_greater_orig:
            analysis.issues["incl_len_groesser_orig_len"] = self.incl_greater_orig
        snaplen = reader.snaplen
        if snaplen and self.max_caplen > snaplen:
            analysis.issues["record_groesser_als_snaplen"] += 1
        analysis.link_types = set(reader.link_types)
        analysis.resolutions = set(reader.resolutions)
        analysis.ts_range = (self.ip_ts_min, self.ip_ts_max)
        analysis.flow_count = self.flow_count

        self._finish_checks()
        self._finish_features(analysis)
        self._finish_artifacts(reader, analysis)
        self._finish_overview(analysis, reader)

        analysis.addresses = set(self.sources.counts) | set(self.destinations.counts)
        analysis.addresses_complete = self.sources.complete and self.destinations.complete
        analysis.macs = set(self.macs.counts)
        analysis.flow_keys = self.flow_keys
        analysis.flow_keys_complete = self.flow_keys_dropped == 0
        analysis.watch_hits = self.watch_hits
        if self.steps:
            analysis.sequence = evaluate_sequence(self.steps)
        return analysis

    def _finish_checks(self):
        options = self.options
        # --- E4: Flussvollstaendigkeit -----------------------------------
        tcp_total = sum(self.tcp_states.values())
        edge = sum(self.tcp_edge.values())
        incomplete = sum(self.tcp_incomplete.values())
        rejected = sum(self.tcp_states[state] for state in TCP_REJECTED)
        base = tcp_total - edge
        e4 = self.e4
        e4.set_result(incomplete == 0, checked=base, violations=incomplete)
        if incomplete:
            if options.facet_d == "D1":
                e4.status_override = STATUS_INFO
                e4.note = ("Facette D1 (zustandslos): unvollstaendige "
                           "Verbindungen sind zu erwarten.")
            elif options.facet_d == "D3":
                e4.severity = STATUS_FAIL
                e4.note = ("Facette D3 (netzreaktiv): unvollstaendige "
                           "Verbindungen weisen auf einen Fehler hin.")
            elif options.facet_d == "D2":
                e4.note = ("Facette D2 (zustandsbehaftet): unvollstaendige "
                           "Verbindungen gegen das Zustandsmodell pruefen.")
            else:
                e4.note = ("Deutung offen: Facette D mit --facet-d angeben "
                           "(D1 erwartet, D3 Fehler).")
        e4.extra.update([
            ("fluesse", self.flow_count),
            ("tcp_verbindungen", tcp_total),
            ("randfluesse", edge),
            ("tcp_ohne_randfluesse", base),
            ("unvollstaendig", incomplete),
            ("anteil_unvollstaendig", _share(incomplete, base)),
            ("abgewiesen_rej", rejected),
            ("zustaende", collections.OrderedDict(
                (state, self.tcp_states[state]) for state in TCP_STATE_TEXT
                if self.tcp_states[state])),
            ("unvollstaendig_nach_zustand", dict(self.tcp_incomplete.most_common())),
            ("randfluesse_nach_zustand", dict(self.tcp_edge.most_common())),
            ("einseitige_fluesse", self.one_sided),
            ("anteil_einseitig", _share(self.one_sided, self.flow_count)),
            ("beispiele_einseitig", list(self.one_sided_examples.items)),
            ("pakete_ohne_flusszuordnung", self.flows.dropped_packets),
            ("flussgrenze_erreicht", self.flows.dropped_packets > 0),
            ("folgefragmente_ohne_fluss", self.unassigned_fragments),
            ("max_gleichzeitig_aktiv", self.flows.max_active),
            ("tupel_nach_abschluss_wiederverwendet", self.flows.reused_after_close),
        ])

        # --- E5: Verteilungsdegeneration ---------------------------------
        if self.ip_packets:
            e5_ok, e5_stats = check_size_degeneration(self.size_classes,
                                                      self.ip_packets)
            self.e5.set_result(e5_ok)
            e5_stats.update([
                ("verschiedene_werte", len(self.sizes)),
                ("min", min(self.sizes)), ("max", max(self.sizes)),
                ("mittel", _round(self.ip_bytes / self.ip_packets, 4)),
            ])
            self.e5.extra.update(e5_stats)
            if not e5_ok:
                self.e5.note = ("P4 ist nur eingeschraenkt aussagekraeftig. Bei "
                                "Flood-Angriffen ist eine schmale Verteilung "
                                "allerdings Angriffsinhalt.")

        # --- E6: Zeitstempel ---------------------------------------------
        e6 = self.e6
        if self.ts_pairs:
            e6.set_result(self.non_monotonic == 0, checked=self.ts_pairs,
                          violations=self.non_monotonic)
        e6.extra.update([
            ("rueckspruenge", self.non_monotonic),
            # Nullabstaende sind keine Fehler: gleiche Zeitstempel kommen bei
            # echten Mitschnitten durch die begrenzte Uhrenaufloesung
            # staendig vor. Sie sind entweder ein Hinweis auf die
            # Aufloesungsgrenze oder auf synthetisch erzeugten Verkehr.
            ("nullabstaende", self.zero_gaps),
            ("groesster_abstand_s", _round(self.max_gap / NS)),
            ("dauer_s", None if self.ts_min is None
             else _round((self.ts_max - self.ts_min) / NS)),
            ("unplausible_zeitstempel", self.implausible_ts),
            ("ohne_zeitstempel", self.missing_ts),
        ])
        if self.implausible_ts:
            e6.note = (f"{self.implausible_ts} Zeitstempel vor 1990 oder in der "
                       "Zukunft; der Generator setzt vermutlich keine echte Zeit.")
            if e6.status == STATUS_OK:
                e6.status_override = STATUS_WARN

        # --- E3, E8, E9, E10: Zusatzangaben ------------------------------
        self.e3.extra["link_types"] = {
            f"{linktype} ({LINKTYPE_NAMES.get(linktype, 'unbekannt')})": count
            for linktype, count in sorted(self.link_type_counts.items())}
        if self.vlan_frames:
            self.e3.extra["vlan_frames"] = self.vlan_frames
        if self.e1.skipped:
            self.e1.extra["abgeschnittene_records"] = self.truncated_records
            self.e1.note = ("Abgeschnittene Records (orig_len > incl_len) "
                            "sind von E1 ausgenommen.")
        if self.padding_cases:
            self.e1.extra["padding_faelle"] = self.padding_cases
        self.e8.extra["geprueft_nach_art"] = dict(self.checksum_kinds)
        self.e8.extra["udp_ohne_pruefsumme"] = self.udp_without_checksum
        failures = self.e8.violations
        if failures:
            top = self.checksum_error_sources.most_common(3)
            self.e8.extra["fehler_nach_quelle"] = {
                format_address(address): count for address, count in top}
            if failures >= 10 and top and top[0][1] / failures >= 0.9:
                self.e8.note = (f"Fehler konzentrieren sich auf "
                                f"{format_address(top[0][0])}: typisch fuer "
                                "Checksum-Offloading beim Mitschnitt auf dem "
                                "sendenden Host, nicht fuer einen Generatorfehler.")
        if self.flag_anomalies:
            self.e9.extra["kombinationen"] = dict(self.flag_anomalies.most_common())
            self.e9.note = ("Portscans (NULL, FIN, Xmas) erzeugen solche "
                            "Pakete absichtlich; dann Angriffsinhalt, kein "
                            "Generatorfehler.")
        if self.structure_counts:
            self.e10.extra["fehlerarten"] = dict(self.structure_counts.most_common())

    def _finish_artifacts(self, reader, analysis):
        af1, af2, af3, af4, af5, af6, af7 = self.af

        def verdict(check, suspicious, basis, note):
            check.set_result(not suspicious, checked=basis,
                             violations=1 if suspicious else 0)
            if not basis:
                check.status_override = STATUS_NA
            if suspicious:
                check.note = note

        # AF1: konstante TTL-Werte
        sources = len(self.sources)
        distinct_ttl = len(self.ttls)
        top_ttl = self.ttls.most_common(5)
        verdict(af1, sources >= 20 and distinct_ttl <= 2, self.ip_packets,
                f"{sources} Quelladressen teilen sich {distinct_ttl} TTL-Wert(e); "
                "reale Quellen unterscheiden sich meist durch Betriebssystem "
                "und Hop-Zahl (in einem flachen LAN mit einheitlichem "
                "Betriebssystem ist das dagegen normal).")
        af1.extra.update([
            ("quelladressen", sources),
            ("verschiedene_ttl", distinct_ttl),
            ("haeufigste_ttl", {str(ttl): _share(count, self.ip_packets)
                                for ttl, count in top_ttl}),
        ])

        # AF2: fortlaufende Adressen
        src_ratio = _share(self.sequential_src, self.src_transitions)
        verdict(af2, self.src_transitions >= 9 and (src_ratio or 0) >= 0.5,
                self.src_transitions,
                "Neue Quelladressen erscheinen ueberwiegend fortlaufend "
                "(Adresse + 1), typisch fuer generierte oder gefaelschte Quellen.")
        af2.extra.update([
            ("neue_quellen_folgen", self.src_transitions),
            ("fortlaufend_quelle", self.sequential_src),
            ("anteil_fortlaufend_quelle", src_ratio),
            ("neue_ziele_folgen", self.dst_transitions),
            ("fortlaufend_ziel", self.sequential_dst),
            ("anteil_fortlaufend_ziel", _share(self.sequential_dst, self.dst_transitions)),
        ])
        if self.dst_transitions >= 9 and (_share(self.sequential_dst, self.dst_transitions) or 0) >= 0.5:
            af2.extra["hinweis_ziel"] = ("Fortlaufende Ziele sind bei Scans "
                                         "Angriffsinhalt (Host-Sweep).")

        # AF3: vorhersagbare Quellports
        repeat_share = _share(self.tuple_repeats, self.syn_connections)
        verdict(af3, self.tuple_repeats >= 5 and (repeat_share or 0) >= 0.01,
                self.syn_connections,
                "Neue Verbindungen wiederholen identische Fuenf-Tupel; typisch "
                "fuer mehrfach injizierte Angriffe oder feste Quellports.")
        af3.extra.update([
            ("neue_tcp_verbindungen", self.syn_connections),
            ("wiederholte_fuenf_tupel", self.tuple_repeats),
            ("anteil_wiederholt", repeat_share),
            ("wiederverwendete_quellports", self.port_reuse),
            ("anteil_quellport_wiederverwendet", _share(self.port_reuse, self.syn_connections)),
            ("fortlaufende_quellports", self.sequential_ports),
            ("anteil_fortlaufend", _share(self.sequential_ports, self.port_transitions)),
            ("hinweis", "Fortlaufende Ports allein sind kein Artefakt: Windows "
                        "vergibt ephemere Ports fortlaufend."),
        ])
        if self.syn_tuples.full or self.syn_ports.full:
            af3.extra["obergrenze_erreicht"] = True

        # AF4: MAC-Praefixe
        vendors = collections.Counter()
        local = 0
        for mac in self.macs.counts:
            vendor = mac_vendor(mac)
            if vendor:
                vendors[vendor] += 1
            if mac[0] & 0x02:
                local += 1
        verdict(af4, bool(vendors), len(self.macs),
                "MAC-Praefixe einer Virtualisierung; fuer die Zusammenfuehrung "
                "ggf. umschreiben (Ebene 4).")
        af4.extra.update([
            ("quell_macs", len(self.macs)),
            ("virtualisierung", dict(vendors.most_common())),
            ("lokal_administriert", local),
        ])

        # AF5: Zeitquantisierung
        effective = None
        if self.quant_total:
            for label, count in zip(QUANT_LABELS, self.quant_counts):
                if count / self.quant_total >= 0.99:
                    effective = label
        self.effective_resolution = effective
        coarse = effective in ("1 ms", "10 ms", "100 ms", "1 s")
        verdict(af5, self.quant_total >= 100 and coarse, self.quant_total,
                f"Zeitstempel liegen auf einem {effective}-Raster, obwohl die "
                "Datei feiner aufloest: Quantisierung durch einen Zeitgeber.")
        af5.extra.update([
            ("dateiaufloesung", sorted(reader.resolutions)),
            ("effektive_aufloesung", effective or "feiner als 1 us"),
            ("anteil_teilbar", collections.OrderedDict(
                (label, _share(count, self.quant_total))
                for label, count in zip(QUANT_LABELS, self.quant_counts))),
        ])

        # AF6: gleichfoermige Taktung. Robust ueber den Quartilsdispersions-
        # koeffizienten (Q3 - Q1) / (Q3 + Q1): eine einzelne lange Pause
        # treibt den Variationskoeffizienten hoch und wuerde eine streng
        # getaktete Injektion verdecken, die Quartile bleiben davon unberuehrt.
        # Poisson-Verkehr liegt bei 0.66, feste Taktung bei 0.
        cv = self.iat_stats.cv
        quartiles = analysis.features["zwischenankunftszeit"].quantiles((0.25, 0.75))
        q1, q3 = quartiles.get(0.25), quartiles.get(0.75)
        qcd = (q3 - q1) / (q3 + q1) if q3 else None
        regular_share = _share(self.flows_regular, self.flows_timed)
        suspicious = (self.iat_stats.count >= 100 and qcd is not None and qcd < 0.1) or \
            (self.flows_timed >= 10 and (regular_share or 0) >= 0.5)
        verdict(af6, suspicious, self.iat_stats.count,
                "Zwischenankunftszeiten sind sehr gleichmaessig; realer "
                "Verkehr ist burstartig (Quartilsdispersion bei Poisson-"
                "Verkehr um 0.66, hier darunter 0.1).")
        af6.extra.update([
            ("quartilsdispersion", _round(qcd, 4)),
            ("variationskoeffizient_global", _round(cv, 4)),
            ("fluesse_ab_10_paketen", self.flows_timed),
            ("fluesse_gleichmaessig_cv_unter_0_1", self.flows_regular),
            ("anteil_gleichmaessig", regular_share),
        ])

        # AF7: Nullnutzlast
        zero_share = _share(self.zero_payload, self.payload_inspected)
        verdict(af7, self.payload_inspected >= 10 and (zero_share or 0) >= 0.5,
                self.payload_inspected,
                "Nutzdaten bestehen ueberwiegend aus Nullbytes: aufgefuellte "
                "Platzhalter statt Anwendungsdaten.")
        af7.extra.update([
            ("pakete_mit_nutzlast", self.payload_inspected),
            ("nur_nullbytes", self.zero_payload),
            ("anteil_nullbytes", zero_share),
        ])

    def _finish_features(self, analysis):
        features = analysis.features
        features["paketgroesse"] = Distribution.from_counter(self.sizes)
        features["zwischenankunftszeit"] = self.iat.distribution(scale=1e-9)

        packets_per_bin = collections.Counter()
        bytes_per_bin = collections.Counter()
        concurrency = collections.Counter()
        if self.ip_t0 is not None:
            first_bin = (self.ip_ts_min - self.ip_t0) // self.bin_ns
            last_bin = (self.ip_ts_max - self.ip_t0) // self.bin_ns
            total_bins = last_bin - first_bin + 1
            for packets, size in self.bins.values():
                packets_per_bin[packets] += 1
                bytes_per_bin[size] += 1
            # leere Intervalle gehoeren zum Durchsatzverlauf dazu
            empty = total_bins - len(self.bins)
            if empty > 0:
                packets_per_bin[0] += empty
                bytes_per_bin[0] += empty
            # gleichzeitig aktive Fluesse: Differenzen aufsummieren; zwischen
            # zwei Aenderungsstellen ist der Wert konstant
            running = 0
            position = first_bin
            for bin_index in sorted(self.concurrency):
                if bin_index > position:
                    concurrency[running] += bin_index - position
                    position = bin_index
                running += self.concurrency[bin_index]
            if position <= last_bin:
                concurrency[running] += last_bin - position + 1
        features["durchsatz_bytes"] = Distribution.from_counter(bytes_per_bin)
        features["durchsatz_pakete"] = Distribution.from_counter(packets_per_bin)
        features["fluss_pakete"] = self.flow_packets.distribution()
        features["fluss_bytes"] = self.flow_bytes.distribution()
        features["fluss_dauer"] = self.flow_duration.distribution(scale=1e-9)
        features["gleichzeitige_fluesse"] = Distribution.from_counter(concurrency)
        features["protokolle"] = dict(self.flow_protocols)
        features["zielports"] = dict(self.flow_services)
        features["quellport_bereiche"] = dict(self.flow_port_ranges)
        features["ttl"] = {str(ttl): count for ttl, count in self.ttls.items()}
        features["tcp_fenster"] = Distribution.from_counter(self.windows)

        seconds = None
        if self.ip_ts_min is not None:
            seconds = (self.ip_ts_max - self.ip_ts_min) / NS
        analysis.seconds = seconds
        tcp_base = self.e4.extra.get("tcp_ohne_randfluesse")
        scalars = analysis.scalars
        scalars["pakete"] = self.ip_packets
        scalars["dauer_s"] = _round(seconds)
        scalars["durchsatz_pakete_pro_s"] = (
            _round(self.ip_packets / seconds) if seconds else None)
        scalars["durchsatz_bytes_pro_s"] = (
            _round(self.ip_bytes / seconds) if seconds else None)
        scalars["fluesse"] = self.flow_count
        scalars["anteil_unvollstaendige_tcp"] = _share(
            self.e4.extra.get("unvollstaendig", 0), tcp_base)
        scalars["anteil_einseitige_fluesse"] = _share(self.one_sided, self.flow_count)
        scalars["anteil_fehlerhafte_pakete"] = _share(self.defect_any, self.ip_records)

    def _finish_overview(self, analysis, reader):
        analysis.effective_resolution = self.effective_resolution
        overview = analysis.overview
        overview["format"] = collections.OrderedDict([
            ("typ", reader.format),
            ("komprimiert", reader.compressed),
            ("version", reader.version),
            ("byte_order", reader.byte_order),
            ("zeitaufloesung", sorted(reader.resolutions)),
            ("effektive_aufloesung", self.effective_resolution or "feiner als 1 us"),
            ("snaplen", reader.snaplen),
            ("link_types", [f"{linktype} ({LINKTYPE_NAMES.get(linktype, 'unbekannt')})"
                            for linktype in sorted(reader.link_types)]),
            ("abgeschnittene_records", self.truncated_records),
            ("probleme", dict(analysis.issues) or None),
        ])
        seconds = None if self.ts_min is None else (self.ts_max - self.ts_min) / NS
        overview["zeitraum"] = collections.OrderedDict([
            ("beginn_utc", _iso(self.ts_min)),
            ("ende_utc", _iso(self.ts_max)),
            ("dauer_s", _round(seconds)),
        ])
        overview["umfang"] = collections.OrderedDict([
            ("records", self.total),
            ("ip_pakete", self.ip_packets),
            ("bytes_draht", self.wire_bytes),
            ("bytes_gespeichert", self.captured_bytes),
            ("bytes_ip", self.ip_bytes),
            ("pakete_pro_s", _round(self.total / seconds, 4) if seconds else None),
            ("bit_pro_s", _round(self.wire_bytes * 8 / seconds, 4) if seconds else None),
            ("lesegrenze_aktiv", analysis.read_limited),
        ])
        overview["schichten"] = collections.OrderedDict([
            ("sicherung", dict(self.l2_counts.most_common())),
            ("vlan_frames", self.vlan_frames),
            ("netz", dict(self.l3_counts.most_common())),
            ("andere_ethertypes", {
                f"0x{value:04x} ({ETHERTYPE_NAMES.get(value, '?')})": count
                for value, count in self.other_ethertypes.most_common(10)}),
            ("transport_pakete", {protocol_name(proto): count
                                  for proto, count in self.proto_packets.most_common()}),
            ("fragmente", self.fragments),
        ])

        def top_hosts(counter):
            return [collections.OrderedDict([
                ("adresse", format_address(address)),
                ("pakete", count),
                ("anteil", _share(count, self.ip_packets, 4)),
                ("klasse", classify_ip(format_address(address))),
            ]) for address, count in counter.most_common(10)]

        overview["hosts"] = collections.OrderedDict([
            ("quelladressen", len(self.sources)),
            ("zieladressen", len(self.destinations)),
            ("vollstaendig_gezaehlt", self.sources.complete and self.destinations.complete),
            ("entropie_quelle_bit", _entropy(self.sources.counts)),
            ("entropie_ziel_bit", _entropy(self.destinations.counts)),
            ("quellklassen", dict(self.src_classes.most_common())),
            ("zielklassen", dict(self.dst_classes.most_common())),
            ("top_quellen", top_hosts(self.sources)),
            ("top_ziele", top_hosts(self.destinations)),
        ])

        services = []
        for service, count in self.flow_services.most_common(15):
            services.append(collections.OrderedDict([
                ("dienst", service),
                ("name", SERVICE_NAMES.get(service)),
                ("fluesse", count),
                ("anteil", _share(count, self.flow_count, 4)),
            ]))
        iot = collections.OrderedDict()
        for name, keys in IOT_SERVICES.items():
            count = sum(self.flow_services.get(key, 0) for key in keys)
            if count:
                iot[name] = count
        overview["dienste"] = collections.OrderedDict([
            ("top_nach_fluessen", services),
            ("iot_fluesse", iot or None),
            ("iot_anteil_fluesse", _share(sum(iot.values()), self.flow_count)),
            ("hinweis", "Portbasierte Zuordnung; ein Dienst auf einem "
                        "Nichtstandardport wird nicht erkannt."),
        ])

        header_only = (self.payload_declared > 0 and self.payload_present == 0)
        overview["nutzdaten"] = collections.OrderedDict([
            ("tcp_udp_pakete", self.transport_packets),
            ("mit_nutzlast", self.payload_packets),
            ("anteil_mit_nutzlast", _share(self.payload_packets, self.transport_packets)),
            ("nutzlast_bytes_deklariert", self.payload_declared),
            ("nutzlast_bytes_vorhanden", self.payload_present),
            ("nur_nullbytes", self.zero_payload),
            ("ohne_nutzdaten_im_mitschnitt", header_only),
        ])
        handshakes = sum(self.tcp_states[state] for state in
                         ("SF", "S1", "S2", "S3", "RSTO", "RSTR"))
        tcp_total = sum(self.tcp_states.values())
        overview["tcp"] = collections.OrderedDict([
            ("flags", dict(self.tcp_flag_counts.most_common(10))),
            ("verbindungen", tcp_total),
            ("mit_handshake", handshakes),
            ("anteil_mit_handshake", _share(handshakes, tcp_total)),
            ("zustaende", collections.OrderedDict(
                (state, collections.OrderedDict([
                    ("anzahl", self.tcp_states[state]),
                    ("bedeutung", text)]))
                for state, text in TCP_STATE_TEXT.items() if self.tcp_states[state])),
        ])

        fidelity = analysis.protocol_fidelity
        fidelity["ip_pakete"] = self.ip_records
        fidelity["fehlerhaft_header"] = self.defect_header
        fidelity["fehlerhaft_pruefsumme"] = self.defect_checksum
        fidelity["fehlerhaft_gesamt"] = self.defect_any
        fidelity["anteil_fehlerhaft"] = _share(self.defect_any, self.ip_records)
        fidelity["anteil_header"] = _share(self.defect_header, self.ip_records)
        fidelity["anteil_pruefsumme"] = _share(self.defect_checksum, self.ip_records)


def _entropy(counts):
    """Shannon-Entropie in Bit ueber die Haeufigkeiten eines Zaehlers."""
    total = sum(counts.values())
    if not total:
        return None
    entropy = -sum((count / total) * math.log2(count / total)
                   for count in counts.values() if count)
    return _round(entropy + 0.0, 4)


def analyze(path, options, label="L1", collect_flow_keys=False, watch=None,
            progress=None, progress_interval=200_000):
    """Einen Mitschnitt vollstaendig auswerten.

    Liefert immer ein Analysis-Objekt; ist die Datei nicht lesbar, steht der
    Grund in analysis.error.
    """
    try:
        reader = CaptureReader(path)
    except (CaptureFormatError, OSError) as error:
        analysis = Analysis(label, path)
        analysis.error = str(error)
        return analysis

    analyzer = Analyzer(label, path, options, collect_flow_keys, watch)
    read_limited = False
    limit = options.max_packets
    feed = analyzer.feed
    try:
        for record in reader:
            if limit is not None and analyzer.total >= limit:
                read_limited = True
                break
            feed(*record)
            if progress is not None and analyzer.total % progress_interval == 0:
                progress(analyzer.total)
        analysis = analyzer.finish(reader, read_limited)
    finally:
        sha256 = reader.finish()
    analysis.sha256 = sha256
    return analysis


# ---------------------------------------------------------------------------
# Distanzmasse (Grundlagen 1.1.4)
# ---------------------------------------------------------------------------

def _merged_cdfs(first, second):
    """Laeuft gemeinsam ueber beide sortierten Wertefolgen.

    Liefert je Stuetzstelle x (aufsteigend) die Werte F1(x) und F2(x) der
    empirischen Verteilungsfunktionen.
    """
    values_a, weights_a, total_a = first.values, first.weights, first.total
    values_b, weights_b, total_b = second.values, second.weights, second.total
    i = j = 0
    cum_a = cum_b = 0.0
    len_a, len_b = len(values_a), len(values_b)
    while i < len_a or j < len_b:
        if j >= len_b or (i < len_a and values_a[i] < values_b[j]):
            x = values_a[i]
        elif i >= len_a or values_b[j] < values_a[i]:
            x = values_b[j]
        else:
            x = values_a[i]
        if i < len_a and values_a[i] == x:
            cum_a += weights_a[i]
            i += 1
        if j < len_b and values_b[j] == x:
            cum_b += weights_b[j]
            j += 1
        yield x, cum_a / total_a, cum_b / total_b


def ks_distance(first, second):
    """D-Wert: groesster senkrechter Abstand der Verteilungsfunktionen."""
    if first.empty or second.empty:
        return None
    distance = 0.0
    for _x, cdf_a, cdf_b in _merged_cdfs(first, second):
        difference = abs(cdf_a - cdf_b)
        if difference > distance:
            distance = difference
    return min(distance, 1.0)


def wasserstein_distance(first, second):
    """W1: Flaeche zwischen den Verteilungsfunktionen (Einheit des Merkmals).

    Zwischen zwei Stuetzstellen sind beide Funktionen konstant; die Flaeche
    ist also die Summe |F1 - F2| mal Abstand der Stuetzstellen.
    """
    if first.empty or second.empty:
        return None
    area = 0.0
    previous_x = None
    previous_difference = 0.0
    for x, cdf_a, cdf_b in _merged_cdfs(first, second):
        if previous_x is not None:
            area += previous_difference * (x - previous_x)
        previous_x = x
        previous_difference = abs(cdf_a - cdf_b)
    return area


def jensen_shannon(first, second):
    """Jensen-Shannon-Divergenz (Basis 2, zwischen 0 und 1) zweier
    kategorialer Verteilungen als {Kategorie: Haeufigkeit}."""
    total_a = math.fsum(first.values())
    total_b = math.fsum(second.values())
    if total_a <= 0 or total_b <= 0:
        return None
    divergence = 0.0
    for key in set(first) | set(second):
        p = first.get(key, 0) / total_a
        q = second.get(key, 0) / total_b
        m = (p + q) / 2
        if p > 0:
            divergence += 0.5 * p * math.log2(p / m)
        if q > 0:
            divergence += 0.5 * q * math.log2(q / m)
    return min(max(divergence, 0.0), 1.0)


def relative_deviation(actual, target):
    """(Ist - Soll) / Soll; None, wenn Soll fehlt oder null ist."""
    if actual is None or target is None or target == 0:
        return None
    return (actual - target) / abs(target)


# ---------------------------------------------------------------------------
# Sollwert aus einer Konfiguration (Facette E2, --spec)
# ---------------------------------------------------------------------------

SPEC_TYPES = ("konstant", "gleichverteilt", "normal", "exponentiell",
              "lognormal", "empirisch", "kategorial")


def load_spec(path):
    """Spezifikation lesen und pruefen. Fehler als SpecError mit Klartext."""
    try:
        with open(path, encoding="utf-8") as handle:
            spec = json.load(handle)
    except (OSError, ValueError) as error:
        raise SpecError(f"Spezifikation nicht lesbar: {error}")
    if not isinstance(spec, dict):
        raise SpecError("Spezifikation muss ein JSON-Objekt sein")
    allowed = {"beschreibung", "reichweite", "verteilungen", "skalare", "ablauf"}
    unknown = set(spec) - allowed
    if unknown:
        raise SpecError(f"unbekannte Abschnitte {sorted(unknown)}; erlaubt sind "
                        f"{sorted(allowed)}")
    for name, entry in (spec.get("verteilungen") or {}).items():
        if name not in FEATURES:
            raise SpecError(f"unbekanntes Merkmal '{name}'; bekannt sind "
                            f"{list(FEATURES)}")
        if not isinstance(entry, dict) or entry.get("typ") not in SPEC_TYPES:
            raise SpecError(f"Merkmal '{name}': 'typ' muss einer von "
                            f"{list(SPEC_TYPES)} sein")
        categorical = FEATURES[name]["typ"] == "kategorial"
        if categorical != (entry["typ"] == "kategorial"):
            raise SpecError(f"Merkmal '{name}' ist {FEATURES[name]['typ']}; "
                            f"Typ '{entry['typ']}' passt nicht")
    for name in (spec.get("skalare") or {}):
        if name not in SCALARS:
            raise SpecError(f"unbekannte skalare Groesse '{name}'; bekannt "
                            f"sind {list(SCALARS)}")
    for name in spec.get("reichweite") or []:
        if name not in FEATURES and name not in SCALARS:
            raise SpecError(f"Reichweite nennt unbekanntes Merkmal '{name}'")
    for index, entry in enumerate(spec.get("ablauf") or []):
        SequenceStep(index, entry)          # wirft bei Fehlern
    return spec


def _normalize_category(feature, key):
    """Kategorienamen der Spezifikation auf die Schreibweise der Merkmale."""
    text = str(key).strip()
    if feature == "protokolle":
        number = _parse_protocol(text)
        return protocol_name(number)
    if feature == "zielports":
        if "/" not in text:
            if text.isdigit():
                raise SpecError(f"zielports: '{text}' ohne Protokoll; "
                                "erwartet etwa '80/tcp'")
            return text.lower()
        port, proto = text.split("/", 1)
        return f"{int(port)}/{proto.strip().lower()}"
    return text


def spec_distribution(feature, entry, rng, size):
    """Sollverteilung aus der Spezifikation.

    Analytische Verteilungen werden als Stichprobe mit festem Startwert
    gezogen (Konzeption: "zaehlt eine daraus gezogene Stichprobe").
    """
    kind = entry["typ"]
    try:
        if kind == "kategorial":
            shares = entry["anteile"]
            return {_normalize_category(feature, key): float(value)
                    for key, value in shares.items()}
        if kind == "konstant":
            return Distribution.from_counter({float(entry["wert"]): 1})
        if kind == "empirisch":
            values = [float(value) for value in entry["werte"]]
            weights = entry.get("gewichte")
            if weights:
                counter = collections.Counter()
                for value, weight in zip(values, weights):
                    counter[value] += float(weight)
                return Distribution.from_counter(counter)
            return Distribution.from_values(values)
        if kind == "gleichverteilt":
            low, high = float(entry["min"]), float(entry["max"])
            draw = lambda: rng.uniform(low, high)
        elif kind == "normal":
            mean, std = float(entry["mittelwert"]), float(entry["std"])
            draw = lambda: rng.gauss(mean, std)
        elif kind == "exponentiell":
            mean = float(entry["mittelwert"])
            draw = lambda: rng.expovariate(1.0 / mean)
        else:  # lognormal
            mu, sigma = float(entry["mu"]), float(entry["sigma"])
            draw = lambda: rng.lognormvariate(mu, sigma)
    except (KeyError, TypeError, ValueError, ZeroDivisionError) as error:
        raise SpecError(f"Merkmal '{feature}' ({kind}): Parameter fehlt oder "
                        f"ist ungueltig ({error})")
    low = entry.get("min_clip")
    high = entry.get("max_clip")
    values = array.array("d")
    for _ in range(size):
        value = draw()
        if low is not None:
            value = max(value, float(low))
        if high is not None:
            value = min(value, float(high))
        values.append(value)
    return Distribution.from_values(values)


class Target:
    """Sollwert: Verteilungen und Skalare aus Mitschnitt und/oder Spezifikation."""

    def __init__(self):
        self.kind = "keiner"          # keiner | mitschnitt | konfiguration | beides
        self.features = {}
        self.scalars = {}
        self.sources = []
        self.assured = None           # None = unbekannt
        self.description = None

    @property
    def available(self):
        return bool(self.features or self.scalars)


def build_target(reference, spec, seed, sample_size):
    """Sollwert zusammensetzen; die Spezifikation hat Vorrang je Merkmal."""
    target = Target()
    if reference is not None and reference.error is None:
        target.kind = "mitschnitt"
        target.features = dict(reference.features)
        target.scalars = dict(reference.scalars)
        target.sources.append(reference.path)
    if spec is not None:
        target.kind = "beides" if target.kind == "mitschnitt" else "konfiguration"
        rng = random.Random(seed + 1)
        for feature, entry in (spec.get("verteilungen") or {}).items():
            target.features[feature] = spec_distribution(feature, entry, rng,
                                                         sample_size)
        for name, value in (spec.get("skalare") or {}).items():
            target.scalars[name] = float(value)
        if spec.get("reichweite") is not None:
            target.assured = list(spec["reichweite"])
        elif spec.get("verteilungen") or spec.get("skalare"):
            target.assured = list(spec.get("verteilungen") or {}) + \
                list(spec.get("skalare") or {})
        target.description = spec.get("beschreibung")
    return target


# ---------------------------------------------------------------------------
# Werkzeug-Diskrepanz (Konzeption 1.3.1)
# ---------------------------------------------------------------------------

def _median_max(values):
    values = [value for value in values if value is not None]
    if not values:
        return collections.OrderedDict([("median", None), ("max", None)])
    return collections.OrderedDict([("median", _round(statistics.median(values), 4)),
                                    ("max", _round(max(values), 4))])


def _continuous_measures(first, second, span):
    distance = ks_distance(first, second)
    area = wasserstein_distance(first, second)
    if area is None:
        normalized = None
    elif span > 0:
        normalized = min(area / span, 1.0)
    else:
        normalized = 0.0              # alle Werte identisch: keine Abweichung
    return collections.OrderedDict([("D", _round(distance, 4)), ("W1", _round(area, 4)),
                                    ("W1_norm", _round(normalized, 4))])


def compare_feature(feature, runs, target_value, assured):
    """Eigenstreuung und Sollabweichung fuer ein Merkmal."""
    meta = FEATURES[feature]
    labels = [run.label for run in runs]
    values = [run.features.get(feature) for run in runs]
    entry = collections.OrderedDict([
        ("typ", meta["typ"]),
        ("ebene", meta["ebene"]),
        ("einheit", meta["einheit"]),
        ("tabelle_1_4", meta["konzept"]),
        ("zugesichert", None if assured is None else feature in assured),
    ])
    continuous = meta["typ"] == "stetig"
    measures = ("D", "W1_norm") if continuous else ("JSD",)

    if continuous:
        present = [value for value in values + [target_value]
                   if value is not None and not value.empty]
        if not present:
            entry["hinweis"] = "keine Werte"
            return entry
        low = min(value.minimum for value in present)
        high = max(value.maximum for value in present)
        span = high - low
        entry["spannweite"] = collections.OrderedDict([
            ("min", _round(low)), ("max", _round(high))])
        compare = lambda a, b: _continuous_measures(a, b, span)
    else:
        compare = lambda a, b: collections.OrderedDict(
            [("JSD", _round(jensen_shannon(a, b), 4))])

    pairs = collections.OrderedDict()
    for i in range(len(runs)):
        for j in range(i + 1, len(runs)):
            pairs[f"{labels[i]}-{labels[j]}"] = compare(values[i], values[j])
    thresholds = {}
    if pairs:
        spread = collections.OrderedDict()
        for measure in measures:
            spread[measure] = _median_max(pair[measure] for pair in pairs.values())
            thresholds[measure] = spread[measure]["max"]
        spread["paare"] = pairs
        entry["eigenstreuung"] = spread

    if target_value is not None:
        deviation = collections.OrderedDict()
        over = collections.Counter()
        for label, value in zip(labels, values):
            result = compare(value, target_value)
            for measure in measures:
                threshold = thresholds.get(measure)
                if threshold is None or result[measure] is None:
                    exceeds = None
                else:
                    exceeds = result[measure] > threshold
                    over[measure] += exceeds
                result[f"ueber_{measure}"] = exceeds
            deviation[label] = result
        summary = collections.OrderedDict()
        for measure in measures:
            summary[measure] = _median_max(deviation[label][measure] for label in labels)
        summary["laeufe_ueber_schwelle"] = (
            {measure: over[measure] for measure in measures} if thresholds else None)
        summary["laeufe"] = deviation
        entry["sollabweichung"] = summary
    return entry


def compare_scalars(runs, target):
    """Skalare: Werte je Lauf, Streuung und relative Abweichung vom Soll."""
    result = collections.OrderedDict()
    for name, text in SCALARS.items():
        values = [run.scalars.get(name) for run in runs]
        present = [value for value in values if value is not None]
        entry = collections.OrderedDict([("bedeutung", text)])
        entry["werte"] = collections.OrderedDict(
            (run.label, value) for run, value in zip(runs, values))
        if present:
            median = statistics.median(present)
            entry["median"] = _round(median)
            entry["min"] = _round(min(present))
            entry["max"] = _round(max(present))
            entry["streuung_relativ"] = (_round((max(present) - min(present)) / abs(median))
                                         if median else None)
        target_value = target.scalars.get(name) if target else None
        if target_value is not None:
            entry["soll"] = _round(target_value)
            deviations = collections.OrderedDict(
                (run.label, _round(relative_deviation(value, target_value)))
                for run, value in zip(runs, values))
            entry["abweichung_relativ"] = deviations
            # Schwelle wie bei den Verteilungen: groesster Abstand zweier
            # Laeufe, in derselben Normierung (bezogen auf den Sollwert)
            if len(present) >= 2 and target_value:
                threshold = (max(present) - min(present)) / abs(target_value)
                entry["schwelle"] = _round(threshold)
                entry["ueber_schwelle"] = collections.OrderedDict(
                    (label, None if value is None else abs(value) > threshold)
                    for label, value in deviations.items())
        result[name] = entry
    return result


def compare_runs(runs, target, assured):
    """Gesamte Werkzeug-Diskrepanz ueber alle Laeufe."""
    usable = [run for run in runs if run.error is None]
    result = collections.OrderedDict()
    result["laeufe"] = [run.label for run in usable]
    result["sollwert"] = target.kind if target else "keiner"
    result["reichweite"] = assured
    features = collections.OrderedDict()
    for feature in FEATURES:
        target_value = target.features.get(feature) if target else None
        features[feature] = compare_feature(feature, usable, target_value, assured)
    result["merkmale"] = features
    result["skalare"] = compare_scalars(usable, target)

    if any(run.sequence for run in usable):
        result["strukturelle_vollstaendigkeit"] = collections.OrderedDict(
            (run.label, collections.OrderedDict([
                ("gefunden", run.sequence["gefunden"]),
                ("schritte", run.sequence["schritte"]),
                ("anteil", run.sequence["anteil"]),
                ("reihenfolge_eingehalten", run.sequence["reihenfolge_eingehalten"]),
            ])) for run in usable if run.sequence)

    findings = []
    for feature, entry in features.items():
        deviation = entry.get("sollabweichung")
        if not deviation or not deviation.get("laeufe_ueber_schwelle"):
            continue
        counts = deviation["laeufe_ueber_schwelle"]
        if any(counts.values()):
            findings.append(collections.OrderedDict([
                ("merkmal", feature),
                ("zugesichert", entry["zugesichert"]),
                ("laeufe_ueber_schwelle", counts),
                ("von", len(usable)),
            ]))
    result["abweichungen_ueber_schwelle"] = findings
    return result


# ---------------------------------------------------------------------------
# Ebene 4: Hintergrundverkehr (--background)
# ---------------------------------------------------------------------------

def _overlaps(start, end, intervals, window_ns):
    low, high = start - window_ns, end + window_ns
    return any(first <= high and last >= low for first, last in intervals)


def compare_background(runs, background, window_seconds):
    """Zusammenfuehrbarkeit, Label-Konflikte und Angriffsanteil."""
    window_ns = int(window_seconds * NS)
    result = collections.OrderedDict()

    def link_names(analysis):
        return [f"{value} ({LINKTYPE_NAMES.get(value, 'unbekannt')})"
                for value in sorted(analysis.link_types)]

    link_types = collections.OrderedDict([("hintergrund", link_names(background))])
    resolutions = collections.OrderedDict([("hintergrund", collections.OrderedDict([
        ("datei", sorted(background.resolutions)),
        ("effektiv", background.effective_resolution)]))])
    collisions = collections.OrderedDict()
    labels = collections.OrderedDict()
    shares = collections.OrderedDict()
    for run in runs:
        if run.error:
            continue
        link_types[run.label] = link_names(run)
        resolutions[run.label] = collections.OrderedDict([
            ("datei", sorted(run.resolutions)), ("effektiv", run.effective_resolution)])

        shared = run.addresses & background.addresses
        shared_macs = run.macs & background.macs
        collisions[run.label] = collections.OrderedDict([
            ("adressen_lauf", len(run.addresses)),
            ("kollisionen", len(shared)),
            ("anteil", _share(len(shared), len(run.addresses))),
            ("beispiele", sorted(format_address(a) for a in shared)[:10]),
            ("mac_kollisionen", len(shared_macs)),
            ("vollstaendig", run.addresses_complete and background.addresses_complete),
        ])

        start, end = run.ts_range
        bg_start, bg_end = background.ts_range
        overlap = (None not in (start, end, bg_start, bg_end)
                   and start <= bg_end + window_ns and end >= bg_start - window_ns)
        total = conflicts_any = conflicts_window = 0
        hits = background.watch_hits or {}
        for key, intervals in (run.flow_keys or {}).items():
            occurrences = hits.get(key)
            for first, last, packets in intervals:
                total += packets
                if occurrences:
                    conflicts_any += packets
                    if overlap and _overlaps(first, last, occurrences, window_ns):
                        conflicts_window += packets
        entry = collections.OrderedDict([
            ("pakete_in_fluessen", total),
            ("konflikte_zeitunabhaengig", conflicts_any),
            ("anteil_eindeutig_zeitunabhaengig",
             _share(total - conflicts_any, total)),
            ("zeitachsen_ueberlappen", overlap),
            ("fenster_s", window_seconds),
        ])
        if overlap:
            entry["konflikte_im_zeitfenster"] = conflicts_window
            entry["anteil_eindeutig_im_zeitfenster"] = _share(total - conflicts_window, total)
        else:
            entry["konflikte_im_zeitfenster"] = None
            entry["hinweis"] = ("Zeitachsen ueberlappen nicht; Mitschnitt vor der "
                                "Pruefung im Zeitfenster zeitlich ausrichten.")
        if not run.flow_keys_complete:
            entry["unvollstaendig"] = "Flussgrenze erreicht"
        labels[run.label] = entry

        shares[run.label] = collections.OrderedDict([
            ("je_paket", _share(run.ip_packets, run.ip_packets + background.ip_packets)),
            ("je_fluss", _share(run.flow_count, run.flow_count + background.flow_count)),
        ])

    distinct = {tuple(value) for value in link_types.values()}
    result["datei"] = background.path
    result["sha256"] = background.sha256
    result["pakete"] = background.ip_packets
    result["fluesse"] = background.flow_count
    result["sicherungsschicht"] = collections.OrderedDict([
        ("einheitlich", len(distinct) == 1), ("link_types", link_types)])
    result["zeitaufloesung"] = resolutions
    result["adresskollisionen"] = collisions
    result["label_integritaet"] = labels
    result["angriffsanteil"] = shares
    return result


# ---------------------------------------------------------------------------
# Validator: Meldungen und Gesamtbewertung
# ---------------------------------------------------------------------------

LEVEL_ERROR = "fehler"
LEVEL_WARN = "warnung"
LEVEL_HINT = "hinweis"

ISSUE_TEXT = {
    "datei_endet_im_record_header": (LEVEL_WARN, "Datei endet mitten in einem "
                                     "Record-Header (abgebrochener Mitschnitt?)"),
    "datei_endet_im_record": (LEVEL_WARN, "Datei endet mitten in einem Record "
                              "(abgebrochener Mitschnitt?)"),
    "datei_endet_im_block_header": (LEVEL_WARN, "pcapng endet mitten in einem "
                                    "Block-Header"),
    "datei_endet_im_block": (LEVEL_WARN, "pcapng endet mitten in einem Block"),
    "record_laenge_unplausibel": (LEVEL_WARN, "Record-Laenge unplausibel; Datei "
                                  "ab hier beschaedigt, der Rest wurde nicht gelesen"),
    "pcapng_block_laenge_unplausibel": (LEVEL_WARN, "pcapng-Blocklaenge "
                                        "unplausibel; Rest nicht gelesen"),
    "zeitstempel_bruchteil_ungueltig": (LEVEL_WARN, "Zeitstempel mit Bruchteil "
                                        ">= 1 s (Formatverstoss)"),
    "incl_len_groesser_orig_len": (LEVEL_WARN, "incl_len > orig_len: mehr Bytes "
                                   "gespeichert als auf dem Draht (Formatverstoss)"),
    "record_groesser_als_snaplen": (LEVEL_HINT, "Records groesser als der "
                                    "Snaplen im Dateikopf"),
    "pcapng_spb_ohne_zeitstempel": (LEVEL_HINT, "Simple Packet Blocks ohne "
                                    "Zeitstempel; Zeit- und Flussmerkmale "
                                    "unvollstaendig"),
    "pcapng_interface_unbekannt": (LEVEL_WARN, "Pakete verweisen auf ein "
                                   "unbekanntes Interface"),
}


def _message(level, role, source, text):
    return collections.OrderedDict([("stufe", level), ("rolle", role),
                                    ("quelle", source), ("text", text)])


def _percent(part, whole):
    if not whole:
        return "-"
    share = 100.0 * part / whole
    if 0 < share < 0.01:
        return "<0.01 %"
    return f"{share:.2f} %"


def analysis_messages(analysis, role):
    """Meldungen zu einem Mitschnitt (Lauf, Referenz oder Hintergrund)."""
    messages = []
    source = analysis.label

    def add(level, text):
        messages.append(_message(level, role, source, text))

    if analysis.error:
        add(LEVEL_ERROR if role == "lauf" else LEVEL_WARN,
            f"Datei nicht auswertbar: {analysis.error}")
        return messages
    if analysis.records == 0:
        add(LEVEL_ERROR if role == "lauf" else LEVEL_WARN,
            "Mitschnitt enthaelt keine Pakete")
        return messages
    if analysis.ip_packets == 0:
        add(LEVEL_WARN, "keine IP-Pakete; Pruefungen und Merkmale bleiben leer")
    for issue, count in sorted(analysis.issues.items()):
        level, text = ISSUE_TEXT.get(issue, (LEVEL_WARN, issue))
        add(level, f"{text} ({count}x)" if count > 1 else text)
    if analysis.read_limited:
        add(LEVEL_WARN, "Lesegrenze aktiv (--max-packets): die Werte stammen vom "
            "Dateianfang und sind nicht repraesentativ (verzerrt E4, E5 und "
            "alle Verteilungen)")

    for check in analysis.checks.values():
        status = check.status
        if status not in (STATUS_FAIL, STATUS_WARN):
            continue
        if check.group == "artefakt":
            text = f"{check.key} {check.name}: auffaellig"
        elif check.status_override is not None and not check.violations:
            text = f"{check.key} {check.name}"
        elif check.key == "E5":
            extra = check.extra
            text = (f"E5 {check.name}: {extra['belegte_klassen']}/"
                    f"{extra['klassen_gesamt']} Groessenklassen belegt, groesste "
                    f"Klasse {100.0 * extra['groesster_klassenanteil']:.1f} %")
        else:
            text = (f"{check.key} {check.name}: {check.violations} von "
                    f"{check.checked} ({_percent(check.violations, check.checked)})")
        if check.note:
            text += f" - {check.note}"
        add(LEVEL_ERROR if status == STATUS_FAIL else LEVEL_WARN, text)

    if analysis.checks["E4"].extra.get("flussgrenze_erreicht"):
        add(LEVEL_WARN, "Obergrenze aktiver Fluesse erreicht (--max-flows); "
            "Flussmerkmale unvollstaendig")
    sampled = [f"{name} ({int(value.total)} von {int(value.population)})"
               for name, value in analysis.features.items()
               if isinstance(value, Distribution) and not value.exact]
    if sampled:
        add(LEVEL_HINT, "Reservoir-Stichprobe statt Vollerhebung bei: "
            + ", ".join(sampled))
    return messages


def call_messages(runs, reference, background, target, assured, args,
                  discrepancy):
    """Meldungen zum Aufruf als Ganzes (Laufzahl, Facetten, Sollwert)."""
    messages = []

    def add(level, text):
        messages.append(_message(level, "aufruf", "Aufruf", text))

    usable = [run for run in runs if run.error is None]
    if len(runs) < RECOMMENDED_RUNS:
        if len(runs) == 1:
            add(LEVEL_WARN, "Nur ein Lauf: Eigenstreuung nicht berechenbar, "
                "Sollabweichung ohne Schwelle. Die Konzeption sieht fuenf "
                "Laeufe bei unveraenderter Konfiguration vor.")
        else:
            add(LEVEL_WARN, f"Nur {len(runs)} Laeufe; die Konzeption sieht "
                "fuenf vor (Eigenstreuung aus zehn Paaren, ein Ausreisser "
                "bestimmt den Median dann nicht).")
    elif len(runs) > RECOMMENDED_RUNS:
        add(LEVEL_HINT, f"{len(runs)} Laeufe statt fuenf; alle gehen in die "
            "Eigenstreuung ein.")

    by_hash = collections.defaultdict(list)
    for run in usable:
        by_hash[run.sha256].append(run.label)
    for labels in by_hash.values():
        if len(labels) > 1:
            add(LEVEL_WARN, f"{', '.join(labels)} sind bytegleich: dieselbe Datei "
                "mehrfach angegeben? (Bei deterministischen Werkzeugen erwartbar.)")
    if reference is not None and reference.sha256 in by_hash:
        add(LEVEL_WARN, "Ein Lauf ist bytegleich mit dem Referenzmitschnitt.")

    link_sets = {tuple(sorted(run.link_types)) for run in usable}
    if len(link_sets) > 1:
        add(LEVEL_WARN, "Die Laeufe haben unterschiedliche Link-Types; "
            "Konfiguration oder Aufzeichnung war nicht unveraendert.")

    facet_e = args.facet_e
    kind = target.kind if target else "keiner"
    if facet_e == "E1" and kind != "keiner":
        add(LEVEL_WARN, "Facette E1 (kein Sollwert), aber ein Sollwert wurde "
            "angegeben; er wird trotzdem ausgewertet.")
    elif facet_e == "E2" and kind not in ("konfiguration", "beides"):
        add(LEVEL_WARN, "Facette E2 verlangt einen Sollwert aus der "
            "Konfiguration (--spec).")
    elif facet_e in ("E3", "E4") and kind not in ("mitschnitt", "beides"):
        add(LEVEL_WARN, f"Facette {facet_e} verlangt einen Sollwert aus einem "
            "Mitschnitt (--reference).")
    if kind == "keiner":
        add(LEVEL_HINT, "Kein Sollwert angegeben: nur Selbstvergleich "
            "(Eigenstreuung), wie bei Facette E1.")
    elif assured is None:
        add(LEVEL_HINT, "Reichweite der Zusicherung unbekannt (--assured oder "
            "'reichweite' in --spec); Sollabweichungen werden fuer alle "
            "Merkmale berichtet.")
    if reference is not None and reference.error is None and usable:
        run_links = set().union(*(run.link_types for run in usable))
        if reference.link_types != run_links:
            add(LEVEL_HINT, "Referenz und Laeufe haben unterschiedliche "
                "Link-Types; die Merkmale beziehen sich auf Schicht 3 und "
                "bleiben vergleichbar.")

    for finding in (discrepancy or {}).get("abweichungen_ueber_schwelle", []):
        if finding["zugesichert"] is False:
            continue
        counts = ", ".join(f"{measure} {count}/{finding['von']}"
                           for measure, count in finding["laeufe_ueber_schwelle"].items())
        prefix = "zugesichertes Merkmal" if finding["zugesichert"] else "Merkmal"
        add(LEVEL_HINT, f"Sollabweichung ueber der Eigenstreuung: {prefix} "
            f"{finding['merkmal']} ({counts} Laeufen)")
    for name, entry in (discrepancy or {}).get("skalare", {}).items():
        over = [label for label, value in (entry.get("ueber_schwelle") or {}).items()
                if value]
        if over and (assured is None or name in assured):
            add(LEVEL_HINT, f"Skalare Sollabweichung ueber der Streuung der "
                f"Laeufe: {name} (Soll {_fmt_num(entry['soll'])}; "
                f"{len(over)}/{len(entry['werte'])} Laeufen)")
    return messages


def overall_status(messages, strict=False):
    """Gesamtstatus und Rueckgabewert; zaehlen nur Laeufe und Aufruf."""
    counted = [m for m in messages if m["rolle"] in ("lauf", "aufruf")]
    errors = sum(1 for m in counted if m["stufe"] == LEVEL_ERROR)
    warnings = sum(1 for m in counted if m["stufe"] == LEVEL_WARN)
    if errors:
        status = STATUS_FAIL
    elif warnings:
        status = STATUS_WARN
    else:
        status = STATUS_OK
    exit_code = 1 if errors or (strict and warnings) else 0
    return status, errors, warnings, exit_code


# ---------------------------------------------------------------------------
# Ergebnisdatei (YAML oder JSON)
#
# YAML, weil es ohne Klammerrauschen lesbar ist, Kommentare erlaubt und von
# jeder Sprache (und jedem Sprachmodell) gelesen wird. Der Schreiber ist
# eingebaut, damit keine Fremdabhaengigkeit entsteht; er erzeugt nur eine
# sichere Teilmenge (Block-Stil, Zeichenketten bei Bedarf in JSON-Quoting,
# das in YAML gueltig ist). Lesen etwa mit yaml.safe_load (PyYAML).
# ---------------------------------------------------------------------------

_PLAIN = re.compile(r"^[A-Za-z_/][A-Za-z0-9 _./()%+=<>*'-]*$")
_RESERVED = {"true", "false", "yes", "no", "on", "off", "null", "y", "n", "~"}


def _yaml_scalar(value, flow=False):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return ".nan"
        if math.isinf(value):
            return ".inf" if value > 0 else "-.inf"
        text = repr(value)
        if "e" in text:
            # YAML 1.1 (PyYAML) erkennt 1e-05 nicht als Zahl, 1.0e-05 schon
            mantissa, exponent = text.split("e")
            if "." not in mantissa:
                mantissa += ".0"
            text = f"{mantissa}e{exponent}"
        return text
    text = str(value)
    if (_PLAIN.match(text) and text.lower() not in _RESERVED
            and not text.endswith(" ") and ": " not in text and " #" not in text
            and not (flow and any(char in text for char in ",[]{}"))):
        return text
    return json.dumps(text, ensure_ascii=False)


def _is_scalar(value):
    return not isinstance(value, (dict, list, tuple))


def _flow_form(value):
    """Kurze Listen und flache Mappings einzeilig, sonst None."""
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        if len(value) <= 12 and all(_is_scalar(item) for item in value):
            text = "[" + ", ".join(_yaml_scalar(item, True) for item in value) + "]"
            if len(text) <= 100:
                return text
        return None
    if isinstance(value, dict):
        if not value:
            return "{}"
        if len(value) <= 8 and all(_is_scalar(item) for item in value.values()):
            text = "{" + ", ".join(f"{_yaml_scalar(str(key), True)}: "
                                   f"{_yaml_scalar(item, True)}"
                                   for key, item in value.items()) + "}"
            if len(text) <= 120:
                return text
        return None
    return _yaml_scalar(value)


def _emit_yaml(value, indent, lines):
    pad = " " * indent
    if isinstance(value, dict):
        for key, item in value.items():
            name = _yaml_scalar(str(key))
            inline = _flow_form(item)
            if inline is not None:
                lines.append(f"{pad}{name}: {inline}")
            else:
                lines.append(f"{pad}{name}:")
                _emit_yaml(item, indent + 2, lines)
    else:
        for item in value:
            inline = _flow_form(item)
            if inline is not None:
                lines.append(f"{pad}- {inline}")
            elif isinstance(item, dict):
                nested = []
                _emit_yaml(item, indent + 2, nested)
                lines.append(f"{pad}- {nested[0][indent + 2:]}")
                lines.extend(nested[1:])
            else:
                lines.append(f"{pad}-")
                _emit_yaml(item, indent + 2, lines)


def to_yaml(data, header=None):
    lines = []
    if header:
        lines.extend(f"# {line}".rstrip() for line in header)
        lines.append("")
    _emit_yaml(data, 0, lines)
    return "\n".join(lines) + "\n"


def _json_ready(value):
    """OrderedDict, Tupel und Mengen in JSON-Grundtypen ueberfuehren."""
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_ready(item) for item in value]
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    return value


LESEHILFE = collections.OrderedDict([
    ("aufbau", "bewertung (Validator-Meldungen) -> laeufe_kurz (Tabelle) -> "
               "diskrepanz (Eigenstreuung, Sollabweichung) -> hintergrund "
               "(Ebene 4, optional) -> sollwert -> laeufe (alle Details)"),
    ("laeufe", "L1..Ln sind die Laeufe in der Reihenfolge der Kommandozeile; "
               "Zuordnung zu Dateien unter meta.laeufe"),
    ("status", "ok = bestanden; warnung = auffaellig, Deutung noetig; "
               "fehler = Verstoss; info = erwartbar (etwa nach Facette D); "
               "n/a = nicht anwendbar oder keine Daten"),
    ("rolle", "Meldungen der Rollen lauf und aufruf bestimmen Status und "
              "Rueckgabewert; referenz und hintergrund nur informativ"),
    ("D", "Kolmogorov-Smirnov-Statistik: groesster Abstand der "
          "Verteilungsfunktionen (0..1)"),
    ("W1", "Wasserstein-Distanz in der Einheit des Merkmals"),
    ("W1_norm", "W1 geteilt durch die gemeinsame Spannweite aller Laeufe und "
                "des Sollwerts (0..1); stets zusammen mit D lesen"),
    ("JSD", "Jensen-Shannon-Divergenz mit Logarithmus zur Basis 2 (0..1)"),
    ("eigenstreuung", "paarweise Distanzen der Laeufe; das Maximum ist die "
                      "Schwelle fuer die Sollabweichung"),
    ("sollabweichung", "Distanz jedes Laufs zum Sollwert; ueber_D, "
                       "ueber_W1_norm, ueber_JSD = groesser als das Maximum der "
                       "Eigenstreuung desselben Masses (Lesehilfe, kein "
                       "Signifikanzkriterium); null = keine Schwelle (< 2 Laeufe)"),
    ("pruefgruppen", collections.OrderedDict([
        ("P", "Konsistenztests nach Yin et al. (NetShare), Appendix B"),
        ("E", "Eigenleistung: Luecken der P-Tests, Mitschnitt, Befunde"),
        ("AF", "Erzeugungsartefakte nach der Pruefliste der Konzeption"),
    ])),
    ("anteil_fehlerhaft", "Anteil der IP-Pakete mit mindestens einem Header- "
                          "(P1, P3, P4, E1, E2, E9, E10) oder Pruefsummenfehler "
                          "(E7, E8): Messgroesse der Protokolltreue"),
    ("tcp_zustaende", TCP_STATE_TEXT),
    ("quellport_bereiche", "0-1023 well-known, 1024-32767 registriert, "
                           "32768-49151 nur Linux-ephemer, 49152-60999 Linux und "
                           "Windows, 61000-65535 Windows/IANA-dynamisch"),
    ("zeiten", "Zeitstempel in UTC; Dauern und Zwischenankunftszeiten in s"),
])


def feature_summary(name, value):
    meta = FEATURES[name]
    if isinstance(value, Distribution):
        return value.summary(meta["einheit"])
    total = sum(value.values())
    if not total:
        return collections.OrderedDict([("n", 0)])
    top = sorted(value.items(), key=lambda item: (-item[1], str(item[0])))[:10]
    return collections.OrderedDict([
        ("n", int(total)),
        ("kategorien", len(value)),
        ("anteile_top10", collections.OrderedDict(
            (str(key), _round(count / total, 4)) for key, count in top)),
    ])


def analysis_to_dict(analysis):
    data = collections.OrderedDict([
        ("id", analysis.label),
        ("datei", os.path.abspath(analysis.path)),
        ("groesse_bytes", analysis.file_size),
        ("sha256", analysis.sha256),
    ])
    if analysis.error:
        data["fehler"] = analysis.error
        return data
    data["status"] = analysis.worst_status()
    data.update(analysis.overview)
    data["protokolltreue"] = analysis.protocol_fidelity
    data["pruefungen"] = [check.to_dict() for check in analysis.checks.values()]
    data["merkmale"] = collections.OrderedDict(
        (name, feature_summary(name, value))
        for name, value in analysis.features.items())
    data["skalare"] = analysis.scalars
    if analysis.sequence:
        data["ablauf"] = analysis.sequence
    return data


def run_table(runs):
    """Kompakte Tabelle je Lauf fuer den schnellen Ueberblick."""
    table = collections.OrderedDict()
    for run in runs:
        if run.error:
            table[run.label] = collections.OrderedDict([
                ("datei", os.path.basename(run.path)), ("status", STATUS_FAIL),
                ("fehler", run.error)])
            continue
        failed = [key for key, check in run.checks.items() if check.status == STATUS_FAIL]
        warned = [key for key, check in run.checks.items() if check.status == STATUS_WARN]
        table[run.label] = collections.OrderedDict([
            ("datei", os.path.basename(run.path)),
            ("status", run.worst_status()),
            ("ip_pakete", run.ip_packets),
            ("dauer_s", run.scalars.get("dauer_s")),
            ("fluesse", run.flow_count),
            ("anteil_fehlerhaft", run.protocol_fidelity.get("anteil_fehlerhaft")),
            ("fehler", failed),
            ("warnungen", warned),
        ])
    return table


def build_result(args, argv, runs, reference, background, target, assured,
                 discrepancy, background_result, messages, options):
    status, errors, warnings, _ = overall_status(messages, args.strict)
    result = collections.OrderedDict()
    result["lesehilfe"] = LESEHILFE
    result["meta"] = collections.OrderedDict([
        ("werkzeug", args.tool),
        ("pcap_check_version", __version__),
        ("erzeugt_utc", datetime.datetime.now(datetime.timezone.utc)
         .strftime("%Y-%m-%dT%H:%M:%SZ")),
        ("aufruf", " ".join(argv)),
        ("python", platform.python_version()),
        ("parameter", options.to_dict()),
        ("facetten", collections.OrderedDict([("D", args.facet_d),
                                              ("E", args.facet_e)])),
        ("reichweite", assured),
        ("laeufe", collections.OrderedDict(
            (run.label, collections.OrderedDict([
                ("datei", os.path.abspath(run.path)), ("sha256", run.sha256)]))
            for run in runs)),
    ])
    result["bewertung"] = collections.OrderedDict([
        ("status", status),
        ("fehler", errors),
        ("warnungen", warnings),
        ("meldungen", messages),
    ])
    result["laeufe_kurz"] = run_table(runs)
    result["protokolltreue"] = collections.OrderedDict(
        (run.label, run.protocol_fidelity) for run in runs if not run.error)
    result["diskrepanz"] = discrepancy
    if background_result is not None:
        result["hintergrund"] = background_result
    target_info = collections.OrderedDict([
        ("art", target.kind),
        ("beschreibung", target.description),
        ("spezifikation", os.path.abspath(args.spec) if args.spec else None),
    ])
    if reference is not None:
        target_info["referenz"] = analysis_to_dict(reference)
    result["sollwert"] = target_info
    result["laeufe"] = [analysis_to_dict(run) for run in runs]
    return result


def write_result(result, path):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    if path.lower().endswith(".json"):
        text = json.dumps(_json_ready(result), indent=2, ensure_ascii=False) + "\n"
    else:
        tool = result["meta"]["werkzeug"] or "unbenannt"
        header = [
            f"pcap_check {__version__} - Ergebnis fuer Werkzeug: {tool}",
            f"erzeugt {result['meta']['erzeugt_utc']}; Gesamtstatus: "
            f"{result['bewertung']['status']}",
            "Lesehilfe zu allen Feldern und Massen: Abschnitt 'lesehilfe'.",
            "Einlesen in Python: yaml.safe_load(open(pfad, encoding='utf-8'))",
        ]
        text = to_yaml(result, header)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


# ---------------------------------------------------------------------------
# Konsolenausgabe
# ---------------------------------------------------------------------------

class Style:
    """ANSI-Farben nur auf einem Terminal und ohne NO_COLOR."""
    CODES = {STATUS_OK: "32", STATUS_FAIL: "31", STATUS_WARN: "33",
             STATUS_INFO: "36", STATUS_NA: "2", LEVEL_HINT: "36", "bold": "1"}
    TAGS = {STATUS_OK: "OK  ", STATUS_FAIL: "FEHL", STATUS_WARN: "WARN",
            STATUS_INFO: "INFO", STATUS_NA: "n/a ", LEVEL_HINT: "HINW"}

    def __init__(self, enabled):
        self.enabled = enabled

    def paint(self, text, code):
        if not self.enabled or not code:
            return text
        return f"\033[{self.CODES.get(code, code)}m{text}\033[0m"

    def tag(self, status):
        return self.paint(self.TAGS.get(status, status), status)


def _fmt_bytes(count):
    if count is None:
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(count) < 1000 or unit == "TB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1000.0


def _fmt_num(value):
    if value is None:
        return "-"
    if isinstance(value, int) or (isinstance(value, float) and value.is_integer()
                                  and abs(value) < 1e9):
        return f"{int(value)}"
    if abs(value) >= 1000 or abs(value) < 0.001:
        return f"{value:.3g}"
    return f"{value:.4g}"


def _fmt_share(part, whole):
    if not whole:
        return "-"
    return f"{100.0 * part / whole:.1f} %"


def _top_shares(counter, total, count=4):
    items = sorted(counter.items(), key=lambda item: -item[1])[:count]
    return ", ".join(f"{key} {_fmt_share(value, total)}" for key, value in items)


def print_rule(title, style, char="="):
    print()
    print(style.paint(char * 78, "bold"))
    print(style.paint(title, "bold"))
    print(style.paint(char * 78, "bold"))


def print_analysis(analysis, style, quiet=False, title=None):
    print_rule(title or f"{analysis.label}: {os.path.basename(analysis.path)}", style)
    if analysis.error:
        print(f"  {style.tag(STATUS_FAIL)} {analysis.error}")
        return
    overview = analysis.overview
    fmt = overview["format"]
    period = overview["zeitraum"]
    size = overview["umfang"]
    layers = overview["schichten"]
    hosts = overview["hosts"]
    payload = overview["nutzdaten"]
    tcp = overview["tcp"]
    records = size["records"]
    print(f"Datei         : {fmt['typ']} {fmt['version'] or ''}"
          f"{' (gzip)' if fmt['komprimiert'] else ''}, Aufloesung "
          f"{'/'.join(fmt['zeitaufloesung']) or '-'} (effektiv "
          f"{fmt['effektive_aufloesung']}), Snaplen {fmt['snaplen'] or '-'}, "
          f"{_fmt_bytes(analysis.file_size)}")
    print(f"SHA-256       : {analysis.sha256}")
    print(f"Link-Type     : {', '.join(fmt['link_types']) or 'unbekannt'}"
          f"; abgeschnittene Records: {fmt['abgeschnittene_records']}")
    print(f"Zeitraum      : {period['beginn_utc']} .. {period['ende_utc']} "
          f"({_fmt_num(period['dauer_s'])} s)")
    print(f"Umfang        : {records} Records, {size['ip_pakete']} IP-Pakete, "
          f"{_fmt_bytes(size['bytes_draht'])}, {_fmt_num(size['pakete_pro_s'])} "
          f"Pakete/s, {_fmt_num(size['bit_pro_s'])} bit/s")
    print(f"Schichten     : {_top_shares(layers['sicherung'], records, 3)} | "
          f"{_top_shares(layers['netz'], records)} | "
          f"{_top_shares(layers['transport_pakete'], size['ip_pakete'])}")
    top = ", ".join(f"{entry['adresse']} ({_fmt_num(100 * (entry['anteil'] or 0))} %)"
                    for entry in hosts["top_quellen"][:3])
    print(f"Hosts         : {hosts['quelladressen']} Quellen, "
          f"{hosts['zieladressen']} Ziele; top {top or '-'}")
    services = ", ".join(
        f"{entry['dienst']}{' ' + entry['name'] if entry['name'] else ''} "
        f"{_fmt_num(100 * (entry['anteil'] or 0))} %"
        for entry in overview["dienste"]["top_nach_fluessen"][:5])
    print(f"Dienste       : {services or '-'} (je Fluss)")
    iot = overview["dienste"]["iot_fluesse"]
    print("IoT-Dienste   : " + (", ".join(f"{name} {count} Fluesse"
                                           for name, count in iot.items())
                                 if iot else "keine IoT-typischen Ports"))
    print(f"Nutzdaten     : {_fmt_share(payload['mit_nutzlast'], payload['tcp_udp_pakete'])}"
          f" der TCP/UDP-Pakete mit Nutzlast, {payload['nur_nullbytes']} nur "
          f"Nullbytes" + ("; KEINE Nutzdaten im Mitschnitt (Header-Trace)"
                         if payload["ohne_nutzdaten_im_mitschnitt"] else ""))
    states = ", ".join(f"{state} {entry['anzahl']}"
                       for state, entry in list(tcp["zustaende"].items())[:6])
    print(f"TCP           : {tcp['verbindungen']} Verbindungen, "
          f"{_fmt_num(100 * (tcp['anteil_mit_handshake'] or 0))} % mit Handshake"
          f"{'; ' + states if states else ''}")
    fidelity = analysis.protocol_fidelity
    print(f"Protokolltreue: {_fmt_share(fidelity['fehlerhaft_gesamt'], fidelity['ip_pakete'])}"
          f" fehlerhafte Pakete (Header {_fmt_share(fidelity['fehlerhaft_header'], fidelity['ip_pakete'])}"
          f", Pruefsummen {_fmt_share(fidelity['fehlerhaft_pruefsumme'], fidelity['ip_pakete'])})")

    for group, group_title in GROUPS.items():
        print()
        print(f"  {style.paint(group_title, 'bold')}")
        for check in analysis.checks.values():
            if check.group != group:
                continue
            status = check.status
            if not check.decidable and check.status_override is None:
                detail = f"({check.skipped} uebersprungen)" if check.skipped else ""
            elif group == "artefakt":
                detail = ""
            elif check.key == "E5":
                extra = check.extra
                detail = (f"{extra['belegte_klassen']}/{extra['klassen_gesamt']} "
                          f"Groessenklassen belegt, groesste Klasse "
                          f"{100.0 * extra['groesster_klassenanteil']:.1f} %")
            else:
                detail = (f"{100.0 * check.pass_ratio:6.2f} %  "
                          f"({check.violations}/{check.checked} Verstoesse)")
            print(f"    {check.key:<4} {check.name:<40} {style.tag(status)} {detail}".rstrip())
            if quiet:
                continue
            if check.skipped and check.decidable:
                print(f"           {check.skipped} Records uebersprungen")
            if status in (STATUS_FAIL, STATUS_WARN, STATUS_INFO):
                for example in check.examples.items[:3]:
                    print(f"           -> {example}")
                if check.note:
                    print(f"           {style.paint(check.note, '2')}")
                if group == "artefakt":
                    for key, value in check.extra.items():
                        print(f"           {key}: {value}")

    print()
    print(f"  {style.paint('Merkmale (Ebene 1/2, Bezug IP-Schicht)', 'bold')}")
    for name, value in analysis.features.items():
        meta = FEATURES[name]
        if isinstance(value, Distribution):
            if value.empty:
                print(f"    {name:<22} keine Werte")
                continue
            quantiles = value.quantiles((0.5, 0.95))
            exact = "" if value.exact else " (Stichprobe)"
            print(f"    {name:<22} n={int(value.population):<9} min {_fmt_num(value.minimum)}"
                  f"  p50 {_fmt_num(quantiles.get(0.5))}  p95 {_fmt_num(quantiles.get(0.95))}"
                  f"  max {_fmt_num(value.maximum)}  mittel {_fmt_num(value.mean())}"
                  f" {meta['einheit'] or ''}{exact}")
        else:
            total = sum(value.values())
            print(f"    {name:<22} " + (_top_shares(value, total, 4) if total else "keine Werte"))
    if analysis.sequence:
        sequence = analysis.sequence
        print()
        print(f"  {style.paint('Ablauf (strukturelle Vollstaendigkeit)', 'bold')}: "
              f"{sequence['gefunden']}/{sequence['schritte']} Schritte gefunden, "
              f"Reihenfolge eingehalten: {sequence['reihenfolge_eingehalten']}")
        if not quiet:
            for step in sequence["details"]:
                mark = style.tag(STATUS_OK if step["gefunden"] else STATUS_FAIL)
                print(f"    {mark} {step['name']} ({step['pakete']} Pakete, "
                      f"erstes Auftreten {step['erstes_auftreten_utc']})")


def print_discrepancy(discrepancy, style, quiet=False):
    runs = discrepancy["laeufe"]
    print_rule(f"Werkzeug-Diskrepanz: {len(runs)} Laeufe, Sollwert: "
               f"{discrepancy['sollwert']}", style)
    if len(runs) < 2 and discrepancy["sollwert"] == "keiner":
        print("  Weder Eigenstreuung (mind. zwei Laeufe) noch Sollwert vorhanden.")
        return
    print(f"  {'Merkmal':<24}{'Mass':<9}{'Eigenstreuung med/max':<24}"
          f"{'Sollabw. med/max':<21}{'> Schwelle'}")
    for feature, entry in discrepancy["merkmale"].items():
        spread = entry.get("eigenstreuung")
        deviation = entry.get("sollabweichung")
        if not spread and not deviation:
            continue
        marker = "*" if entry["zugesichert"] else " "
        measures = ("D", "W1_norm") if entry["typ"] == "stetig" else ("JSD",)
        for index, measure in enumerate(measures):
            name = f"{feature} {marker}" if index == 0 else ""
            own = (f"{_fmt_num(spread[measure]['median'])} / {_fmt_num(spread[measure]['max'])}"
                   if spread else "-")
            target = (f"{_fmt_num(deviation[measure]['median'])} / {_fmt_num(deviation[measure]['max'])}"
                      if deviation else "-")
            over = "-"
            if deviation and deviation.get("laeufe_ueber_schwelle"):
                count = deviation["laeufe_ueber_schwelle"][measure]
                over = style.paint(f"{count}/{len(runs)}", STATUS_WARN if count else STATUS_OK)
            print(f"  {name:<24}{measure:<9}{own:<24}{target:<21}{over}")
    print("  (* zugesichertes Merkmal; Schwelle = Maximum der Eigenstreuung)")
    if quiet:
        return
    print()
    print(f"  {style.paint('Skalare Groessen', 'bold')}")
    for name, entry in discrepancy["skalare"].items():
        values = " ".join(f"{label}={_fmt_num(value)}" for label, value in entry["werte"].items())
        line = f"    {name:<28} {values}"
        if "soll" in entry:
            deviations = [value for value in entry["abweichung_relativ"].values()
                          if value is not None]
            line += f" | Soll {_fmt_num(entry['soll'])}"
            if deviations:
                line += f", rel. Abw. median {_fmt_num(statistics.median(deviations))}"
        print(line)
    structure = discrepancy.get("strukturelle_vollstaendigkeit")
    if structure:
        print()
        print(f"  {style.paint('Strukturelle Vollstaendigkeit', 'bold')}")
        for label, entry in structure.items():
            print(f"    {label}: {entry['gefunden']}/{entry['schritte']} Schritte, "
                  f"Reihenfolge eingehalten: {entry['reihenfolge_eingehalten']}")


def print_background(result, style):
    print_rule(f"Ebene 4 gegen Hintergrund: {os.path.basename(result['datei'])}", style)
    links = result["sicherungsschicht"]
    print(f"  Sicherungsschicht einheitlich: {links['einheitlich']} "
          f"({'; '.join(f'{k}: {v}' for k, v in links['link_types'].items())})")
    for label, entry in result["label_integritaet"].items():
        collision = result["adresskollisionen"][label]
        share = result["angriffsanteil"][label]
        window = entry["anteil_eindeutig_im_zeitfenster"] if entry["zeitachsen_ueberlappen"] else None
        print(f"  {label}: Adresskollisionen {collision['kollisionen']} "
              f"({_fmt_num(100 * (collision['anteil'] or 0))} %), eindeutig zuordenbar "
              f"zeitunabhaengig {_fmt_num(100 * (entry['anteil_eindeutig_zeitunabhaengig'] or 0))} %"
              f", im Zeitfenster {'-' if window is None else _fmt_num(100 * window) + ' %'}"
              f"; Angriffsanteil je Paket {_fmt_num(100 * (share['je_paket'] or 0))} %"
              f", je Fluss {_fmt_num(100 * (share['je_fluss'] or 0))} %")
        if entry.get("hinweis"):
            print(f"      {entry['hinweis']}")


def print_messages(messages, status, errors, warnings, style):
    print_rule(f"Bewertung: {status.upper()} ({errors} Fehler, {warnings} Warnungen"
               f" in Laeufen und Aufruf)", style)
    if not messages:
        print("  Keine Auffaelligkeiten.")
        return
    order = {LEVEL_ERROR: 0, LEVEL_WARN: 1, LEVEL_HINT: 2}
    for message in sorted(messages, key=lambda m: order[m["stufe"]]):
        level = {LEVEL_ERROR: STATUS_FAIL, LEVEL_WARN: STATUS_WARN}.get(
            message["stufe"], LEVEL_HINT)
        print(f"  {style.tag(level)}  {message['quelle']:<11} {message['text']}")


# ---------------------------------------------------------------------------
# Kommandozeile
# ---------------------------------------------------------------------------

def _positive_float(text):
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("muss groesser als 0 sein")
    return value


def _nonnegative_float(text):
    value = float(text)
    if value < 0:
        raise argparse.ArgumentTypeError("darf nicht negativ sein")
    return value


def _positive_int(text):
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("muss groesser als 0 sein")
    return value


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pcap_check.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcaps", nargs="+",
                        help="Laeufe des Werkzeugs (pcap/pcapng, auch .gz); "
                             "werden in dieser Reihenfolge L1, L2, ... genannt")
    group = parser.add_argument_group("Werkzeug und Sollwert")
    group.add_argument("--tool", help="Name des Werkzeugs (fuer Bericht und "
                                      "Dateiname)")
    group.add_argument("--reference", metavar="PCAP",
                       help="Sollwert aus einem Mitschnitt (Facette E3: "
                            "Trainingsdaten, E4: Eingangsmitschnitt)")
    group.add_argument("--spec", metavar="JSON",
                       help="Sollwert aus der Konfiguration (Facette E2): "
                            "Verteilungen, Skalare, Reichweite, Ablauf")
    group.add_argument("--assured", metavar="LISTE",
                       help="Reichweite der Zusicherung: kommagetrennte "
                            "Merkmale; ueberschreibt 'reichweite' der Spezifikation")
    group.add_argument("--facet-d", choices=("D1", "D2", "D3"),
                       help="Rueckkopplung des Werkzeugs; steuert die Deutung "
                            "unvollstaendiger TCP-Verbindungen (E4)")
    group.add_argument("--facet-e", choices=("E1", "E2", "E3", "E4"),
                       help="Referenzbedarf; wird gegen die Angaben geprueft")
    group.add_argument("--background", metavar="PCAP",
                       help="Hintergrundverkehr fuer Ebene 4 (Zusammenfuehr"
                            "barkeit, Label-Konflikte, Angriffsanteil)")
    group = parser.add_argument_group("Ausgabe")
    group.add_argument("-o", "--output",
                       help="Ergebnisdatei (.yaml/.yml oder .json); Standard: "
                            "pcap_check_<werkzeug>.yaml im aktuellen Verzeichnis")
    group.add_argument("--json", metavar="PFAD",
                       help="Ergebnis zusaetzlich als JSON schreiben")
    group.add_argument("--no-output", action="store_true",
                       help="keine Ergebnisdatei schreiben")
    group.add_argument("--quiet", action="store_true",
                       help="Beispiele und Zusatzwerte auf der Konsole unterdruecken")
    group.add_argument("--no-color", action="store_true", help="keine Farben")
    group.add_argument("--strict", action="store_true",
                       help="Rueckgabewert 1 auch bei Warnungen")
    group = parser.add_argument_group("Parameter der Auswertung")
    group.add_argument("--bin", type=_positive_float, default=DEFAULT_BIN,
                       metavar="S", help="Zeitintervall fuer Durchsatz und "
                       f"gleichzeitige Fluesse in s (Standard {DEFAULT_BIN})")
    group.add_argument("--flow-timeout", type=_positive_float,
                       default=DEFAULT_FLOW_TIMEOUT, metavar="S",
                       help=f"Leerlauf bis Flussende in s (Standard {DEFAULT_FLOW_TIMEOUT:g})")
    group.add_argument("--edge-margin", type=_nonnegative_float, metavar="S",
                       help="Randfluesse: so nah am Mitschnittanfang/-ende "
                            "gelten fehlender Aufbau/Abbau als abgeschnitten "
                            "(Standard = --flow-timeout; 0 schaltet ab)")
    group.add_argument("--label-window", type=_nonnegative_float,
                       default=DEFAULT_LABEL_WINDOW, metavar="S",
                       help="Zeitfenster fuer Label-Konflikte mit dem "
                            f"Hintergrund in s (Standard {DEFAULT_LABEL_WINDOW:g})")
    group.add_argument("--sample-cap", type=_positive_int, default=DEFAULT_SAMPLE_CAP,
                       metavar="N", help="Werte je Stichprobenmerkmal; darueber "
                       f"Reservoir-Stichprobe (Standard {DEFAULT_SAMPLE_CAP})")
    group.add_argument("--max-packets", type=_positive_int, default=None, metavar="N",
                       help="Analyse nach N Records abbrechen. Nur zur "
                            "Fehlersuche: die Werte stammen dann vom "
                            "Dateianfang und verzerren E4, E5 und alle Verteilungen.")
    group.add_argument("--max-flows", type=_positive_int, default=DEFAULT_FLOW_LIMIT,
                       metavar="N", help="Obergrenze gleichzeitig aktiver "
                       "Fluesse; Ueberlauf wird im Bericht ausgewiesen")
    group.add_argument("--max-hosts", type=_positive_int, default=DEFAULT_HOST_LIMIT,
                       metavar="N", help="Obergrenze verschiedener Adressen je Zaehler")
    group.add_argument("--jobs", type=_positive_int, default=1, metavar="N",
                       help="Laeufe und Referenz in N Prozessen parallel "
                            "auswerten; Ergebnisse identisch zu N=1")
    group.add_argument("--seed", type=int, default=DEFAULT_SEED,
                       help="Startwert fuer Stichproben und Beispielauswahl "
                            "(Reproduzierbarkeit)")
    parser.add_argument("--version", action="version",
                        version=f"pcap_check {__version__}")
    return parser


def _slug(text):
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")
    return slug or "ergebnis"


class _Progress:
    """Fortschritt auf stderr, nur auf einem Terminal."""

    def __init__(self, label, enabled):
        self.label = label
        self.enabled = enabled
        self.started = time.time()

    def __call__(self, count):
        if self.enabled:
            rate = count / max(time.time() - self.started, 1e-6)
            sys.stderr.write(f"\r  {self.label}: {count:,} Records gelesen "
                             f"({rate:,.0f}/s)   ")
            sys.stderr.flush()

    def done(self):
        if self.enabled:
            sys.stderr.write("\r" + " " * 70 + "\r")
            sys.stderr.flush()


def _run_analysis(path, options, label, progress_enabled, **kwargs):
    progress = _Progress(f"{label} {os.path.basename(path)}", progress_enabled)
    try:
        return analyze(path, options, label, progress=progress, **kwargs)
    finally:
        progress.done()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    style = Style(sys.stdout.isatty() and not args.no_color
                  and "NO_COLOR" not in os.environ)
    progress = sys.stderr.isatty()

    spec = None
    if args.spec:
        try:
            spec = load_spec(args.spec)
        except SpecError as error:
            parser.error(f"--spec: {error}")
    assured = None
    if args.assured:
        assured = [name.strip() for name in args.assured.split(",") if name.strip()]
        unknown = [name for name in assured if name not in FEATURES and name not in SCALARS]
        if unknown:
            parser.error(f"--assured: unbekannte Merkmale {unknown}; bekannt sind "
                         f"{list(FEATURES) + list(SCALARS)}")

    options = Options(max_packets=args.max_packets, flow_limit=args.max_flows,
                      seed=args.seed, sample_cap=args.sample_cap,
                      host_limit=args.max_hosts, bin_seconds=args.bin,
                      flow_timeout=args.flow_timeout, edge_margin=args.edge_margin,
                      facet_d=args.facet_d,
                      sequence=(spec or {}).get("ablauf"))
    tool = args.tool or os.path.splitext(os.path.basename(args.pcaps[0]))[0]
    args.tool = tool

    print(style.paint(f"pcap_check {__version__} - Werkzeug: {tool}, "
                      f"{len(args.pcaps)} Lauf/Laeufe", "bold"))

    tasks = [(path, options, f"L{index}", {"collect_flow_keys": bool(args.background)})
             for index, path in enumerate(args.pcaps, start=1)]
    if args.reference:
        # Der Sollwert wird mit derselben Auswertung extrahiert wie die
        # Ausgabe (Konzeption Tabelle 1.3); ohne Ablaufschritte, die gehoeren
        # zum Werkzeug, nicht zur Referenz.
        tasks.append((args.reference, Options(**{**vars(options), "sequence": None}),
                      "Referenz", {}))

    def show(analysis):
        if analysis.label == "Referenz":
            print_analysis(analysis, style, quiet=True, title="Sollwert (Referenz): "
                           f"{os.path.basename(analysis.path)}")
        else:
            print_analysis(analysis, style, args.quiet)

    results = []
    if args.jobs > 1 and len(tasks) > 1:
        with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures = [pool.submit(analyze, path, task_options, label, **extra)
                       for path, task_options, label, extra in tasks]
            for future in futures:
                results.append(future.result())
                show(results[-1])
    else:
        for path, task_options, label, extra in tasks:
            results.append(_run_analysis(path, task_options, label, progress, **extra))
            show(results[-1])
    runs = results[:len(args.pcaps)]
    reference = results[len(args.pcaps)] if args.reference else None

    target = build_target(reference, spec, args.seed, args.sample_cap)
    if assured is None:
        assured = target.assured
    target.assured = assured

    discrepancy = compare_runs(runs, target, assured)
    print_discrepancy(discrepancy, style, args.quiet)

    background_result = None
    background = None
    if args.background:
        watch = set()
        for run in runs:
            watch.update(run.flow_keys or ())
        background_options = Options(**{**vars(options), "sequence": None})
        background = _run_analysis(args.background, background_options,
                                   "Hintergrund", progress, watch=watch)
        if background.error is None:
            background_result = compare_background(runs, background, args.label_window)
            print_background(background_result, style)

    messages = []
    for run in runs:
        messages.extend(analysis_messages(run, "lauf"))
    if reference is not None:
        messages.extend(analysis_messages(reference, "referenz"))
    if background is not None:
        messages.extend(analysis_messages(background, "hintergrund"))
    messages.extend(call_messages(runs, reference, background, target, assured,
                                  args, discrepancy))
    status, errors, warnings, exit_code = overall_status(messages, args.strict)
    print_messages(messages, status, errors, warnings, style)

    if not args.no_output:
        result = build_result(args, ["pcap_check.py"] + argv, runs, reference,
                              background, target, assured, discrepancy,
                              background_result, messages, options)
        output = args.output or f"pcap_check_{_slug(tool)}.yaml"
        written = []
        try:
            write_result(result, output)
            written.append(output)
            if args.json:
                json_path = (args.json if args.json.lower().endswith(".json")
                             else args.json + ".json")
                if os.path.abspath(json_path) != os.path.abspath(output):
                    write_result(result, json_path)
                    written.append(json_path)
        except OSError as error:
            print(f"[fehler] Ergebnis nicht schreibbar: {error}", file=sys.stderr)
            return 1
        print()
        for path in written:
            print(f"Ergebnis geschrieben: {os.path.abspath(path)}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
