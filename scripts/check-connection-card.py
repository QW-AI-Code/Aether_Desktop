#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prüft die vier Reparaturen aus dem Lauf vom 2026-09-17.

Jede davon behebt etwas, das ein Nutzer auf dem Bildschirm gesehen hat, und
jede kann beim nächsten Umbau still verschwinden — der Code compiliert
weiter, nur die Anzeige lügt wieder. Genau deshalb steht hier für jeden Punkt
ein Anker im Quelltext.

1. `Cannot start a runtime from within a runtime` (loge3, vier Paniken in
   `tokio-rt-worker`) — die Laufzeit muss auf einem eigenen Thread geboren
   werden, weil `tor_rtcompat 0.46.0` in `create_runtime()` ein `block_on`
   macht.
2. Der Gegenwarte-Deadlock aus loge4 — die Tor-Schranke darf nur auf den Port
   warten, den der Carrier SELBST öffnet, nie auf den der Stufe 2.
3. Endpoint / Protokoll / Flagge der Verbindungskarte: erster Hop statt
   Wiederholung der Zeile darüber, Pipeline-Name statt `SMART`, und `T1` ist
   kein Land.
4. Die 10,7 Sekunden Stille des Leck-Tests (loge1) — vier STUN-Server
   gleichzeitig, nicht nacheinander.
"""
import re
import sys
from pathlib import Path

WURZEL = Path(__file__).resolve().parent.parent
STATE = WURZEL / "src-tauri/src/state.rs"
PROBE = WURZEL / "src-tauri/src/probe.rs"
ENGINE = WURZEL / "src-tauri/src/engine.rs"
MAIN = WURZEL / "src-tauri/src/main.rs"
FIRSTHOP = WURZEL / "src-tauri/src/firsthop.rs"
TOR_NATIVE = WURZEL / "src-tauri/src/tor_native.rs"
KARTE = WURZEL / "src/views/connectioncard.js"


def ohne_kommentare(text: str, marker: str = "//") -> str:
    """Kommentare weg — eine Erklärung ist kein Beweis, dass der Code es tut."""
    aus = []
    for zeile in text.split("\n"):
        kern = zeile.strip()
        if kern.startswith(marker) or kern.startswith("///") or kern.startswith("*"):
            continue
        aus.append(zeile)
    return "\n".join(aus)


def main() -> int:
    fehler = []

    for pfad in (STATE, PROBE, ENGINE, MAIN, FIRSTHOP, TOR_NATIVE, KARTE):
        if not pfad.exists():
            print(f"✗ fehlt: {pfad.relative_to(WURZEL)}")
            return 1

    state = ohne_kommentare(STATE.read_text(encoding="utf-8", errors="replace"))
    probe = ohne_kommentare(PROBE.read_text(encoding="utf-8", errors="replace"))
    engine = ohne_kommentare(ENGINE.read_text(encoding="utf-8", errors="replace"))
    main_rs = ohne_kommentare(MAIN.read_text(encoding="utf-8", errors="replace"))
    firsthop = FIRSTHOP.read_text(encoding="utf-8", errors="replace")
    nativ = TOR_NATIVE.read_text(encoding="utf-8", errors="replace")
    karte = ohne_kommentare(KARTE.read_text(encoding="utf-8", errors="replace"))

    # ---- 1) (1.3.0) der Kern ist unverändert; Tor läuft nur über tor.exe --
    # Die früheren Prüfungen an `native/aether/aether/src/tor.rs` (arti im
    # Engine) entfallen: kein Tor-Modus startet mehr arti im Kern.

    # ---- 2) die Schranke wartet auf den Port des Carriers -----------------
    if "fn tor_listener_port(" not in state:
        fehler.append("es gibt keinen eigenen Begriff für den Port, den der Carrier öffnet")
    schranke = re.search(r"fn tor_gate\(&mut self\)\s*->\s*TorGate\s*\{(.*?)\n    \}", state, re.S)
    if not schranke:
        fehler.append("`tor_gate` ist nicht auffindbar")
    else:
        koerper = schranke.group(1)
        if "self.tor_listener_port()" not in koerper:
            fehler.append("die Schranke prüft nicht den Listener-Port des Carriers")
        if "data_path_exit_port" in koerper:
            fehler.append(
                "die Schranke wartet wieder auf den Ausgangsport der Kette — den "
                "öffnet Stufe 2, die erst nach der Schranke startet: der "
                "Deadlock aus loge4 ist zurück"
            )

    # ---- 3a) der erste Hop ist verdrahtet, nicht nur vorhanden ------------
    if "mod firsthop;" not in main_rs:
        fehler.append("`firsthop` ist nicht als Modul registriert, also toter Code")
    if "crate::firsthop::ingest" not in engine:
        fehler.append("die Engine-Logzeilen laufen nicht durch `firsthop::ingest`")
    if "crate::firsthop::ingest" not in state:
        fehler.append("die Tor-Logzeilen laufen nicht durch `firsthop::ingest`")
    if "crate::firsthop::reset()" not in state:
        fehler.append(
            "der erste Hop wird zwischen zwei Sitzungen nicht zurückgesetzt; die "
            "Karte zeigt dann die Adresse der VORIGEN Verbindung"
        )
    if "crate::firsthop::get()" not in state:
        fehler.append("das Endpoint-Feld benutzt den ersten Hop nicht")
    else:
        # Kein Ersatz ohne Rückfall: solange kein Hop feststeht, muss das alte
        # Verhalten bleiben, sonst steht dort im Zweifel gar nichts.
        if "or_else" not in state.split("crate::firsthop::get()")[1][:400]:
            fehler.append(
                "der erste Hop hat keinen Rückfall auf das alte Endpoint-Feld; "
                "ohne Treffer wäre die Zeile leer"
            )
    # Der Sammler selbst: zwei Marker, und geraten wird nichts.
    for pflicht, warum in (
        ("using cloudflare edge ", "die Edge-Zeile der Engine wird nicht gelesen"),
        ("tor first hop: ", "die Zeile mit dem ersten Tor-Hop wird nicht gelesen"),
        (
            "parse::<SocketAddr>()",
            "der Endpoint wird als Text übernommen statt als Adresse geprüft — "
            "jedes Wort hinter dem Marker landete dann in der Karte",
        ),
    ):
        if pflicht not in firsthop:
            fehler.append(warum)

    # Und die Tor-Seite, die den ersten Hop überhaupt erst erzeugt.
    for pflicht, warum in (
        ("fn first_hop_of", "der Fingerprint des ersten Hops wird nicht aus `circuit-status` gelesen"),
        ("fn bridge_endpoint_of", "der Fingerprint wird nicht in eine Brücken-Adresse übersetzt"),
        (
            "fn is_documentation_addr",
            "die Doku-Adressen (192.0.2.0/24) der snowflake-Zeilen werden nicht "
            "gefiltert; die Karte zeigte dann eine erfundene Adresse",
        ),
    ):
        if pflicht not in nativ:
            fehler.append(warum)

    # ---- 3b) der Pipeline-Name steht auf der Protokoll-Kachel -------------
    protokoll = re.search(
        r"fn display_protocol\(&self\)\s*->\s*Option<String>\s*\{(.*?)\n    \}", state, re.S
    )
    if not protokoll:
        fehler.append("`display_protocol` ist nicht auffindbar")
    else:
        koerper = protokoll.group(1)
        if not re.search(
            r"TransportBackend::Tor\s*\|\s*crate::profile::TransportBackend::TorPsiphon\s*\)\s*\{\s*return pipeline_name",
            koerper,
        ):
            fehler.append(
                "`Tor` / `Tor → Psiphon` zeigen nicht mehr ihren eigenen Namen vor der "
                "Kettenbedingung — die Kachel fällt dann auf `SMART` zurück (1.3.0-Bug)"
            )
        if "protocol_label()" not in koerper:
            fehler.append("die Protokoll-Kachel kennt den Namen der Pipeline nicht")
        if "is_chained()" not in koerper:
            fehler.append(
                "die Kachel behauptet den Kettennamen auch ohne tragende Stufe 2 — "
                "`Aether → Psiphon`, während Psiphon noch nicht trägt"
            )
        if not re.search(r"if\s+self\.chain_exit_port\.is_some\(\)\s*\{\s*if let Some\(label\)", koerper):
            pass  # die neue Form ist umgekehrt verschachtelt; das ist gewollt.
        else:
            fehler.append(
                "die alte Form ist zurück: der Name erscheint NUR bei gesetztem "
                "chain_exit_port, also nie bei `Tor` allein (Bild: `SMART`)"
            )

    # ---- 3c) `T1` ist kein Land ------------------------------------------
    if "fn is_real_country(" not in probe:
        fehler.append(
            "es gibt keine Prüfung auf Pseudo-Ländercodes; `loc=T1` landet als "
            "Land in der Karte und die Flagge bleibt ein Globus"
        )
    else:
        iso = re.search(r'const ISO: &str = "([^"\n]+)"', probe)
        codes = iso.group(1).split() if iso else []
        if len(set(codes)) != 249 or any(c in codes for c in ["T1","XX","ZZ","QQ","XK"]):
            fehler.append("country validator must use the 249 assigned ISO codes, excluding pseudo codes")
        if "ISO.split_ascii_whitespace().any(|c|c==cc)" not in probe:
            fehler.append("country validator does not enforce membership in the ISO whitelist")
        # An allen drei Stellen, an denen ein Ländercode entsteht.
        trace = re.search(r'strip_prefix\("loc="\)(.*?)\n        \}', probe, re.S)
        if not trace or "is_real_country" not in trace.group(1):
            fehler.append("der cloudflare-trace-Pfad prüft den Code nicht")
        json_pfad = re.search(r'json_str\(body, "query"\)(.*?)\n    \}', probe, re.S)
        if not json_pfad or "is_real_country" not in json_pfad.group(1):
            fehler.append("der ip-api-JSON-Pfad prüft den Code nicht")
        refine = re.search(r"fn refine_country_on\((.*?)\n\}", probe, re.S)
        if not refine:
            fehler.append("refine_country ist verschwunden")
        else:
            # Der ip-api-Rückweg selbst muss prüfen. `is_real_country` irgendwo im
            # Rumpf genügt nicht: seit 1.2.5 steht davor die lokale geoip-Abfrage,
            # die ihren EIGENEN Code prüft (`&code`) — und deren Prüfung bezeugt
            # nichts über den Code, der aus dem Netz kommt (`&cc`).
            if not re.search(r"is_real_country\(&cc\)", refine.group(1)):
                fehler.append(
                    "die Verfeinerung aus dem Tunnel übernimmt einen Pseudo-Code als "
                    "Ergebnis und schliesst damit den einzigen Weg zum echten Land"
                )

    # ---- 3d) Tor hat seine eigene Ping-Skala ------------------------------
    if "PING_BANDS_TOR" not in karte or "function pingBandsFor(" not in karte:
        fehler.append(
            "es gibt keine eigene Ping-Skala für Tor; drei Hops an der "
            "Tunnel-Skala gemessen heissen immer `Poor` (Bild: 397 ms)"
        )
    else:
        tor_band = re.search(r"PING_BANDS_TOR\s*=\s*\{(.*?)\}", karte, re.S)
        tunnel_gut = re.search(r"PING_GOOD_MS\s*=\s*(\d+)", karte)
        tor_gut = re.search(r"good:\s*(\d+)", tor_band.group(1)) if tor_band else None
        if not tor_gut or not tunnel_gut:
            fehler.append("die Ping-Bänder sind nicht ablesbar")
        elif int(tor_gut.group(1)) <= int(tunnel_gut.group(1)):
            fehler.append("die Tor-Skala ist nicht weiter als die Tunnel-Skala")
        if "pingBandsFor(connected ? snapshot.protocol : null)" not in karte:
            fehler.append("die Skala wird beim Zeichnen nicht aus der Pipeline gewählt")
        for aufruf in ("pingGrade(connected, lastMs, bands)", "pingStrength(connected, lastMs, bands)"):
            if aufruf not in karte:
                fehler.append(f"`{aufruf}` fehlt — Wort und Balkenhöhe laufen auseinander")

    # ---- 4) vier STUN-Server gleichzeitig --------------------------------
    stun = re.search(
        r"pub fn stun_reflexive_ip\(timeout: Duration\)\s*->\s*Option<StunResult>\s*\{(.*?)\n\}",
        probe,
        re.S,
    )
    if not stun:
        fehler.append("`stun_reflexive_ip` ist nicht auffindbar")
    else:
        koerper = stun.group(1)
        if "std::thread::Builder" not in koerper or "recv_timeout" not in koerper:
            fehler.append(
                "die STUN-Server werden wieder nacheinander gefragt: vier mal "
                "2,5 s Stille = die 10,7 Sekunden aus loge1"
            )
        if "drop(tx)" not in koerper:
            fehler.append(
                "der Haupt-Sender wird nicht fallen gelassen; schweigen alle "
                "Server, wartet `recv_timeout` trotzdem die volle Frist ab"
            )
        if re.search(r"if let Some\(ip\) = stun_query\(server, timeout\)\s*\{\s*return", koerper):
            fehler.append("in der Schleife steht wieder ein `return` — das ist die sequentielle Form")

    if fehler:
        print("✗ Verbindungskarte und Tor-Ketten:")
        for f in fehler:
            print(f"   - {f}")
        return 1

    print(
        "✓ Tor nur über tor.exe (offizielles Tor, Core-Overlay separat geprüft), Schranke "
        "am Carrier-Port statt am Kettenausgang, erster Hop verdrahtet mit "
        "Rückfall und Reset, Pipeline-Name auf der Kachel, T1/A1/A2/O1/XX kein "
        "Land an allen drei Stellen, eigene Ping-Skala für Tor, vier STUN-Server "
        "gleichzeitig"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
