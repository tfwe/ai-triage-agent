#!/usr/bin/env python3
"""Build the anonymized real-vendor-export corpus from pinned public sources.

Reads the raw source files listed in ``--raw-dir`` (fetched once by hand from
the public sources recorded in ``data/real-vendor/provenance.json``), runs
the anonymization pass described there, and writes the corpus tree that
``scripts/run_real_vendor_pipeline.py`` stages into ``data/raw-real/``.

Raw sources are never committed or copied into the corpus; only their sha256
digests are recorded. All host identifiers (IPs, IPv6, hostnames, domains,
MACs, non-standard user names) are replaced with documentation-range values
before anything is written.

Usage::

    .venv/bin/python scripts/build_real_vendor_corpus.py --raw-dir <dir> \
        --zeek-logs-dir <dir> --out data/real-vendor

``--raw-dir`` must contain::

    pcaps/            (optional; only referenced for provenance hashes)
    evtx/*.evtx       Windows event log exports from EVTX-ATTACK-SAMPLES
    Linux_2k.log      logpai/loghub Linux auth log
    OpenSSH_2k.log    logpai/loghub OpenSSH auth log
    suri/eve.json     Suricata alert-only EVE JSON from WRCCDC 2018

``--zeek-logs-dir`` must contain one directory per capture with Zeek JSON
logs (``*.log`` lines of JSON), as produced by Zeek 8.2.2 in JSON mode.

Requires the ``evtx`` pip package (PyO3 binding) when ``evtx/`` inputs are
present: converts each EVTX to Windows Event XML wrapped in a single
``<Events>`` root element.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sys
from collections import Counter, defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Fixed hostname map (real identifier -> corpus alias). Applied before the
# domain pass so compound names like PC01.example.corp collapse whole.
HOSTNAME_MAP = {
    "IEWIN7": "HOST-WIN-A",
    "MSEDGEWIN10": "HOST-WIN-B",
    "PC01.EXAMPLE.CORP": "HOST-WIN-C",
    "PC01": "HOST-WIN-C",
    "LABSZ": "HOST-LNX-A",
    "COMBO": "HOST-LNX-B",
}

# Only the zeek log files the parsers actually read (parsers/schemas.py
# SCHEMA_MAP). Anything else Zeek writes is not staged.
ZEEK_SCHEMA_FILES = {
    "conn", "dns", "http", "ssl", "files", "dhcp", "x509", "pe", "ocsp",
}

# Zeek captures staged into the corpus: <pcap file name> -> <corpus slug>.
ZEEK_CAPTURES = {
    "C2_Foudre_Backdoor_DGA.pcapng": "c2-foudre-dga",
    "cmds over dns txt queries and reponses.pcap": "c2-dns-txt",
    "rdp_tunneling_meterpreter_portfwd.pcapng": "c2-rdp-tunneling-meterpreter",
    "LM_rdp_sharprdp.pcapng": "lm-rdp-sharprdp",
    "LM_psexec_smb_dcerpc_epm_svcctl.pcapng": "lm-psexec-svcctl",
    "LM_smbexec_smb_dcerpc_svcctl_epm.pcapng": "lm-smbexec-svcctl",
    "LM_WMI_ProcessCallCreate.pcapng": "lm-wmi-proccall",
    "LM_dcom_mmc20.application_dcerpc.pcapng": "lm-dcom-mmc20",
    "CA_kerbrute_passwordspray_kerberos_AS-REQ.pcapng": "ca-kerbrute-spray",
    "DCSync_krbtgt_dcerpc_smb.pcapng": "ca-dcsync",
    "zerologon_mimikatz_ntlm_privacy_scan_and_exploit_encrypted.pcapng": "lm-zerologon",
    "discovery_scan_dcerpc_endpoint_mapper.pcapng": "disc-dcerpc-scan",
    "Discovery_privgroups_domain_admins_samr_lookupnames_req.pcapng": "disc-samr-privgroups",
}

# Windows event exports: <evtx file name> -> <hostname alias>/<file name>.
WINDOWS_EXPORTS = {
    "discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx":
        "HOST-WIN-A/discovery-appcmd.xml",
    "privesc_unquoted_svc_sysmon_1_11.evtx":
        "HOST-WIN-B/privesc-unquoted-svc.xml",
    "LM_5145_Remote_FileCopy.evtx":
        "HOST-WIN-C/lm-5145-remote-filecopy.xml",
}

# Linux auth logs: <file> -> <hostname alias>/syslog.log  (top level: the
# linux parser derives the hostname from the first path component)
LINUX_LOGS = {
    "OpenSSH_2k.log": "HOST-LNX-A/syslog.log",
    "Linux_2k.log": "HOST-LNX-B/syslog.log",
}

# IDS slice: top-N (src, dst, signature) triples by alert count, capped.
IDS_TRIPLE_TOP = 8
IDS_TRIPLE_CAP = 1000

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])("
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"                      # 1:2:3:4:5:6:7:8
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"                                  # x:x:x:x:x:x:x:
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"                  # x:x:x:x:x:x::y
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"         # ...::y:y
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"                                  # ::y:...
    r"|::"                                                           # bare ::
    r")(?![0-9A-Fa-f:.])",
    re.IGNORECASE,
)
MAC_RE = re.compile(r"(?<![\w:])([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![\w:])")
DOMAIN_RE = re.compile(
    r"(?<![a-zA-Z0-9-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:pl|com|net|org|local|corp|io|info|biz|ru|cn|pw|top|xyz|google|gov|"
    r"edu|uk|de|fr|ch|arpa)"
    r")(?![a-zA-Z0-9-])",
    re.IGNORECASE,
)


def _hex(token: str, n: int = 6) -> str:
    return hashlib.md5(token.encode()).hexdigest()[:n]


def _is_ipv6(token: str) -> bool:
    """True only for tokens ipaddress accepts as IPv6 (rejects MAC-shaped
    false positives and dotted IPv4)."""
    try:
        ipaddress.IPv6Address(token)
    except ValueError:
        return False
    return True


# Non-standard usernames observed in HOST-LNX-* syslog: -> user-<4hex> alias
# (IEUser keeps its original fixed alias).
USERNAME_MAP = {
    "IEUser": "user-1e4f",
    **{name: f"user-{_hex(name, 4)}" for name in (
        "fztu", "cyrus", "news", "matlab", "inspur", "oracle", "support",
    )},
}


def _ip_family(addr: str) -> str:
    """Return 'private' | 'public' | 'reserved' for a valid IPv4, '' otherwise.

    Multicast/reserved/unspecified IPv4 land in 'reserved' so they are never
    handed public documentation aliases.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return ""
    if isinstance(ip, ipaddress.IPv6Address):
        return ""
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "private"
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "reserved"
    return "public"


class Anonymizer:
    """Deterministic token remapping built from the full corpus text."""

    def __init__(self) -> None:
        self.ipv4_map: dict[str, str] = {}
        self.ipv6_map: dict[str, str] = {}
        self.mac_map: dict[str, str] = {}
        self.domain_map: dict[str, str] = {}

    def scan(self, text: str) -> None:
        for m in IPV4_RE.finditer(text):
            addr = m.group(1)
            if addr in self.ipv4_map or not _ip_family(addr):
                continue
            self.ipv4_map[addr] = ""
        for m in IPV6_RE.finditer(text):
            addr = m.group(1).lower()
            if addr in self.ipv6_map or not _is_ipv6(addr):
                continue
            self.ipv6_map[addr] = ""
        for m in MAC_RE.finditer(text):
            mac = m.group(0).lower()
            self.mac_map.setdefault(mac, "")
        for m in DOMAIN_RE.finditer(text):
            self.domain_map.setdefault(m.group(1).lower(), "")

    def assign(self) -> None:
        """Fix the deterministic alias tables (sorted for reproducibility)."""
        # Private + reserved hosts (multicast/reserved/unspecified must never
        # reach the public pool): RFC 6598 shared address space (100.64.0.0/10)
        # has room for every unique address; public hosts fit RFC 5737 TEST-NET-3.
        private_base = int(ipaddress.ip_address("100.64.0.0"))
        public_base = int(ipaddress.ip_address("203.0.113.0"))
        addrs = sorted(
            (a for a in self.ipv4_map
             if _ip_family(a) in ("private", "reserved")),
            key=lambda a: tuple(int(p) for p in a.split(".")),
        )
        if len(addrs) > 2 ** 22:  # 100.64.0.0/10 capacity
            sys.exit(f"private alias table overflow: {len(addrs)} hosts")
        for i, addr in enumerate(addrs, start=1):
            self.ipv4_map[addr] = str(ipaddress.ip_address(private_base + i))
        addrs = sorted(
            (a for a in self.ipv4_map if _ip_family(a) == "public"),
            key=lambda a: tuple(int(p) for p in a.split(".")),
        )
        for i, addr in enumerate(addrs, start=1):
            if i > 254:
                sys.exit(f"public alias table overflow: {len(addrs)} hosts")
            self.ipv4_map[addr] = str(ipaddress.ip_address(public_base + i))
        for addr in sorted(self.ipv6_map):
            self.ipv6_map[addr] = f"2001:db8::{_hex(addr, 4)}"
        for mac in sorted(self.mac_map):
            h = _hex(mac, 8)
            self.mac_map[mac] = (
                f"0c:6a:{h[0:2]}:{h[2:4]}:{h[4:6]}:{h[6:8]}"
            )
        for dom in sorted(self.domain_map):
            self.domain_map[dom] = f"dom-{_hex(dom)}.example"

    def assert_no_collisions(self) -> None:
        """Exit non-zero if two distinct source tokens share an alias."""
        for name, mapping in (
            ("ipv4", self.ipv4_map),
            ("ipv6", self.ipv6_map),
            ("mac", self.mac_map),
            ("domain", self.domain_map),
        ):
            vals = list(mapping.values())
            if len(set(vals)) != len(vals):
                dupes = sorted(v for v, c in Counter(vals).items() if c > 1)
                sys.exit(f"alias collision in {name} map: {dupes}")

    def apply(self, text: str) -> str:
        def sub_ip4(m: re.Match) -> str:
            return self.ipv4_map.get(m.group(1), m.group(1))

        def sub_ip6(m: re.Match) -> str:
            addr = m.group(1).lower()
            if not _is_ipv6(addr):
                return m.group(0)  # e.g. MAC-shaped candidate; MAC pass owns it
            if addr not in self.ipv6_map:
                sys.exit(f"unmappable IPv6 at write time: {addr}")
            return self.ipv6_map[addr]

        def sub_mac(m: re.Match) -> str:
            return self.mac_map.get(m.group(0).lower(), m.group(0))

        def sub_dom(m: re.Match) -> str:
            return self.domain_map.get(m.group(1).lower(), m.group(0))

        text = IPV6_RE.sub(sub_ip6, text)
        text = IPV4_RE.sub(sub_ip4, text)
        for name, alias in sorted(HOSTNAME_MAP.items(), key=lambda kv: -len(kv[0])):
            text = re.sub(
                rf"(?<![\w-]){re.escape(name)}(?![\w-])", alias, text,
                flags=re.IGNORECASE,
            )
        text = DOMAIN_RE.sub(sub_dom, text)
        text = MAC_RE.sub(sub_mac, text)
        for name, alias in USERNAME_MAP.items():
            text = re.sub(rf"(?<![\w-]){re.escape(name)}(?![\w-])", alias, text)
        return text

    def summary(self) -> dict:
        return {
            "ipv4_mapped": len(self.ipv4_map),
            "ipv6_mapped": len(self.ipv6_map),
            "macs_mapped": len(self.mac_map),
            "domains_mapped": len(self.domain_map),
        }


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_inputs(raw_dir: str, zeek_logs_dir: str) -> None:
    """Exit non-zero unless every required raw source is present.

    Runs BEFORE any destructive action on --out: all 19 provenance sources
    (2 Linux logs, 3 EVTX exports, 13 pcaps, suri/eve.json), one Zeek capture
    dir per ZEEK_CAPTURES entry, and an importable ``evtx`` package.
    """
    missing = []
    for name in LINUX_LOGS:
        p = os.path.join(raw_dir, name)
        if not os.path.isfile(p):
            missing.append(p)
    for name in WINDOWS_EXPORTS:
        p = os.path.join(raw_dir, "evtx", name)
        if not os.path.isfile(p):
            missing.append(p)
    for pcap_name in ZEEK_CAPTURES:
        p = os.path.join(raw_dir, "pcaps", pcap_name)
        if not os.path.isfile(p):
            missing.append(p)
    eve_path = os.path.join(raw_dir, "suri", "eve.json")
    if not os.path.isfile(eve_path):
        missing.append(eve_path)
    if missing:
        sys.exit("missing required raw sources:\n  " + "\n  ".join(missing))

    for pcap_name in ZEEK_CAPTURES:
        stem = pcap_name.rsplit(".", 1)[0]
        if not os.path.isdir(os.path.join(zeek_logs_dir, stem, "json")) \
                and not os.path.isdir(os.path.join(zeek_logs_dir, stem)):
            sys.exit(f"missing zeek capture dir for {stem}: "
                     f"{os.path.join(zeek_logs_dir, stem)}")

    try:
        from evtx import PyEvtxParser  # noqa: F401
    except ImportError as exc:
        sys.exit(f"the 'evtx' pip package is required: {exc}")

    print(f"inputs validated: {len(LINUX_LOGS) + len(WINDOWS_EXPORTS)} + "
          f"{len(ZEEK_CAPTURES)} + 1 provenance sources, "
          f"{len(ZEEK_CAPTURES)} zeek capture dirs, evtx importable")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw-dir", required=True, help="directory with raw sources")
    ap.add_argument("--zeek-logs-dir", required=True,
                    help="directory with per-capture Zeek JSON logs")
    ap.add_argument("--out", default=os.path.join(REPO_ROOT, "data", "real-vendor"))
    args = ap.parse_args()

    # Validate everything first: --out is only touched after this succeeds.
    validate_inputs(args.raw_dir, args.zeek_logs_dir)

    # Build into a temp dir and swap on success so a failed run never leaves
    # a half-written corpus at --out.
    out = args.out
    tmp_out = out + f".tmp-{os.getpid()}"
    if os.path.exists(tmp_out):
        shutil.rmtree(tmp_out)
    os.makedirs(tmp_out)

    anon = Anonymizer()

    # Pass 1 over every text input builds the deterministic alias tables.
    all_text = []
    # Linux auth logs: read before the scan pass so aliases cover them.
    for name in LINUX_LOGS:
        p = os.path.join(args.raw_dir, name)
        if os.path.exists(p):
            all_text.append(open(p, encoding="utf-8", errors="replace").read())
    # EVTX records must be converted before scan; do the conversion to a
    # staging buffer first, then scan, then write anonymized.
    evtx_xml: dict[str, str] = {}
    try:
        from evtx import PyEvtxParser
    except ImportError as exc:
        sys.exit(f"the 'evtx' pip package is required: {exc}")
    for name in WINDOWS_EXPORTS:
        p = os.path.join(args.raw_dir, "evtx", name)
        if not os.path.exists(p):
            continue
        buf = ["<Events>\n"]
        for rec in PyEvtxParser(p).records():
            data = rec["data"].strip().replace("\r\n", "\n")
            # each record carries its own XML declaration; strip it
            if data.startswith("<?xml"):
                data = data.split("?>", 1)[1].strip()
            buf.append(data)
            buf.append("\n")
        buf.append("</Events>\n")
        evtx_xml[name] = "".join(buf)
        all_text.append(evtx_xml[name])

    zeek_texts: dict[tuple[str, str], str] = {}
    for pcap_name, slug in ZEEK_CAPTURES.items():
        stem = pcap_name.rsplit(".", 1)[0]
        capture_dir = os.path.join(args.zeek_logs_dir, stem, "json")
        if not os.path.isdir(capture_dir):
            capture_dir = os.path.join(args.zeek_logs_dir, stem)
        if not os.path.isdir(capture_dir):
            sys.exit(f"missing zeek logs for capture {slug}: {capture_dir}")
        for fname in sorted(os.listdir(capture_dir)):
            stem, ext = os.path.splitext(fname)
            if ext != ".log" or stem not in ZEEK_SCHEMA_FILES:
                continue
            text = open(os.path.join(capture_dir, fname), encoding="utf-8").read()
            zeek_texts[(slug, stem)] = text
            all_text.append(text)

    eve_path = os.path.join(args.raw_dir, "suri", "eve.json")
    ids_events: list[dict] = []
    if os.path.exists(eve_path):
        with open(eve_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "alert":
                    ids_events.append(event)
        all_text.append(
            "\n".join(
                f"{e.get('src_ip')}->{e.get('dest_ip')}"
                f" {(e.get('alert') or {}).get('signature', '')}"
                for e in ids_events
            )
        )

    for text in all_text:
        anon.scan(text)
    anon.assign()
    anon.assert_no_collisions()
    print("alias table:", anon.summary())

    # Windows
    for name, xml in evtx_xml.items():
        rel = WINDOWS_EXPORTS[name]
        dest_path = os.path.join(tmp_out, "windows", rel)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        open(dest_path, "w", encoding="utf-8").write(anon.apply(xml))
        print(f"  windows {rel}: {xml.count('<Event ')} events")

    # Linux
    for name, rel in LINUX_LOGS.items():
        src = os.path.join(args.raw_dir, name)
        if not os.path.exists(src):
            continue
        lines = [line.rstrip("\r") for line in
                 open(src, encoding="utf-8", errors="replace").read().splitlines()
                 if line.strip()]
        dest_path = os.path.join(tmp_out, rel)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        open(dest_path, "w", encoding="utf-8").write(
            "\n".join(anon.apply(line) for line in lines) + "\n"
        )
        print(f"  linux {rel}: {len(lines)} lines")

    # Zeek
    # Zeek UIDs collide across different captures (the sample pcaps share
    # overlapping lab traffic), so every conn-reference is namespaced with
    # the capture slug before it is written. Without this the loader would
    # merge unrelated sessions.
    UID_FIELDS = {
        "conn": ["uid"], "dns": ["uid"], "http": ["uid"], "ssl": ["uid"],
        "pe": ["uid"], "files": ["conn_uids"], "dhcp": ["uids"],
    }
    for (slug, stem), text in sorted(zeek_texts.items()):
        dest_path = os.path.join(tmp_out, "zeek", slug, f"{stem}.json")
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        out_lines = []
        for line in text.splitlines():
            line = anon.apply(line)
            fields = UID_FIELDS.get(stem)
            if fields:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    out_lines.append(line)
                    continue
                changed = False
                for field in fields:
                    val = rec.get(field)
                    if isinstance(val, str):
                        rec[field] = f"{slug}:{val}"
                        changed = True
                    elif isinstance(val, list):
                        rec[field] = [f"{slug}:{v}" for v in val]
                        changed = True
                if changed:
                    line = json.dumps(rec, separators=(",", ":"))
            out_lines.append(line)
        open(dest_path, "w", encoding="utf-8").write("\n".join(out_lines) + "\n")
    print(f"  zeek: {len(zeek_texts)} log files across "
          f"{len({s for s, _ in zeek_texts})} captures")

    # IDS
    if ids_events:
        triples = Counter()
        first_seen = defaultdict(list)
        for event in ids_events:
            alert = event.get("alert", {})
            key = (event.get("src_ip"), event.get("dest_ip"),
                   alert.get("signature_id"))
            triples[key] += 1
            first_seen[key].append(event)
        top = [k for k, _ in triples.most_common(IDS_TRIPLE_TOP)]
        lines = []
        for key in top:
            for event in first_seen[key][: IDS_TRIPLE_CAP]:
                alert = event["alert"]
                m = re.match(
                    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)",
                    str(event.get("timestamp", "")),
                )
                fast_ts = (
                    f"{m.group(2)}/{m.group(3)}-{m.group(4)}:{m.group(5)}:"
                    f"{m.group(6)}.{m.group(7)[:6]}" if m else str(event.get("timestamp"))
                )
                cls = alert.get("category")
                cls_part = f"[Classification: {cls}] " if cls else ""
                lines.append(
                    f"{fast_ts}  [**] [1:{alert['signature_id']}:{alert.get('rev', 1)}] "
                    f"{alert['signature']} [**] {cls_part}"
                    f"[Priority: {alert.get('priority', 3)}] "
                    f"{{{(event.get('proto') or 'IP').upper()}}} "
                    f"{event['src_ip']}:{event.get('src_port')} "
                    f"-> {event['dest_ip']}:{event.get('dest_port')}"
                )
        rendered = "\n".join(lines) + "\n"
        dest_path = os.path.join(tmp_out, "ids", "IDS-WRCCDC-2018", "fast.log")
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        open(dest_path, "w", encoding="utf-8").write(anon.apply(rendered))
        print(f"  ids: {len(lines)} alert lines "
              f"(of {len(ids_events)} eve alerts; top {len(top)} triples, "
              f"capped {IDS_TRIPLE_CAP})")

    # Provenance sidecar
    prov = {
        "sources": [],
        "anonymization": anon.summary(),
        "outputs": {},
    }
    for name in list(LINUX_LOGS):
        p = os.path.join(args.raw_dir, name)
        if os.path.exists(p):
            prov["sources"].append({"file": name, "sha256": sha256(p)})
    for name in WINDOWS_EXPORTS:
        p = os.path.join(args.raw_dir, "evtx", name)
        if os.path.exists(p):
            prov["sources"].append({"file": f"evtx/{name}", "sha256": sha256(p)})
    for pcap_name in ZEEK_CAPTURES:
        p = os.path.join(args.raw_dir, "pcaps", pcap_name)
        if os.path.exists(p):
            prov["sources"].append({"file": f"pcaps/{pcap_name}",
                                    "sha256": sha256(p)})
    if os.path.exists(eve_path):
        prov["sources"].append({"file": "suri/eve.json", "sha256": sha256(eve_path)})
    with open(os.path.join(tmp_out, "provenance.json"), "w") as w:
        json.dump(prov, w, indent=2)

    # Atomic-ish swap: only replace the real --out once the whole tree
    # (including provenance.json) was written successfully.
    if os.path.exists(out):
        shutil.rmtree(out)
    os.rename(tmp_out, out)
    print(f"corpus written to {out}")


if __name__ == "__main__":
    main()
