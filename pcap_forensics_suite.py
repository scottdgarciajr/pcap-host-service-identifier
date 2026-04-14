"""
pcap_forensics_suite.py
=======================
Integrated PCAP Network Forensic Analysis Suite
Combines:
  1. PCAP Analyzer      — temporal, network, service, ransomware analysis
  2. Service Visualizer — interactive host/service/file explorer
  3. Coverage Gap Report — CSV export of uncovered time windows

All paths are configurable via GUI. No hard-coded paths.
"""

# ═══════════════════════════════════════════════════════════════════
#  STDLIB IMPORTS
# ═══════════════════════════════════════════════════════════════════
import csv
import json
import os
import socket
import time
import traceback
import threading
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone

# ═══════════════════════════════════════════════════════════════════
#  GUI IMPORTS
# ═══════════════════════════════════════════════════════════════════
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext

# ═══════════════════════════════════════════════════════════════════
#  SCAPY (optional at import time; checked before analysis)
# ═══════════════════════════════════════════════════════════════════
try:
    from scapy.all import PcapReader, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════
#  RANSOMWARE PORT SIGNATURES
# ═══════════════════════════════════════════════════════════════════
RANSOMWARE_PORT_SIGNATURES = {
    445:  "SMB — primary ransomware lateral-movement vector (WannaCry/NotPetya/Ryuk)",
    139:  "NetBIOS Session — legacy SMB, used in SMB relay and lateral movement",
    137:  "NetBIOS Name Service — network reconnaissance / NBNS poisoning",
    138:  "NetBIOS Datagram — broadcast-based service discovery abuse",
    3389: "RDP — common initial-access vector and operator remote-control channel",
    5900: "VNC — remote desktop, often abused post-compromise for persistence",
    4444: "Metasploit/msfvenom default reverse-shell listener port",
    4445: "Common alternate reverse-shell / C2 beacon port",
    5555: "Common RAT / Android ADB / C2 beacon port",
    1080: "SOCKS proxy — frequently used to tunnel C2 or exfil traffic",
    8080: "HTTP alternate — common C2 beaconing and web-shell communication",
    8443: "HTTPS alternate — encrypted C2 beaconing",
    88:   "Kerberos — targeted by Kerberoasting / ticket-forging attacks",
    389:  "LDAP — AD enumeration; abused by ransomware pre-deployment recon",
    636:  "LDAPS — encrypted LDAP; same enumeration risk as 389",
    135:  "MSRPC / EPMAP — used in DCOM lateral movement (PsExec, WMI)",
    21:   "FTP control — plaintext exfiltration staging channel",
    20:   "FTP data — plaintext data transfer for exfil",
    22:   "SSH/SFTP — encrypted exfil; also used for encrypted C2 tunnelling",
    990:  "FTPS — encrypted FTP exfiltration",
    2049: "NFS — network file system; abused for mass file access / exfil",
    25:   "SMTP — phishing delivery vector; also exfil via email attachment",
    587:  "SMTP submission — outbound mail, potential exfil or spam relay",
    143:  "IMAP — mailbox access; watch for unusual volume indicating harvesting",
    993:  "IMAPS — encrypted IMAP; same concern as 143",
    110:  "POP3 — mailbox access; credential harvesting",
    995:  "POP3S — encrypted POP3",
    9001: "Tor ORPort — Tor relay; used to anonymise C2 communication",
    9050: "Tor SOCKS proxy — local Tor client proxy port",
    9150: "Tor Browser SOCKS — Tor Browser proxy port",
    50050:"Cobalt Strike default Team Server port",
    2222: "Cobalt Strike / common SSH alternate / RAT listener",
    6667: "IRC — historically used for botnet C2 channels",
    6697: "IRC over TLS — encrypted IRC C2",
    1433: "MS SQL Server — targeted for data exfil and SQL injection staging",
    3306: "MySQL — targeted for credential theft and database exfil",
    5432: "PostgreSQL — database exfiltration target",
    27017:"MongoDB — unauthenticated instances targeted for ransom",
    23:   "Telnet — plaintext remote access; indicator of legacy/compromised system",
    5985: "WinRM HTTP — Windows Remote Management, used in lateral movement",
    5986: "WinRM HTTPS — encrypted WinRM lateral movement",
    47001:"WinRM alternate — another WinRM port used by offensive tools",
}

RANSOMWARE_PORT_SEVERITY = {
    445: "HIGH", 139: "HIGH", 3389: "HIGH", 88: "HIGH",
    135: "HIGH", 389: "HIGH", 22: "HIGH", 25: "HIGH",
    21: "HIGH", 4444: "HIGH", 50050: "HIGH",
    137: "MEDIUM", 138: "MEDIUM", 5900: "MEDIUM", 1080: "MEDIUM",
    4445: "MEDIUM", 5555: "MEDIUM", 8080: "MEDIUM", 8443: "MEDIUM",
    636: "MEDIUM", 143: "MEDIUM", 993: "MEDIUM", 587: "MEDIUM",
    1433: "MEDIUM", 3306: "MEDIUM", 5432: "MEDIUM", 27017: "MEDIUM",
    5985: "MEDIUM", 5986: "MEDIUM", 2222: "MEDIUM", 6667: "MEDIUM",
    9001: "MEDIUM", 9050: "MEDIUM", 9150: "MEDIUM",
    20: "LOW", 110: "LOW", 995: "LOW", 990: "LOW", 2049: "LOW",
    6697: "LOW", 47001: "LOW", 23: "LOW",
}

# ═══════════════════════════════════════════════════════════════════
#  DEFAULT KNOWN SYSTEMS — editable via GUI
# ═══════════════════════════════════════════════════════════════════
DEFAULT_KNOWN_SYSTEMS = {
    "192.168.100.10": {
        "label": "DC1", "department": "Domain Controller",
        "role": "Primary Active Directory — DNS / DHCP / Kerberos / NTP / LDAP / SMB",
        "expected_services": {53, 67, 88, 123, 135, 137, 138, 139, 389, 445},
    },
    "192.168.100.11": {
        "label": "DC2", "department": "Domain Controller",
        "role": "Secondary DC — file services / NetBIOS / SMB",
        "expected_services": {80, 123, 137, 138, 139, 143, 445},
    },
    "192.168.100.16": {
        "label": "Mayor2_2", "department": "Mayor's Office",
        "role": "Mayor workstation — DHCP client / NetBIOS participant",
        "expected_services": {68, 123, 137, 138},
    },
    "192.168.100.17": {
        "label": "Mayor2_4", "department": "Mayor's Office",
        "role": "Mayor workstation — DHCP client / NetBIOS participant",
        "expected_services": {68, 123, 137, 138},
    },
    "192.168.100.18": {
        "label": "Mayor_WS3", "department": "Mayor's Office",
        "role": "Mayor workstation — DHCP client / NetBIOS participant",
        "expected_services": {68, 123, 137, 138},
    },
    "192.168.100.20": {
        "label": "Mayor_WS4", "department": "Mayor's Office",
        "role": "Mayor workstation — DHCP client / NetBIOS participant",
        "expected_services": {68, 123, 137, 138},
    },
    "192.168.100.13": {
        "label": "TaxOffice_1", "department": "Tax Office",
        "role": "Tax workstation — DHCP client / NetBIOS participant",
        "expected_services": {68, 123, 137, 138, 139},
    },
    "192.168.100.14": {
        "label": "TaxOffice_2", "department": "Tax Office",
        "role": "Tax workstation — DHCP client / NetBIOS participant",
        "expected_services": {68, 123, 137, 138, 139},
    },
    "192.168.100.21": {
        "label": "TaxOffice_4", "department": "Tax Office",
        "role": "Tax workstation — DHCP client / NetBIOS participant",
        "expected_services": {68, 123, 137, 138, 139},
    },
    "192.168.100.19": {
        "label": "Police1_1", "department": "Police Department",
        "role": "Police workstation — HTTPS client only",
        "expected_services": {443},
    },
    "192.168.100.12": {
        "label": "IT_2", "department": "IT",
        "role": "IT workstation — internal HTTP management / helpdesk",
        "expected_services": {80},
    },
    "192.168.100.1": {
        "label": "WebServer / Gateway", "department": "Web Server",
        "role": "Public web server / default gateway — DNS, HTTP, HTTPS",
        "expected_services": {53, 80, 443},
    },
    "192.168.100.255": {
        "label": "Subnet Broadcast", "department": "Infrastructure",
        "role": "Layer-3 subnet broadcast — NetBIOS only",
        "expected_services": {137, 138},
    },
    "255.255.255.255": {
        "label": "Limited Broadcast", "department": "Infrastructure",
        "role": "Limited broadcast — DHCP / NetBIOS discover",
        "expected_services": {67, 68},
    },
    "0.0.0.0": {
        "label": "Unassigned / DHCP discover source", "department": "Infrastructure",
        "role": "DHCP discover source address (pre-assignment)",
        "expected_services": {68},
    },
    "192.168.100.4": {
        "label": "Unknown_4", "department": "Unknown",
        "role": "Unidentified host — investigate; only NetBIOS-NS seen",
        "expected_services": {137},
    },
    "192.168.100.5": {
        "label": "Unknown_5", "department": "Unknown",
        "role": "Unidentified host — investigate; NetBIOS-NS/DGM seen",
        "expected_services": {137, 138},
    },
    "192.168.100.180": {
        "label": "Unknown_180", "department": "Unknown",
        "role": "Unidentified host — investigate; only NetBIOS-NS seen",
        "expected_services": {137},
    },
}

DEFAULT_REQUIRED_DEPARTMENTS = {
    "Domain Controller", "Mayor's Office", "Tax Office",
    "Police Department", "Community Development",
    "Planning and Zoning", "IT", "Web Server",
}

# ═══════════════════════════════════════════════════════════════════
#  ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════
EPHEMERAL_MIN = 1024
EPHEMERAL_MAX = 65535
GAP_THRESHOLD_SECONDS = 300
SERVICE_CACHE = {}


def get_service_name(port):
    if port in SERVICE_CACHE:
        return SERVICE_CACHE[port]
    try:
        name = socket.getservbyport(int(port))
    except Exception:
        name = "unknown"
    SERVICE_CACHE[port] = name
    return name


def is_ephemeral(port):
    return EPHEMERAL_MIN <= port <= EPHEMERAL_MAX


def ts_to_iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def nested_dict():
    return defaultdict(set)


def nested_int_dict():
    return defaultdict(int)


def analyze_single_pcap(file_path):
    from scapy.all import PcapReader, IP, TCP, UDP
    ip_services = defaultdict(nested_dict)
    ip_port_counts = defaultdict(nested_int_dict)
    packet_count = 0
    first_ts = None
    last_ts = None
    start_time = time.time()

    try:
        with PcapReader(file_path) as pcap:
            for pkt in pcap:
                packet_count += 1
                pkt_ts = float(pkt.time)
                if first_ts is None or pkt_ts < first_ts:
                    first_ts = pkt_ts
                if last_ts is None or pkt_ts > last_ts:
                    last_ts = pkt_ts

                if not pkt.haslayer(IP):
                    continue
                ip = pkt[IP]

                if pkt.haslayer(TCP):
                    src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
                else:
                    continue

                src_ip, dst_ip = ip.src, ip.dst
                src_eph = is_ephemeral(src_port)
                dst_eph = is_ephemeral(dst_port)

                def record(addr, port):
                    ip_services[addr][port].add(file_path)
                    ip_port_counts[addr][port] += 1

                if src_eph and not dst_eph:
                    record(dst_ip, dst_port)
                elif dst_eph and not src_eph:
                    record(src_ip, src_port)
                elif not src_eph and not dst_eph:
                    record(src_ip, src_port)
                    record(dst_ip, dst_port)

    except Exception as exc:
        return None

    if packet_count == 0:
        return None

    return {
        "file": file_path,
        "packets": packet_count,
        "hosts": len(ip_services),
        "data": ip_services,
        "counts": ip_port_counts,
        "time": time.time() - start_time,
        "first_ts": first_ts,
        "last_ts": last_ts,
    }


def merge_results(results):
    merged = defaultdict(nested_dict)
    merged_counts = defaultdict(nested_int_dict)
    total_packets = 0
    for r in results:
        total_packets += r["packets"]
        for ip, ports in r["data"].items():
            for port, files in ports.items():
                merged[ip][port].update(files)
        for ip, ports in r["counts"].items():
            for port, count in ports.items():
                merged_counts[ip][port] += count
    return merged, merged_counts, total_packets


def build_temporal_coverage(valid_results, gap_threshold=GAP_THRESHOLD_SECONDS):
    timed = [r for r in valid_results if r.get("first_ts") is not None]
    if not timed:
        return {"error": "No timestamp data available."}
    timed.sort(key=lambda r: r["first_ts"])
    overall_first = timed[0]["first_ts"]
    overall_last = max(r["last_ts"] for r in timed)

    file_entries = [{
        "file": os.path.basename(r["file"]),
        "full_path": r["file"],
        "first_ts": ts_to_iso(r["first_ts"]),
        "last_ts": ts_to_iso(r["last_ts"]),
        "duration_seconds": round(r["last_ts"] - r["first_ts"], 3),
    } for r in timed]

    intervals = sorted((r["first_ts"], r["last_ts"]) for r in timed)
    merged_ivs = []
    cur_s, cur_e = intervals[0]
    for s, e in intervals[1:]:
        if s <= cur_e:
            cur_e = max(cur_e, e)
        else:
            merged_ivs.append((cur_s, cur_e))
            cur_s, cur_e = s, e
    merged_ivs.append((cur_s, cur_e))

    gaps = []
    for i in range(len(merged_ivs) - 1):
        g_start = merged_ivs[i][1]
        g_end = merged_ivs[i + 1][0]
        dur = g_end - g_start
        if dur >= gap_threshold:
            gaps.append({
                "gap_start": ts_to_iso(g_start),
                "gap_end": ts_to_iso(g_end),
                "gap_duration_seconds": round(dur, 3),
            })

    return {
        "overall_first": ts_to_iso(overall_first),
        "overall_last": ts_to_iso(overall_last),
        "total_duration_seconds": round(overall_last - overall_first, 3),
        "is_contiguous": len(gaps) == 0,
        "gap_threshold_seconds": gap_threshold,
        "files": file_entries,
        "gaps": gaps,
    }


def build_json_output(ip_services, ip_counts, total_packets, known_systems):
    output = {}
    for ip, ports in ip_services.items():
        sys_info = known_systems.get(ip, {})
        output[ip] = {
            "_meta": {
                "label": sys_info.get("label", "unknown"),
                "department": sys_info.get("department", "unknown"),
                "role": sys_info.get("role", "unknown"),
            }
        }
        expected = sys_info.get("expected_services", set())
        for port, files in ports.items():
            count = ip_counts[ip][port]
            percent = (count / total_packets * 100) if total_packets else 0
            is_unexpected = port not in expected
            is_ransomware = port in RANSOMWARE_PORT_SIGNATURES and is_unexpected
            entry = {
                "service": get_service_name(port),
                "packet_count": count,
                "percent_of_total_packets": round(percent, 4),
                "unexpected": is_unexpected,
                "files": sorted(list(files)),
            }
            if is_ransomware:
                entry["ransomware_signal"] = True
                entry["ransomware_severity"] = RANSOMWARE_PORT_SEVERITY.get(port, "LOW")
                entry["ransomware_note"] = RANSOMWARE_PORT_SIGNATURES[port]
            output[ip][str(port)] = entry
    return output


def build_coverage_report(ip_services, ip_counts, total_packets, temporal_data,
                           known_systems, required_departments):
    lines = []
    W = 72
    sep = "=" * W

    lines += [sep, "SECTION 1 — TEMPORAL COVERAGE", sep, ""]
    if "error" in temporal_data:
        lines.append(f"  ERROR: {temporal_data['error']}")
    else:
        lines.append(f"  Capture start   : {temporal_data['overall_first']}")
        lines.append(f"  Capture end     : {temporal_data['overall_last']}")
        dur = temporal_data['total_duration_seconds']
        lines.append(f"  Total span      : {dur:,.0f}s  ({dur/3600:.2f} hours)")
        lines.append(f"  Is contiguous   : {'YES' if temporal_data['is_contiguous'] else 'NO — gaps detected'}")
        lines.append(f"  Files analysed  : {len(temporal_data['files'])}")
        lines.append(f"  Gap threshold   : >{temporal_data['gap_threshold_seconds']}s silence")
        lines.append("")
        if temporal_data["gaps"]:
            lines.append(f"  COVERAGE GAPS DETECTED ({len(temporal_data['gaps'])} gap(s)):")
            for g in temporal_data["gaps"]:
                d = g['gap_duration_seconds']
                lines.append(f"    {g['gap_start']}  ->  {g['gap_end']}  ({d:,.0f}s / {d/3600:.2f}h)")
        else:
            lines.append("  No significant gaps detected — coverage appears contiguous.")
        lines += ["", "  Per-file timeline:"]
        for fe in sorted(temporal_data["files"], key=lambda x: x["first_ts"]):
            lines.append(f"    {fe['file']:<45} {fe['first_ts']}  ->  {fe['last_ts']}  ({fe['duration_seconds']:,.0f}s)")

    lines += ["", "", sep, "SECTION 2 — NETWORK COVERAGE", sep, ""]
    observed_ips = set(ip_services.keys())
    known_ips = set(known_systems.keys())
    covered_ips = observed_ips & known_ips
    unknown_ips = observed_ips - known_ips
    missing_known_ips = known_ips - observed_ips
    observed_depts = {known_systems[ip]["department"] for ip in covered_ips}
    missing_depts = required_departments - observed_depts

    lines.append(f"  Total distinct IPs observed      : {len(observed_ips)}")
    lines.append(f"  IPs matched to known systems     : {len(covered_ips)}")
    lines.append(f"  IPs with no known assignment     : {len(unknown_ips)}")
    lines.append(f"  Known systems NOT seen in caps   : {len(missing_known_ips)}")
    lines.append("")
    lines.append("  DEPARTMENTS WITH COVERAGE:")
    for dept in sorted(observed_depts):
        lines.append(f"    [OK]  {dept}")
    if missing_depts:
        lines.append("")
        lines.append("  DEPARTMENTS WITH NO COVERAGE:")
        for dept in sorted(missing_depts):
            lines.append(f"    [MISSING]  {dept}")
    if missing_known_ips:
        lines.append("")
        lines.append("  KNOWN SYSTEMS NOT SEEN IN ANY CAPTURE:")
        for ip in sorted(missing_known_ips):
            s = known_systems[ip]
            lines.append(f"    {ip:<20} {s['label']:<20} {s['department']}")
    if unknown_ips:
        lines.append("")
        lines.append("  UNRECOGNISED IPs:")
        for ip in sorted(unknown_ips):
            lines.append(f"    {ip}")

    lines += ["", "", sep, "SECTION 3 — PER-HOST SERVICE VALIDATION", sep,
              "  [UNEXPECTED] = port not in host's defined role",
              "  [RANSOMWARE SIGNAL] = unexpected port matching a ransomware signature",
              "  [rsw-context] = expected port that is also ransomware-associated", ""]

    for ip in sorted(observed_ips):
        sys_info = known_systems.get(ip)
        label = sys_info["label"] if sys_info else "UNKNOWN"
        dept = sys_info["department"] if sys_info else "Unknown"
        role = sys_info["role"] if sys_info else "No role defined — investigate"
        expected = sys_info["expected_services"] if sys_info else set()
        observed_ports = set(ip_services[ip].keys())
        unexpected_ports = observed_ports - expected
        ransomware_hits = {p for p in unexpected_ports if p in RANSOMWARE_PORT_SIGNATURES}
        ransomware_contextual = {p for p in observed_ports & expected if p in RANSOMWARE_PORT_SIGNATURES}

        lines.append(f"  {'-' * (W - 2)}")
        lines.append(f"  Host : {ip}  [{label}]")
        lines.append(f"  Dept : {dept}")
        lines.append(f"  Role : {role}")
        lines.append("")
        lines.append(f"  {'Port':<6} {'Service':<22} {'Packets':>12} {'% Total':>10}  Flags")
        lines.append(f"  {'----':<6} {'-------':<22} {'-------':>12} {'-------':>10}  -----")

        for port in sorted(observed_ports):
            count = ip_counts[ip][port]
            pct = (count / total_packets * 100) if total_packets else 0
            svc = get_service_name(port)
            flags = []
            if port in unexpected_ports:
                flags.append("UNEXPECTED")
            if port in ransomware_hits:
                sev = RANSOMWARE_PORT_SEVERITY.get(port, "LOW")
                flags.append(f"RANSOMWARE SIGNAL [{sev}]")
            elif port in ransomware_contextual:
                sev = RANSOMWARE_PORT_SEVERITY.get(port, "LOW")
                flags.append(f"rsw-context [{sev}]")
            flag_str = "  <- " + " | ".join(flags) if flags else ""
            lines.append(f"  {port:<6} {svc:<22} {count:>12,} {pct:>9.4f}%{flag_str}")

        lines.append("")
        if {p for p in (observed_ports - expected)} and ransomware_hits:
            lines.append("  RANSOMWARE SIGNAL DETAIL:")
            for port in sorted(ransomware_hits, key=lambda p: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(
                    RANSOMWARE_PORT_SEVERITY.get(p, "LOW"), 2)):
                sev = RANSOMWARE_PORT_SEVERITY.get(port, "LOW")
                desc = RANSOMWARE_PORT_SIGNATURES[port]
                lines.append(f"    [{sev}] Port {port}: {desc}")
            lines.append("")

    lines += ["", sep, "SECTION 4 — RANSOMWARE SIGNAL SUMMARY", sep,
              "  Hosts with unexpected ports matching ransomware signatures.", ""]

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    hit_rows = []
    for ip in sorted(observed_ips):
        sys_info = known_systems.get(ip)
        expected = sys_info["expected_services"] if sys_info else set()
        observed_ports = set(ip_services[ip].keys())
        hits = {p for p in observed_ports if p in RANSOMWARE_PORT_SIGNATURES and p not in expected}
        if not hits:
            continue
        worst_sev = min((RANSOMWARE_PORT_SEVERITY.get(p, "LOW") for p in hits),
                        key=lambda s: severity_order.get(s, 2))
        hit_rows.append((worst_sev, ip, sys_info, hits))

    hit_rows.sort(key=lambda x: severity_order.get(x[0], 2))

    if hit_rows:
        for worst_sev, ip, sys_info, hits in hit_rows:
            label = sys_info["label"] if sys_info else "UNKNOWN"
            dept = sys_info["department"] if sys_info else "Unknown"
            lines.append(f"  [{worst_sev}] {ip}  [{label}]  —  {dept}")
            for port in sorted(hits, key=lambda p: severity_order.get(
                    RANSOMWARE_PORT_SEVERITY.get(p, "LOW"), 2)):
                sev = RANSOMWARE_PORT_SEVERITY.get(port, "LOW")
                desc = RANSOMWARE_PORT_SIGNATURES[port]
                count = ip_counts[ip][port]
                pct = (count / total_packets * 100) if total_packets else 0
                lines.append(f"    [{sev}] Port {port} ({get_service_name(port)}) — {count:,} pkts ({pct:.4f}%)")
                lines.append(f"           {desc}")
            lines.append("")
    else:
        lines.append("  No ransomware-associated unexpected ports detected.")

    lines += ["", sep, "END OF REPORT", sep]
    return lines


def generate_uncovered_time_report(data, output_file, gap_threshold=GAP_THRESHOLD_SECONDS):
    def parse_time(ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", ""))
        except Exception:
            return None

    def format_hms(seconds):
        seconds = int(seconds)
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        parts = []
        if h: parts.append(f"{h}h")
        if m: parts.append(f"{m}m")
        if s or not parts: parts.append(f"{s}s")
        return " ".join(parts)

    files = data.get("files", [])
    normalized = []
    for f in files:
        start = parse_time(f.get("first_ts"))
        end = parse_time(f.get("last_ts"))
        if start and end:
            normalized.append({"file": f.get("file"), "start": start, "end": end})
    normalized.sort(key=lambda x: x["start"])

    uncovered = []
    for i in range(len(normalized) - 1):
        cur = normalized[i]
        nxt = normalized[i + 1]
        gap_secs = (nxt["start"] - cur["end"]).total_seconds()
        if gap_secs >= gap_threshold:
            uncovered.append({
                "Uncovered Start Time": cur["end"].strftime("%Y-%m-%d %H:%M:%S"),
                "Uncovered End Time": nxt["start"].strftime("%Y-%m-%d %H:%M:%S"),
                "Uncovered Duration": format_hms(gap_secs),
                "Before File": cur["file"],
                "After File": nxt["file"],
            })

    fieldnames = ["Uncovered Start Time", "Uncovered End Time",
                  "Uncovered Duration", "Before File", "After File"]
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(uncovered)

    return len(uncovered)


# ═══════════════════════════════════════════════════════════════════
#  COLOR THEME
# ═══════════════════════════════════════════════════════════════════
THEME = {
    "bg":         "#0d0f14",
    "bg2":        "#151820",
    "bg3":        "#1e2230",
    "panel":      "#111318",
    "border":     "#2a2f3d",
    "accent":     "#00d4ff",
    "accent2":    "#ff6b35",
    "accent3":    "#39ff14",
    "warn":       "#ffb300",
    "danger":     "#ff3547",
    "text":       "#c8d0e0",
    "text_dim":   "#5a6070",
    "text_bright":"#edf2ff",
    "high":       "#ff3547",
    "medium":     "#ffb300",
    "low":        "#39ff14",
    "ok":         "#00d4ff",
    "font_mono":  ("Courier New", 10),
    "font_ui":    ("Courier New", 10),
    "font_head":  ("Courier New", 12, "bold"),
    "font_title": ("Courier New", 14, "bold"),
}


# ═══════════════════════════════════════════════════════════════════
#  STYLED WIDGET HELPERS
# ═══════════════════════════════════════════════════════════════════
def styled_label(parent, text, font=None, fg=None, **kw):
    return tk.Label(parent, text=text,
                    font=font or THEME["font_ui"],
                    fg=fg or THEME["text"],
                    bg=THEME["bg2"],
                    **kw)


def styled_button(parent, text, command, fg=None, **kw):
    btn = tk.Button(
        parent, text=text, command=command,
        font=THEME["font_ui"],
        fg=fg or THEME["bg"],
        bg=THEME["accent"],
        activebackground=THEME["accent2"],
        activeforeground=THEME["bg"],
        relief="flat", bd=0,
        padx=12, pady=4,
        cursor="hand2",
        **kw
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=THEME["accent2"]))
    btn.bind("<Leave>", lambda e: btn.config(bg=fg or THEME["accent"]))
    return btn


def styled_entry(parent, textvariable=None, width=40, **kw):
    return tk.Entry(
        parent,
        textvariable=textvariable,
        font=THEME["font_mono"],
        fg=THEME["text_bright"],
        bg=THEME["bg3"],
        insertbackground=THEME["accent"],
        relief="flat",
        bd=0,
        highlightthickness=1,
        highlightbackground=THEME["border"],
        highlightcolor=THEME["accent"],
        width=width,
        **kw
    )


def styled_listbox(parent, **kw):
    lb = tk.Listbox(
        parent,
        font=THEME["font_mono"],
        fg=THEME["text"],
        bg=THEME["bg3"],
        selectbackground=THEME["accent"],
        selectforeground=THEME["bg"],
        relief="flat",
        bd=0,
        highlightthickness=1,
        highlightbackground=THEME["border"],
        activestyle="none",
        **kw
    )
    return lb


def styled_frame(parent, **kw):
    return tk.Frame(parent, bg=THEME["bg2"], **kw)


def styled_scrolled_text(parent, **kw):
    st = scrolledtext.ScrolledText(
        parent,
        font=THEME["font_mono"],
        fg=THEME["text"],
        bg=THEME["bg3"],
        insertbackground=THEME["accent"],
        relief="flat",
        bd=0,
        highlightthickness=1,
        highlightbackground=THEME["border"],
        **kw
    )
    return st


def section_header(parent, text):
    f = tk.Frame(parent, bg=THEME["accent"], height=1)
    f.pack(fill=tk.X, pady=(12, 0))
    lbl = tk.Label(parent, text=f"  {text}",
                   font=THEME["font_head"],
                   fg=THEME["accent"],
                   bg=THEME["bg2"],
                   anchor="w")
    lbl.pack(fill=tk.X)
    f2 = tk.Frame(parent, bg=THEME["border"], height=1)
    f2.pack(fill=tk.X, pady=(0, 6))


def add_scrollbar(parent, widget, orient="vertical"):
    if orient == "vertical":
        sb = tk.Scrollbar(parent, orient=tk.VERTICAL, command=widget.yview,
                          bg=THEME["bg3"], troughcolor=THEME["bg"],
                          activebackground=THEME["accent"])
        widget.config(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    else:
        sb = tk.Scrollbar(parent, orient=tk.HORIZONTAL, command=widget.xview,
                          bg=THEME["bg3"], troughcolor=THEME["bg"],
                          activebackground=THEME["accent"])
        widget.config(xscrollcommand=sb.set)
        sb.pack(side=tk.BOTTOM, fill=tk.X)
        widget.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    return sb


# ═══════════════════════════════════════════════════════════════════
#  TAB 1 — ANALYZER
# ═══════════════════════════════════════════════════════════════════
class AnalyzerTab:
    def __init__(self, parent, app):
        self.app = app
        self.frame = styled_frame(parent)
        self._build()

    def _build(self):
        f = self.frame

        # ── Paths ──
        section_header(f, "INPUT / OUTPUT PATHS")
        paths_frame = styled_frame(f)
        paths_frame.pack(fill=tk.X, padx=14, pady=4)

        rows = [
            ("PCAP Directory",    "pcap_dir",     "dir"),
            ("JSON Output",       "json_output",  "file_save"),
            ("Temporal JSON",     "temporal_out", "file_save"),
            ("Coverage Report",   "cov_report",   "file_save"),
            ("Grouped Profiles",  "grouped_out",  "file_save"),
        ]

        for label, var_name, kind in rows:
            row = styled_frame(paths_frame)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=f"{label:<22}", font=THEME["font_mono"],
                     fg=THEME["text_dim"], bg=THEME["bg2"], anchor="w", width=22).pack(side=tk.LEFT)
            var = self.app.vars[var_name]
            ent = styled_entry(row, textvariable=var, width=55)
            ent.pack(side=tk.LEFT, padx=(4, 6))

            if kind == "dir":
                cmd = lambda v=var: v.set(filedialog.askdirectory(title="Select PCAP Directory") or v.get())
            else:
                cmd = lambda v=var: v.set(
                    filedialog.asksaveasfilename(title="Save As", defaultextension=".json") or v.get()
                )
            styled_button(row, "Browse", cmd).pack(side=tk.LEFT)

        # ── Settings ──
        section_header(f, "ANALYSIS SETTINGS")
        sett_frame = styled_frame(f)
        sett_frame.pack(fill=tk.X, padx=14, pady=4)

        row1 = styled_frame(sett_frame)
        row1.pack(fill=tk.X, pady=2)
        tk.Label(row1, text="Gap Threshold (seconds):", font=THEME["font_mono"],
                 fg=THEME["text_dim"], bg=THEME["bg2"]).pack(side=tk.LEFT)
        styled_entry(row1, textvariable=self.app.vars["gap_threshold"], width=8).pack(side=tk.LEFT, padx=6)

        row2 = styled_frame(sett_frame)
        row2.pack(fill=tk.X, pady=2)
        tk.Label(row2, text="Max Workers (CPU cores):", font=THEME["font_mono"],
                 fg=THEME["text_dim"], bg=THEME["bg2"]).pack(side=tk.LEFT)
        styled_entry(row2, textvariable=self.app.vars["max_workers"], width=8).pack(side=tk.LEFT, padx=6)

        # ── Run Button ──
        section_header(f, "RUN ANALYSIS")
        btn_frame = styled_frame(f)
        btn_frame.pack(fill=tk.X, padx=14, pady=8)

        self.run_btn = styled_button(btn_frame, "▶  RUN FULL ANALYSIS", self._run_analysis,
                                     fg=THEME["bg"])
        self.run_btn.config(font=THEME["font_head"], padx=20, pady=8)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 12))

        self.status_lbl = tk.Label(btn_frame, text="Ready.", font=THEME["font_mono"],
                                   fg=THEME["text_dim"], bg=THEME["bg2"])
        self.status_lbl.pack(side=tk.LEFT)

        # ── Log ──
        section_header(f, "ANALYSIS LOG")
        log_frame = styled_frame(f)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=14, pady=(4, 14))

        self.log = styled_scrolled_text(log_frame, height=18)
        self.log.pack(fill=tk.BOTH, expand=True)
        self.log.config(state=tk.DISABLED)

        # Configure tags for coloured log output
        self.log.tag_config("info",    foreground=THEME["ok"])
        self.log.tag_config("warn",    foreground=THEME["warn"])
        self.log.tag_config("danger",  foreground=THEME["danger"])
        self.log.tag_config("success", foreground=THEME["accent3"])
        self.log.tag_config("dim",     foreground=THEME["text_dim"])

    def _log(self, msg, tag="info"):
        self.log.config(state=tk.NORMAL)
        self.log.insert(tk.END, msg + "\n", tag)
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)

    def _run_analysis(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Scapy Missing",
                                 "Scapy is not installed.\nRun: pip install scapy")
            return

        pcap_dir = self.app.vars["pcap_dir"].get().strip()
        if not pcap_dir or not os.path.isdir(pcap_dir):
            messagebox.showerror("Invalid Path", "Please select a valid PCAP directory.")
            return

        self.run_btn.config(state=tk.DISABLED, text="⏳  Running…")
        self.log.config(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.config(state=tk.DISABLED)

        thread = threading.Thread(target=self._analysis_worker, daemon=True)
        thread.start()

    def _analysis_worker(self):
        try:
            pcap_dir   = self.app.vars["pcap_dir"].get().strip()
            json_out   = self.app.vars["json_output"].get().strip()
            temp_out   = self.app.vars["temporal_out"].get().strip()
            cov_report = self.app.vars["cov_report"].get().strip()
            grouped_out= self.app.vars["grouped_out"].get().strip()
            gap_thr    = int(self.app.vars["gap_threshold"].get().strip() or 300)
            max_wkr    = int(self.app.vars["max_workers"].get().strip() or os.cpu_count())

            known_systems = self.app.known_systems
            req_depts     = self.app.required_departments

            # Collect files
            all_files = []
            for root, _, fnames in os.walk(pcap_dir):
                for fn in fnames:
                    all_files.append(os.path.join(root, fn))

            self._log(f"[INFO] Found {len(all_files)} files in {pcap_dir}", "info")
            self._log(f"[INFO] Using {max_wkr} worker processes", "dim")

            valid_results = []
            completed = 0

            with ProcessPoolExecutor(max_workers=max_wkr) as executor:
                futures = {executor.submit(analyze_single_pcap, f): f for f in all_files}
                for future in as_completed(futures):
                    completed += 1
                    fp = futures[future]
                    try:
                        result = future.result()
                    except Exception as e:
                        self._log(f"[ERROR] {os.path.basename(fp)}: {e}", "danger")
                        continue
                    if result is None:
                        self._log(f"[SKIP]  {os.path.basename(fp)} — no IP packets", "dim")
                        continue
                    valid_results.append(result)
                    self._log(
                        f"[{completed}/{len(all_files)}] {os.path.basename(fp)} | "
                        f"{result['packets']:,} pkts | {result['hosts']} hosts | "
                        f"{result['time']:.2f}s",
                        "success"
                    )

            if not valid_results:
                self._log("[WARN] No valid PCAP files found or no IP traffic detected.", "warn")
                self.run_btn.config(state=tk.NORMAL, text="▶  RUN FULL ANALYSIS")
                return

            merged, merged_counts, total_packets = merge_results(valid_results)
            self._log(f"\n[SUMMARY] {len(valid_results)} PCAPs | {total_packets:,} packets | {len(merged)} hosts", "success")

            # Temporal
            temporal_data = build_temporal_coverage(valid_results, gap_thr)
            with open(temp_out, "w") as f:
                json.dump(temporal_data, f, indent=4)
            self._log(f"[SAVED]  {temp_out}", "info")

            # JSON
            json_output = build_json_output(merged, merged_counts, total_packets, known_systems)
            with open(json_out, "w") as f:
                json.dump(json_output, f, indent=4)
            self._log(f"[SAVED]  {json_out}", "info")

            # Coverage report
            report_lines = build_coverage_report(merged, merged_counts, total_packets,
                                                  temporal_data, known_systems, req_depts)
            with open(cov_report, "w", encoding="utf-8") as f:
                f.write("\n".join(report_lines))
            self._log(f"[SAVED]  {cov_report}", "info")

            # Grouped profiles
            profile_to_ips = defaultdict(list)
            for ip, ports in merged.items():
                services = []
                for port, files in ports.items():
                    name = get_service_name(port)
                    if name == "unknown":
                        continue
                    file_list = sorted(os.path.basename(fpath) for fpath in files)
                    services.append(f"{port}({name}) [{', '.join(file_list)}]")
                if not services:
                    continue
                profile_to_ips[tuple(sorted(services))].append(ip)

            sorted_profiles = sorted(profile_to_ips.items(), key=lambda x: len(x[1]), reverse=True)
            lines = ["Grouped Hosts by Identical Service Profiles\n", "Hosts\tServices Offered\n"]
            for services, ips in sorted_profiles:
                lines.append(f"{', '.join(sorted(ips))}\t{'; '.join(services)}")
            with open(grouped_out, "w") as f:
                f.write("\n".join(lines))
            self._log(f"[SAVED]  {grouped_out}", "info")

            # Store results in app for other tabs
            self.app.analysis_results = {
                "merged": merged,
                "merged_counts": merged_counts,
                "total_packets": total_packets,
                "temporal_data": temporal_data,
                "json_output": json_output,
            }

            self._log("\n[DONE] All outputs written successfully.", "success")
            self.app.root.after(0, self._on_done_success)

        except Exception as e:
            self._log(f"\n[FATAL] {e}", "danger")
            self._log(traceback.format_exc(), "danger")
            self.app.root.after(0, lambda: self.run_btn.config(
                state=tk.NORMAL, text="▶  RUN FULL ANALYSIS"))

    def _on_done_success(self):
        self.run_btn.config(state=tk.NORMAL, text="▶  RUN FULL ANALYSIS")
        self.status_lbl.config(text="Analysis complete.", fg=THEME["accent3"])
        messagebox.showinfo("Complete", "Analysis finished.\nAll output files written.")


# ═══════════════════════════════════════════════════════════════════
#  TAB 2 — SERVICE VISUALIZER
# ═══════════════════════════════════════════════════════════════════
class VisualizerTab:
    def __init__(self, parent, app):
        self.app = app
        self.frame = styled_frame(parent)
        self.data = {}
        self.grouped = {}
        self.group_keys = []
        self.current_hosts = []
        self.current_services = []
        self.current_ip = None
        self._build()

    def _build(self):
        f = self.frame

        # ── Top bar ──
        top = styled_frame(f)
        top.pack(fill=tk.X, padx=14, pady=8)

        tk.Label(top, text="JSON Source:", font=THEME["font_mono"],
                 fg=THEME["text_dim"], bg=THEME["bg2"]).pack(side=tk.LEFT)
        self.json_path_var = tk.StringVar(value=self.app.vars["json_output"].get())
        ent = styled_entry(top, textvariable=self.json_path_var, width=50)
        ent.pack(side=tk.LEFT, padx=6)

        styled_button(top, "Browse", self._browse_json).pack(side=tk.LEFT, padx=(0, 6))
        styled_button(top, "Load JSON", self._load_json, fg=THEME["bg"]).pack(side=tk.LEFT, padx=(0, 6))
        styled_button(top, "↻ From Analysis", self._load_from_analysis,
                      fg=THEME["bg"]).pack(side=tk.LEFT)

        # ── Column headers ──
        hdr = styled_frame(f)
        hdr.pack(fill=tk.X, padx=14, pady=(0, 2))
        for col, w in [("SERVICE GROUPS", 0), ("HOSTS (IPs)", 0),
                       ("SERVICES / PORTS", 0), ("SOURCE FILES", 0), ("HOST METADATA", 0)]:
            tk.Label(hdr, text=col, font=THEME["font_head"],
                     fg=THEME["accent"], bg=THEME["bg2"],
                     anchor="w").pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        # ── 5-column layout ──
        cols_frame = styled_frame(f)
        cols_frame.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 14))

        def make_col():
            col = styled_frame(cols_frame)
            col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
            inner = styled_frame(col)
            inner.pack(fill=tk.BOTH, expand=True)
            inner.config(highlightthickness=1, highlightbackground=THEME["border"])
            return inner

        # Groups
        g_col = make_col()
        self.group_list = styled_listbox(g_col, selectmode=tk.SINGLE)
        sb = tk.Scrollbar(g_col, orient=tk.VERTICAL, command=self.group_list.yview,
                          bg=THEME["bg3"], troughcolor=THEME["bg"])
        self.group_list.config(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.group_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.group_list.bind("<<ListboxSelect>>", self._on_group_select)

        # Hosts
        h_col = make_col()
        self.host_list = styled_listbox(h_col, selectmode=tk.SINGLE)
        sb2 = tk.Scrollbar(h_col, orient=tk.VERTICAL, command=self.host_list.yview,
                           bg=THEME["bg3"], troughcolor=THEME["bg"])
        self.host_list.config(yscrollcommand=sb2.set)
        sb2.pack(side=tk.RIGHT, fill=tk.Y)
        self.host_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.host_list.bind("<<ListboxSelect>>", self._on_host_select)

        # Services
        s_col = make_col()
        self.service_list = styled_listbox(s_col, selectmode=tk.SINGLE)
        sb3 = tk.Scrollbar(s_col, orient=tk.VERTICAL, command=self.service_list.yview,
                           bg=THEME["bg3"], troughcolor=THEME["bg"])
        self.service_list.config(yscrollcommand=sb3.set)
        sb3.pack(side=tk.RIGHT, fill=tk.Y)
        self.service_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.service_list.bind("<<ListboxSelect>>", self._on_service_select)

        # Files
        fi_col = make_col()
        self.file_list = styled_listbox(fi_col, selectmode=tk.SINGLE)
        sb4 = tk.Scrollbar(fi_col, orient=tk.VERTICAL, command=self.file_list.yview,
                           bg=THEME["bg3"], troughcolor=THEME["bg"])
        self.file_list.config(yscrollcommand=sb4.set)
        sb4.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Metadata
        m_col = make_col()
        self.meta_text = styled_scrolled_text(m_col, height=6)
        self.meta_text.pack(fill=tk.BOTH, expand=True)
        self.meta_text.config(state=tk.DISABLED)

        # Legend
        leg = styled_frame(f)
        leg.pack(fill=tk.X, padx=14, pady=(0, 8))
        for txt, col in [("● UNEXPECTED", THEME["danger"]),
                         ("● HIGH TRAFFIC (>50%)", THEME["warn"]),
                         ("● RANSOMWARE SIGNAL", THEME["accent2"]),
                         ("● NORMAL", THEME["ok"])]:
            tk.Label(leg, text=txt, font=THEME["font_mono"],
                     fg=col, bg=THEME["bg2"]).pack(side=tk.LEFT, padx=8)

    def _browse_json(self):
        path = filedialog.askopenfilename(title="Select JSON File",
                                          filetypes=[("JSON files", "*.json")])
        if path:
            self.json_path_var.set(path)

    def _load_json(self):
        path = self.json_path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("File Not Found", f"Cannot open:\n{path}")
            return
        try:
            with open(path, "r") as f:
                self.data = json.load(f)
            self._group_and_populate()
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    def _load_from_analysis(self):
        if not self.app.analysis_results:
            messagebox.showwarning("No Data", "Run an analysis first, or load a JSON file.")
            return
        self.data = self.app.analysis_results["json_output"]
        self._group_and_populate()

    def _group_and_populate(self):
        self.grouped = {}
        for ip, ports in self.data.items():
            services = []
            for port, details in ports.items():
                if port == "_meta":
                    continue
                name = details.get("service", "unknown")
                unexp = details.get("unexpected", False)
                tag = "(!)" if unexp else ""
                services.append(f"{port}({name}){tag}")
            key = tuple(sorted(services))
            self.grouped.setdefault(key, []).append(ip)

        self.group_list.delete(0, tk.END)
        sorted_groups = sorted(self.grouped.items(), key=lambda x: len(x[1]), reverse=True)
        self.group_keys = []
        for services, ips in sorted_groups:
            label = f"{len(ips)} host(s) | {' ; '.join(services[:4])}"
            if len(services) > 4:
                label += " …"
            self.group_list.insert(tk.END, label)
            self.group_keys.append(services)

        self.host_list.delete(0, tk.END)
        self.service_list.delete(0, tk.END)
        self.file_list.delete(0, tk.END)
        self.meta_text.config(state=tk.NORMAL)
        self.meta_text.delete("1.0", tk.END)
        self.meta_text.config(state=tk.DISABLED)

    def _on_group_select(self, event):
        sel = self.group_list.curselection()
        if not sel:
            return
        services_key = self.group_keys[sel[0]]
        self.current_hosts = self.grouped[services_key]
        self.host_list.delete(0, tk.END)
        self.service_list.delete(0, tk.END)
        self.file_list.delete(0, tk.END)
        self.meta_text.config(state=tk.NORMAL)
        self.meta_text.delete("1.0", tk.END)
        self.meta_text.config(state=tk.DISABLED)
        for ip in sorted(self.current_hosts):
            self.host_list.insert(tk.END, ip)

    def _on_host_select(self, event):
        sel = self.host_list.curselection()
        if not sel:
            return
        ip = self.host_list.get(sel[0])
        self.current_ip = ip
        self.service_list.delete(0, tk.END)
        self.file_list.delete(0, tk.END)

        meta = self.data[ip].get("_meta", {})
        self.meta_text.config(state=tk.NORMAL)
        self.meta_text.delete("1.0", tk.END)
        self.meta_text.insert(tk.END,
            f"Label      : {meta.get('label', 'N/A')}\n"
            f"Department : {meta.get('department', 'N/A')}\n"
            f"Role       : {meta.get('role', 'N/A')}\n"
        )
        self.meta_text.config(state=tk.DISABLED)

        self.current_services = []
        for port, details in self.data[ip].items():
            if port == "_meta":
                continue
            name = details.get("service", "unknown")
            count = details.get("packet_count", 0)
            pct = details.get("percent_of_total_packets", 0)
            unexp = details.get("unexpected", False)
            rsw = details.get("ransomware_signal", False)
            label = f"{port:<6} {name:<18} {count:>10,} pkts  {pct:>6.2f}%"
            self.service_list.insert(tk.END, label)
            idx = self.service_list.size() - 1
            if rsw:
                self.service_list.itemconfig(idx, fg=THEME["accent2"])
            elif unexp:
                self.service_list.itemconfig(idx, fg=THEME["danger"])
            elif pct > 50:
                self.service_list.itemconfig(idx, fg=THEME["warn"])
            else:
                self.service_list.itemconfig(idx, fg=THEME["ok"])
            self.current_services.append((port, label))

    def _on_service_select(self, event):
        sel = self.service_list.curselection()
        if not sel:
            return
        port, _ = self.current_services[sel[0]]
        self.file_list.delete(0, tk.END)
        files = self.data.get(self.current_ip, {}).get(port, {}).get("files", [])
        for fp in sorted(files):
            self.file_list.insert(tk.END, os.path.basename(fp))


# ═══════════════════════════════════════════════════════════════════
#  TAB 3 — COVERAGE GAP REPORT
# ═══════════════════════════════════════════════════════════════════
class GapReportTab:
    def __init__(self, parent, app):
        self.app = app
        self.frame = styled_frame(parent)
        self._build()

    def _build(self):
        f = self.frame

        section_header(f, "COVERAGE GAP REPORT")

        # ── Paths ──
        paths_frame = styled_frame(f)
        paths_frame.pack(fill=tk.X, padx=14, pady=6)

        # Temporal JSON input
        row1 = styled_frame(paths_frame)
        row1.pack(fill=tk.X, pady=3)
        tk.Label(row1, text="Temporal JSON Input:", font=THEME["font_mono"],
                 fg=THEME["text_dim"], bg=THEME["bg2"], width=24, anchor="w").pack(side=tk.LEFT)
        self.json_var = tk.StringVar(value=self.app.vars["temporal_out"].get())
        ent1 = styled_entry(row1, textvariable=self.json_var, width=52)
        ent1.pack(side=tk.LEFT, padx=4)
        styled_button(row1, "Browse", lambda: self.json_var.set(
            filedialog.askopenfilename(filetypes=[("JSON", "*.json")]) or self.json_var.get()
        )).pack(side=tk.LEFT)

        # CSV output
        row2 = styled_frame(paths_frame)
        row2.pack(fill=tk.X, pady=3)
        tk.Label(row2, text="CSV Output File:", font=THEME["font_mono"],
                 fg=THEME["text_dim"], bg=THEME["bg2"], width=24, anchor="w").pack(side=tk.LEFT)
        self.csv_var = tk.StringVar(value=self.app.vars["gap_csv_out"].get())
        ent2 = styled_entry(row2, textvariable=self.csv_var, width=52)
        ent2.pack(side=tk.LEFT, padx=4)
        styled_button(row2, "Browse", lambda: self.csv_var.set(
            filedialog.asksaveasfilename(defaultextension=".csv",
                                          filetypes=[("CSV", "*.csv")]) or self.csv_var.get()
        )).pack(side=tk.LEFT)

        # Gap threshold
        row3 = styled_frame(paths_frame)
        row3.pack(fill=tk.X, pady=3)
        tk.Label(row3, text="Gap Threshold (seconds):", font=THEME["font_mono"],
                 fg=THEME["text_dim"], bg=THEME["bg2"], width=24, anchor="w").pack(side=tk.LEFT)
        styled_entry(row3, textvariable=self.app.vars["gap_threshold"], width=10).pack(side=tk.LEFT, padx=4)

        # ── Buttons ──
        btn_frame = styled_frame(f)
        btn_frame.pack(fill=tk.X, padx=14, pady=8)
        styled_button(btn_frame, "▶  GENERATE CSV REPORT", self._generate, fg=THEME["bg"]).pack(side=tk.LEFT, padx=(0, 12))
        styled_button(btn_frame, "↻ Load From Analysis", self._load_from_analysis, fg=THEME["bg"]).pack(side=tk.LEFT)

        self.status_lbl = tk.Label(btn_frame, text="", font=THEME["font_mono"],
                                    fg=THEME["accent3"], bg=THEME["bg2"])
        self.status_lbl.pack(side=tk.LEFT, padx=12)

        # ── Results table ──
        section_header(f, "GAP TABLE PREVIEW")
        table_frame = styled_frame(f)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=14, pady=(4, 14))

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.Treeview",
                         background=THEME["bg3"],
                         foreground=THEME["text"],
                         fieldbackground=THEME["bg3"],
                         rowheight=22,
                         font=THEME["font_mono"])
        style.configure("Dark.Treeview.Heading",
                         background=THEME["bg"],
                         foreground=THEME["accent"],
                         font=THEME["font_head"])
        style.map("Dark.Treeview", background=[("selected", THEME["accent"])],
                  foreground=[("selected", THEME["bg"])])

        cols = ("Start", "End", "Duration", "Before File", "After File")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                  style="Dark.Treeview")
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180 if "File" in col else 140, anchor="w")

        vsb = tk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview,
                           bg=THEME["bg3"], troughcolor=THEME["bg"])
        hsb = tk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview,
                           bg=THEME["bg3"], troughcolor=THEME["bg"])
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)

    def _load_from_analysis(self):
        if not self.app.analysis_results:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return
        td = self.app.analysis_results.get("temporal_data", {})
        self._populate_from_temporal(td)

    def _generate(self):
        json_path = self.json_var.get().strip()
        csv_path = self.csv_var.get().strip()
        gap_thr = int(self.app.vars["gap_threshold"].get().strip() or 300)

        if not json_path or not os.path.isfile(json_path):
            messagebox.showerror("File Not Found", f"Cannot open:\n{json_path}")
            return
        if not csv_path:
            messagebox.showerror("No Output", "Please specify a CSV output path.")
            return

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            count = generate_uncovered_time_report(data, csv_path, gap_thr)
            self.status_lbl.config(text=f"✓ {count} gap(s) found → {os.path.basename(csv_path)}")
            self._populate_from_temporal(data)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _populate_from_temporal(self, td):
        for row in self.tree.get_children():
            self.tree.delete(row)

        gap_thr = int(self.app.vars["gap_threshold"].get().strip() or 300)
        files = td.get("files", [])

        def parse_t(ts):
            if not ts:
                return None
            try:
                return datetime.fromisoformat(ts.replace("Z", ""))
            except Exception:
                return None

        normalized = []
        for f in files:
            s = parse_t(f.get("first_ts"))
            e = parse_t(f.get("last_ts"))
            if s and e:
                normalized.append({"file": f.get("file"), "start": s, "end": e})
        normalized.sort(key=lambda x: x["start"])

        def fmt_hms(secs):
            secs = int(secs)
            h = secs // 3600; m = (secs % 3600) // 60; s = secs % 60
            parts = []
            if h: parts.append(f"{h}h")
            if m: parts.append(f"{m}m")
            if s or not parts: parts.append(f"{s}s")
            return " ".join(parts)

        for i in range(len(normalized) - 1):
            cur = normalized[i]; nxt = normalized[i + 1]
            gap = (nxt["start"] - cur["end"]).total_seconds()
            if gap >= gap_thr:
                self.tree.insert("", tk.END, values=(
                    cur["end"].strftime("%Y-%m-%d %H:%M:%S"),
                    nxt["start"].strftime("%Y-%m-%d %H:%M:%S"),
                    fmt_hms(gap),
                    cur["file"],
                    nxt["file"],
                ))


# ═══════════════════════════════════════════════════════════════════
#  TAB 4 — SYSTEM MAP EDITOR
# ═══════════════════════════════════════════════════════════════════
class SystemMapTab:
    def __init__(self, parent, app):
        self.app = app
        self.frame = styled_frame(parent)
        self._build()

    def _build(self):
        f = self.frame
        section_header(f, "KNOWN SYSTEMS CONFIGURATION")

        info = tk.Label(f,
            text="  Define known hosts, their department, role, and expected service ports.\n"
                 "  Hosts NOT in this map will appear as UNRECOGNISED in the coverage report.",
            font=THEME["font_mono"], fg=THEME["text_dim"], bg=THEME["bg2"], justify="left")
        info.pack(fill=tk.X, padx=14, pady=(4, 0))

        # ── Toolbar ──
        tb = styled_frame(f)
        tb.pack(fill=tk.X, padx=14, pady=6)
        styled_button(tb, "+ Add Host", self._add_host).pack(side=tk.LEFT, padx=(0, 6))
        styled_button(tb, "✕ Remove Selected", self._remove_host, fg=THEME["bg"]).pack(side=tk.LEFT, padx=(0, 6))
        styled_button(tb, "↓ Load JSON Map", self._load_map).pack(side=tk.LEFT, padx=(0, 6))
        styled_button(tb, "↑ Save JSON Map", self._save_map).pack(side=tk.LEFT, padx=(0, 6))
        styled_button(tb, "↺ Reset Defaults", self._reset_defaults).pack(side=tk.LEFT)

        # ── Host list + editor ──
        split = styled_frame(f)
        split.pack(fill=tk.BOTH, expand=True, padx=14, pady=(4, 14))

        # Left: IP list
        left = styled_frame(split)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        left.config(highlightthickness=1, highlightbackground=THEME["border"])
        tk.Label(left, text="IP ADDRESSES", font=THEME["font_head"],
                 fg=THEME["accent"], bg=THEME["bg2"]).pack(pady=(4, 2))
        self.ip_list = styled_listbox(left, width=22, selectmode=tk.SINGLE)
        sb = tk.Scrollbar(left, orient=tk.VERTICAL, command=self.ip_list.yview,
                          bg=THEME["bg3"], troughcolor=THEME["bg"])
        self.ip_list.config(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.ip_list.pack(side=tk.LEFT, fill=tk.Y)
        self.ip_list.bind("<<ListboxSelect>>", self._on_ip_select)

        # Right: editor
        right = styled_frame(split)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right.config(highlightthickness=1, highlightbackground=THEME["border"])
        tk.Label(right, text="HOST DETAILS", font=THEME["font_head"],
                 fg=THEME["accent"], bg=THEME["bg2"]).pack(pady=(4, 2))

        self.edit_vars = {}
        fields = [("IP Address", "ip"), ("Label", "label"),
                  ("Department", "department"), ("Role", "role"),
                  ("Expected Ports (comma-separated)", "expected")]
        edit_inner = styled_frame(right)
        edit_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        for lbl_text, key in fields:
            row = styled_frame(edit_inner)
            row.pack(fill=tk.X, pady=3)
            tk.Label(row, text=f"{lbl_text}:", font=THEME["font_mono"],
                     fg=THEME["text_dim"], bg=THEME["bg2"], width=32, anchor="w").pack(side=tk.LEFT)
            var = tk.StringVar()
            ent = styled_entry(row, textvariable=var, width=45)
            ent.pack(side=tk.LEFT)
            self.edit_vars[key] = var

        save_row = styled_frame(edit_inner)
        save_row.pack(fill=tk.X, pady=8)
        styled_button(save_row, "✓ Save Host Changes", self._save_host_edit).pack(side=tk.LEFT)
        self.edit_status = tk.Label(save_row, text="", font=THEME["font_mono"],
                                     fg=THEME["accent3"], bg=THEME["bg2"])
        self.edit_status.pack(side=tk.LEFT, padx=10)

        # ── Required departments ──
        section_header(f, "REQUIRED DEPARTMENTS")
        req_frame = styled_frame(f)
        req_frame.pack(fill=tk.X, padx=14, pady=(4, 14))

        row = styled_frame(req_frame)
        row.pack(fill=tk.X)
        tk.Label(row, text="Departments (comma-separated):", font=THEME["font_mono"],
                 fg=THEME["text_dim"], bg=THEME["bg2"]).pack(side=tk.LEFT)
        self.req_depts_var = tk.StringVar(
            value=", ".join(sorted(self.app.required_departments))
        )
        ent = styled_entry(row, textvariable=self.req_depts_var, width=70)
        ent.pack(side=tk.LEFT, padx=6)
        styled_button(row, "Apply", self._apply_req_depts).pack(side=tk.LEFT)

        self._refresh_ip_list()

    def _refresh_ip_list(self):
        self.ip_list.delete(0, tk.END)
        for ip in sorted(self.app.known_systems.keys()):
            label = self.app.known_systems[ip].get("label", "")
            self.ip_list.insert(tk.END, f"{ip}  [{label}]")

    def _on_ip_select(self, event):
        sel = self.ip_list.curselection()
        if not sel:
            return
        raw = self.ip_list.get(sel[0])
        ip = raw.split("  [")[0].strip()
        info = self.app.known_systems.get(ip, {})
        self.edit_vars["ip"].set(ip)
        self.edit_vars["label"].set(info.get("label", ""))
        self.edit_vars["department"].set(info.get("department", ""))
        self.edit_vars["role"].set(info.get("role", ""))
        ports = info.get("expected_services", set())
        self.edit_vars["expected"].set(", ".join(str(p) for p in sorted(ports)))
        self.edit_status.config(text="")

    def _save_host_edit(self):
        ip = self.edit_vars["ip"].get().strip()
        if not ip:
            messagebox.showerror("Validation", "IP address cannot be empty.")
            return
        try:
            raw_ports = self.edit_vars["expected"].get().strip()
            ports = set(int(p.strip()) for p in raw_ports.split(",") if p.strip()) if raw_ports else set()
        except ValueError:
            messagebox.showerror("Validation", "Expected ports must be integers.")
            return

        self.app.known_systems[ip] = {
            "label": self.edit_vars["label"].get().strip(),
            "department": self.edit_vars["department"].get().strip(),
            "role": self.edit_vars["role"].get().strip(),
            "expected_services": ports,
        }
        self._refresh_ip_list()
        self.edit_status.config(text=f"✓ Saved {ip}")

    def _add_host(self):
        for key in self.edit_vars:
            self.edit_vars[key].set("")
        self.edit_vars["ip"].set("192.168.100.")
        self.edit_status.config(text="Enter details and click 'Save Host Changes'")

    def _remove_host(self):
        sel = self.ip_list.curselection()
        if not sel:
            return
        raw = self.ip_list.get(sel[0])
        ip = raw.split("  [")[0].strip()
        if messagebox.askyesno("Confirm", f"Remove {ip} from known systems?"):
            self.app.known_systems.pop(ip, None)
            self._refresh_ip_list()

    def _load_map(self):
        path = filedialog.askopenfilename(title="Load System Map",
                                           filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, "r") as f:
                raw = json.load(f)
            new_map = {}
            for ip, info in raw.items():
                new_map[ip] = {
                    "label": info.get("label", ""),
                    "department": info.get("department", ""),
                    "role": info.get("role", ""),
                    "expected_services": set(info.get("expected_services", [])),
                }
            self.app.known_systems = new_map
            self._refresh_ip_list()
            messagebox.showinfo("Loaded", f"Loaded {len(new_map)} hosts from {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    def _save_map(self):
        path = filedialog.asksaveasfilename(title="Save System Map",
                                             defaultextension=".json",
                                             filetypes=[("JSON", "*.json")])
        if not path:
            return
        serializable = {}
        for ip, info in self.app.known_systems.items():
            serializable[ip] = {
                "label": info["label"],
                "department": info["department"],
                "role": info["role"],
                "expected_services": sorted(list(info.get("expected_services", set()))),
            }
        with open(path, "w") as f:
            json.dump(serializable, f, indent=4)
        messagebox.showinfo("Saved", f"System map saved to {os.path.basename(path)}")

    def _reset_defaults(self):
        if messagebox.askyesno("Reset", "Reset to built-in Giacobeville defaults?"):
            self.app.known_systems = {
                ip: dict(info, expected_services=set(info["expected_services"]))
                for ip, info in DEFAULT_KNOWN_SYSTEMS.items()
            }
            self._refresh_ip_list()

    def _apply_req_depts(self):
        raw = self.req_depts_var.get()
        self.app.required_departments = {d.strip() for d in raw.split(",") if d.strip()}
        messagebox.showinfo("Applied", f"{len(self.app.required_departments)} required departments set.")


# ═══════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════
class ForensicSuiteApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("⬡  PCAP FORENSIC ANALYSIS SUITE")
        self.root.geometry("1350x820")
        self.root.configure(bg=THEME["bg"])
        self.root.minsize(1100, 700)

        # Shared state
        self.known_systems = {
            ip: dict(info, expected_services=set(info["expected_services"]))
            for ip, info in DEFAULT_KNOWN_SYSTEMS.items()
        }
        self.required_departments = set(DEFAULT_REQUIRED_DEPARTMENTS)
        self.analysis_results = {}

        # Shared path vars
        self.vars = {
            "pcap_dir":      tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Desktop", "networklabs", "Network_Traffic")),
            "json_output":   tk.StringVar(value="grouped_hosts.json"),
            "temporal_out":  tk.StringVar(value="temporal_coverage.json"),
            "cov_report":    tk.StringVar(value="coverage_report.txt"),
            "grouped_out":   tk.StringVar(value="advanced_grouped_hosts.txt"),
            "gap_csv_out":   tk.StringVar(value="uncovered_time_windows.csv"),
            "gap_threshold": tk.StringVar(value=str(GAP_THRESHOLD_SECONDS)),
            "max_workers":   tk.StringVar(value=str(os.cpu_count() or 4)),
        }

        self._build_ui()
        self.root.mainloop()

    def _build_ui(self):
        # ── Title bar ──
        title_bar = tk.Frame(self.root, bg=THEME["bg"], pady=10)
        title_bar.pack(fill=tk.X, padx=16)

        tk.Label(title_bar,
                 text="⬡ PCAP FORENSIC ANALYSIS SUITE",
                 font=("Courier New", 16, "bold"),
                 fg=THEME["accent"],
                 bg=THEME["bg"]).pack(side=tk.LEFT)

        tk.Label(title_bar,
                 text="Network Traffic | Service Validation | Ransomware Signals | Gap Analysis",
                 font=("Courier New", 9),
                 fg=THEME["text_dim"],
                 bg=THEME["bg"]).pack(side=tk.LEFT, padx=16)

        divider = tk.Frame(self.root, bg=THEME["border"], height=1)
        divider.pack(fill=tk.X)

        # ── Notebook ──
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Suite.TNotebook",
                         background=THEME["bg"],
                         borderwidth=0)
        style.configure("Suite.TNotebook.Tab",
                         background=THEME["bg3"],
                         foreground=THEME["text_dim"],
                         font=("Courier New", 10, "bold"),
                         padding=(14, 6),
                         borderwidth=0)
        style.map("Suite.TNotebook.Tab",
                  background=[("selected", THEME["bg2"])],
                  foreground=[("selected", THEME["accent"])])

        nb = ttk.Notebook(self.root, style="Suite.TNotebook")
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        tabs = [
            ("▶  ANALYZER",       AnalyzerTab),
            ("◈  VISUALIZER",     VisualizerTab),
            ("◷  GAP REPORT",     GapReportTab),
            ("⬡  SYSTEM MAP",     SystemMapTab),
        ]

        for tab_label, TabClass in tabs:
            tab_obj = TabClass(nb, self)
            nb.add(tab_obj.frame, text=tab_label)

        # ── Status bar ──
        status_bar = tk.Frame(self.root, bg=THEME["bg"], pady=3)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Frame(status_bar, bg=THEME["border"], height=1).pack(fill=tk.X)
        tk.Label(status_bar,
                 text="  Scapy: " + ("✓ Available" if SCAPY_AVAILABLE else "✗ Not installed — pip install scapy"),
                 font=("Courier New", 8),
                 fg=THEME["accent3"] if SCAPY_AVAILABLE else THEME["danger"],
                 bg=THEME["bg"]).pack(side=tk.LEFT)
        tk.Label(status_bar,
                 text=f"  Workers: {os.cpu_count()}  |  Python multiprocessing enabled",
                 font=("Courier New", 8),
                 fg=THEME["text_dim"],
                 bg=THEME["bg"]).pack(side=tk.LEFT, padx=10)


# ═══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    ForensicSuiteApp()
