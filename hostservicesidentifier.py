from scapy.all import PcapReader, IP
from collections import defaultdict
import os
import sys
import socket


# Ephemeral range (>1024 treated as client ports)
EPHEMERAL_MIN = 1024
EPHEMERAL_MAX = 65535


def is_ephemeral(port):
    return EPHEMERAL_MIN <= port <= EPHEMERAL_MAX


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"


def analyze_pcap(file_path, debug=True):

    if debug:
        print("[DEBUG] Starting analysis...")
        print(f"[DEBUG] Checking file path: {file_path}")

    if not os.path.exists(file_path):
        print(f"[ERROR] File does not exist: {file_path}")
        sys.exit(1)

    ip_services = defaultdict(set)
    packet_count = 0

    with PcapReader(file_path) as pcap_reader:
        for packet in pcap_reader:
            packet_count += 1

            if not packet.haslayer(IP):
                continue

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            payload = bytes(ip_layer.payload)

            # TCP
            if proto == 6 and len(payload) >= 4:
                src_port = int.from_bytes(payload[0:2], byteorder='big')
                dst_port = int.from_bytes(payload[2:4], byteorder='big')

            # UDP
            elif proto == 17 and len(payload) >= 4:
                src_port = int.from_bytes(payload[0:2], byteorder='big')
                dst_port = int.from_bytes(payload[2:4], byteorder='big')

            else:
                continue

            src_is_ephemeral = is_ephemeral(src_port)
            dst_is_ephemeral = is_ephemeral(dst_port)

            # Determine service provider
            if src_is_ephemeral and not dst_is_ephemeral:
                ip_services[dst_ip].add(dst_port)

            elif dst_is_ephemeral and not src_is_ephemeral:
                ip_services[src_ip].add(src_port)

            elif not src_is_ephemeral and not dst_is_ephemeral:
                ip_services[src_ip].add(src_port)
                ip_services[dst_ip].add(dst_port)

            if debug and packet_count <= 20:
                print(f"[EARLY DEBUG] {src_ip}:{src_port} → {dst_ip}:{dst_port}")

    if debug:
        print(f"\n[DEBUG] Total packets processed: {packet_count}")
        print(f"[DEBUG] Hosts offering services: {len(ip_services)}")

    return ip_services


def print_and_save_results(ip_services, output_file="grouped_hosts_by_service_profile.txt"):

    from collections import defaultdict

    # New structure: service_profile_tuple -> list of IPs
    profile_to_ips = defaultdict(list)

    for ip, ports in ip_services.items():

        # Build sorted list of valid services for this IP
        valid_services = []
        for port in sorted(ports):
            service_name = get_service_name(port)
            if service_name != "unknown":
                valid_services.append(f"{port}({service_name})")

        if not valid_services:
            continue  # Skip hosts with only unknown services

        profile_key = tuple(valid_services)
        profile_to_ips[profile_key].append(ip)

    # Sort profiles by number of IPs (largest groups first)
    sorted_profiles = sorted(
        profile_to_ips.items(),
        key=lambda x: len(x[1]),
        reverse=True
    )

    lines = []
    lines.append("Grouped Hosts by Identical Service Profiles\n")
    lines.append("Hosts\tServices Offered")

    for services, ips in sorted_profiles:

        sorted_ips = sorted(
            ips,
            key=lambda ip: tuple(int(part) for part in ip.split('.'))
        )

        ip_string = ", ".join(sorted_ips)
        service_string = ", ".join(services)

        lines.append(f"{ip_string}\t{service_string}")

    output_text = "\n".join(lines)

    # Print to terminal
    print("\n" + output_text)

    # Save to file
    with open(output_file, "w") as f:
        f.write(output_text)

    print(f"\n[INFO] Output saved to: {output_file}")


if __name__ == "__main__":
    pcap_file = '/Users/scottgarciajr/Downloads/20110413_pcap_1 (1).pcap'
    results = analyze_pcap(pcap_file, debug=True)
    print_and_save_results(results)
