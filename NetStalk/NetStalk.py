#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Kanbdaw b import dyal les libraries li ghadi n7tajo
# We start by importing the libraries we'll need
import socket
import argparse
import re
from datetime import datetime

# Mock Vulnerability Database (Service: Version: [CVEs])
# Hada database sghir dyal l vulnerabilities, ghir bach ntestiw
# This is a small mock vulnerability database for testing purposes
MOCK_VULN_DB = {
    "vsftpd": {
        "2.3.4": ["CVE-2011-2523 (Backdoor Command Execution)"],
    },
    "Apache": {
        "2.4.29": ["CVE-2017-15715 (FilesMatch bypass)", "CVE-2018-1312 (Authentication Bypass)"],
        "2.2.8": ["CVE-2008-1680 (XSS)"]
    },
    "OpenSSH": {
        "7.4": ["CVE-2017-15906 (Username Enumeration)"],
        "6.6.1": ["CVE-2016-10009 (Multiple Vulnerabilities)"]
    },
    "nginx": {
        "1.10.3": ["CVE-2017-7529 (Integer Overflow)"]
    }
}

# Common ports and their likely services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-alt"
}


def get_banner(sock):
    """
    Tries to grab a banner from an open socket.
    Kan7awlo njbdo l'banner mn l'socket li m7lol.
    """
    try:
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner
    except socket.timeout:
        return "No banner received (timeout)"
    except Exception as e:
        return f"Error grabbing banner: {e}"

def scan_port(target_ip, port):
    """
    Scans a single port on the target IP.
    Hada function dyal port scanning l port wa7d.
    """
    try:
        # Create a new socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt
        
        # Try to connect to the target IP and port
        # Kan7awlo ntconnectaw l target IP o l'port
        result = sock.connect_ex((target_ip, port))
        
        # If the connection was successful (result is 0)
        # Ila l'connection n SUCCESS (result = 0), l'port m7lol
        if result == 0:
            banner = get_banner(sock)
            return True, banner
        else:
            return False, None
    except socket.error as e:
        # Handle socket-related errors
        # print(f"Socket error on port {port}: {e}") # Optional: for debugging
        return False, None
    except Exception as e:
        # Handle other potential errors
        # print(f"An unexpected error occurred on port {port}: {e}") # Optional: for debugging
        return False, None
    finally:
        # Ensure the socket is always closed
        if 'sock' in locals():
            sock.close()

def enumerate_service(port, banner):
    """
    Tries to identify the service and version from the banner.
    Hna kan7awlo n3arfo chno service kayn f dak l'port o l'version dyalo.
    """
    service_name = COMMON_PORTS.get(port, "Unknown")
    version = "Unknown"

    if banner and banner != "No banner received (timeout)" and not banner.startswith("Error grabbing banner"):
        # Example: Try to parse Apache version (e.g., Apache/2.4.29 (Ubuntu))
        apache_match = re.search(r"Apache(?:/| )([\d\.]+)", banner, re.IGNORECASE)
        if apache_match:
            service_name = "Apache"
            version = apache_match.group(1)
            return service_name, version

        # Example: Try to parse OpenSSH version (e.g., SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7)
        openssh_match = re.search(r"OpenSSH_([\d\w\.]+)", banner, re.IGNORECASE)
        if openssh_match:
            service_name = "OpenSSH"
            version = openssh_match.group(1).split('p')[0] # Get version before 'p' if exists
            return service_name, version

        # Example: Try to parse vsftpd version (e.g., (vsFTPd 2.3.4))
        vsftpd_match = re.search(r"vsFTPd\s+([\d\.]+)", banner, re.IGNORECASE)
        if vsftpd_match:
            service_name = "vsftpd"
            version = vsftpd_match.group(1)
            return service_name, version
        
        # Example: Try to parse nginx version
        nginx_match = re.search(r"nginx/([\d\.]+)", banner, re.IGNORECASE)
        if nginx_match:
            service_name = "nginx"
            version = nginx_match.group(1)
            return service_name, version

        # Fallback if no specific pattern matches but banner exists
        # If a common service is known for the port, use that name.
        # The banner itself might contain version info, but parsing is complex.
        # For simplicity, we'll just return the banner as potential version info.
        if service_name != "Unknown":
             # Heuristic: if banner is short and looks like a version
            if len(banner) < 30 and re.match(r"[\w\d\.\s-]+", banner):
                version = banner # Could be version or just a short banner
        else: # If port is not common, try to guess service from banner
            if "http" in banner.lower(): service_name = "HTTP"
            elif "ftp" in banner.lower(): service_name = "FTP"
            elif "ssh" in banner.lower(): service_name = "SSH"
            
    return service_name, version


def check_vulnerabilities(service_name, version):
    """
    Checks for known vulnerabilities based on service and version from the mock DB.
    Kanvérifiw ila kan chi ta2tir vulnerabilité 3la 7sab service o version.
    """
    vulnerabilities_found = []
    if service_name in MOCK_VULN_DB:
        service_vulns = MOCK_VULN_DB[service_name]
        # Check for exact version match
        if version in service_vulns:
            vulnerabilities_found.extend(service_vulns[version])
        else:
            # Check for partial matches (e.g., 2.4 matches 2.4.x)
            # This is a simplified check
            for vuln_version, cves in service_vulns.items():
                if version.startswith(vuln_version.rsplit('.', 1)[0]): # e.g. 2.4 from 2.4.29
                    vulnerabilities_found.extend(f"{cve} (potentially for version {vuln_version})" for cve in cves)
    
    # Add a note about this being a mock DB
    if not vulnerabilities_found and service_name != "Unknown" and version != "Unknown":
        return ["No specific vulnerabilities found in local mock DB for this version. Manual check recommended."]
    elif not vulnerabilities_found:
        return [] # No vulns and not enough info to suggest manual check
        
    return vulnerabilities_found

def generate_report(target_ip, scan_results):
    """
    Generates a report of the scan findings.
    F lkhr, kanjme3o kolchi f rapport.
    """
    report = f"\n--- Penetration Test Report for {target_ip} ---\n"
    report += f"Scan initiated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    if not scan_results:
        report += "No open ports or services found.\n"
        return report

    report += "Open Ports & Services:\n"
    report += "----------------------\n"
    for res in scan_results:
        report += f"[+] Port {res['port']} ({res['service_name']} - Version: {res['version']}): Open\n"
        if res['banner'] and res['banner'] != "No banner received (timeout)" and not res['banner'].startswith("Error grabbing banner"):
            report += f"    Banner: {res['banner']}\n"
        if res['vulnerabilities']:
            report += "    Potential Vulnerabilities (from mock DB):\n"
            for vuln in res['vulnerabilities']:
                report += f"      - {vuln}\n"
        else:
            if res['service_name'] != "Unknown" and res['version'] != "Unknown":
                 report += "    No vulnerabilities listed in mock DB for this specific service/version.\n"
        report += "\n"
        
    report += "--- End of Report ---\n"
    return report

def main():
    """
    Main function to drive the toolkit.
    Hada howa l'function lra2issi li kaykhdm l'toolkit.
    """
    parser = argparse.ArgumentParser(description="Simple Python Penetration Testing Toolkit")
    parser.add_argument("target_ip", help="The IP address of the target machine. (IP dyal l target)")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan (e.g., 80,443,22). Default is common ports.", default=None)
    parser.add_argument("-r", "--range", help="Port range to scan (e.g., 1-1024). Overrides --ports if both are given.", default=None)

    args = parser.parse_args()
    target_ip = args.target_ip

    # Validate IP address format (basic check)
    # kit7a9a9 mn l'format dyal l'adresse IP
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        print(f"[-] Invalid IP address format: {target_ip}")
        return

    print(f"[INFO] Starting scan on target: {target_ip}")
    
    ports_to_scan = []
    if args.range:
        try:
            start_port, end_port = map(int, args.range.split('-'))
            if not (0 < start_port <= 65535 and 0 < end_port <= 65535 and start_port <= end_port):
                raise ValueError
            ports_to_scan = range(start_port, end_port + 1)
            print(f"[INFO] Scanning port range: {start_port}-{end_port}")
        except ValueError:
            print("[-] Invalid port range format. Use START-END (e.g., 1-1024).")
            return
    elif args.ports:
        try:
            ports_to_scan = [int(p.strip()) for p in args.ports.split(',')]
            if not all(0 < p <= 65535 for p in ports_to_scan):
                raise ValueError
            print(f"[INFO] Scanning specific ports: {', '.join(map(str, ports_to_scan))}")
        except ValueError:
            print("[-] Invalid port list format. Use comma-separated numbers (e.g., 80,443).")
            return
    else:
        ports_to_scan = COMMON_PORTS.keys()
        print(f"[INFO] Scanning common ports: {', '.join(map(str, ports_to_scan))}")


    scan_results = []
    # Nchofo wach l'port m7lol wla la
    # Let's see if the port is open or not
    for port in ports_to_scan:
        print(f"[...] Scanning port {port}...")
        is_open, banner_data = scan_port(target_ip, port)
        if is_open:
            service_name, version = enumerate_service(port, banner_data)
            print(f"[+] Port {port} ({service_name} - {version}) is open.")
            if banner_data:
                print(f"    Banner: {banner_data[:100]}{'...' if len(banner_data) > 100 else ''}") # Print truncated banner
            
            vulnerabilities = check_vulnerabilities(service_name, version)
            if vulnerabilities:
                print(f"    [!] Potential Vulnerabilities Found:")
                for vuln in vulnerabilities:
                    print(f"        - {vuln}")
            
            scan_results.append({
                "port": port,
                "banner": banner_data,
                "service_name": service_name,
                "version": version,
                "vulnerabilities": vulnerabilities
            })

    report = generate_report(target_ip, scan_results)
    print(report)

    # Optionally, save the report to a file
    # enregistrer l'rapport f chi fichier
    report_filename = f"pentest_report_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[INFO] Report saved to {report_filename}")

if __name__ == "__main__":
    main()
