#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cisco Network Device Hardening Auditor
Based on enterprise security best practices
Read-only assessment tool with detailed reporting
"""

import os
import re
import sys
import time
import json
import csv
import logging
import argparse
import socket
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from dotenv import load_dotenv
import paramiko
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm
from rich import print as rprint

# Set UTF-8 encoding for Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

# Load environment variables
load_dotenv()

console = Console()

class CiscoSecurityAuditor:
    """Network Device Security Auditor - Read-only assessment tool"""

    def __init__(self, args=None):
        self.ssh = None
        self.channel = None
        self.host = os.getenv("DEVICE_IP")
        self.username = os.getenv("SSH_USERNAME")
        self.password = os.getenv("SSH_PASSWORD")
        self.audit_results = []
        self.device_info = {}
        self.full_config = None
        self.platform = "Unknown"  # IOS, NX-OS, IOS-XR

        # Command-line arguments
        self.args = args if args else type('obj', (object,), {
            'non_interactive': False,
            'output': '.',
            'format': 'json',
            'verbose': False,
            'dry_run': False,
            'email': False
        })()

        # Configure logging
        log_level = logging.DEBUG if self.args.verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def display_banner(self):
        """Display security auditor banner"""
        banner = """
        ===============================================================

                CISCO NETWORK DEVICE HARDENING AUDITOR

             Enterprise Security Posture Assessment Tool
                        Read-Only Audit Mode

        ===============================================================
        """
        console.print(Panel(banner, style="bold cyan"))

    def connect(self, retries=3):
        """Establish SSH connection to the device with retry logic"""
        if not all([self.host, self.username, self.password]):
            console.print("[bold red]✗[/bold red] Missing credentials in .env file")
            console.print("[yellow]Required: DEVICE_IP, SSH_USERNAME, SSH_PASSWORD[/yellow]")
            return False

        console.print(f"\n[bold]Target Device:[/bold] {self.host}")
        console.print(f"[bold]Username:[/bold] {self.username}")

        # Connection retry logic with exponential backoff
        for attempt in range(retries):
            try:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Establishing secure SSH connection..."),
                    transient=True
                ) as progress:
                    progress.add_task("connecting", total=None)

                    self.ssh = paramiko.SSHClient()
                    self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    self.ssh.connect(
                        hostname=self.host,
                        username=self.username,
                        password=self.password,
                        look_for_keys=False,
                        allow_agent=False,
                        timeout=15,
                        auth_timeout=15
                    )

                    self.channel = self.ssh.invoke_shell()
                    time.sleep(1)
                    self._clear_buffer()

                    # Disable paging
                    self.channel.send("terminal length 0\n")
                    time.sleep(0.5)
                    self._clear_buffer()

                console.print("[bold green]✓[/bold green] Successfully connected to device")
                return True

            except paramiko.AuthenticationException:
                console.print("[bold red]✗[/bold red] Authentication failed - Check credentials")
                return False
            except (paramiko.SSHException, socket.timeout, Exception) as e:
                if attempt < retries - 1:
                    wait = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                    logging.warning(f"Connection failed, retrying in {wait}s... ({str(e)})")
                    console.print(f"[yellow]⚠[/yellow] Connection attempt {attempt + 1} failed, retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    console.print(f"[bold red]✗[/bold red] Connection failed after {retries} attempts: {str(e)}")
                    return False

        return False

    def _clear_buffer(self, timeout=2):
        """Clear the channel buffer"""
        output = ""
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            if self.channel.recv_ready():
                chunk = self.channel.recv(8192).decode('utf-8', errors='ignore')
                output += chunk
                if any(p in chunk for p in ['#', '>']):
                    break
            else:
                time.sleep(0.1)
        return output

    def run_command(self, command, timeout=10, delay=0.5):
        """Execute command with error handling and rate limiting"""
        if self.args.dry_run:
            console.print(f"[dim]Would execute: {command}[/dim]")
            return ""

        try:
            logging.debug(f"Executing command: {command}")
            self.channel.send(command + "\n")
            time.sleep(delay)  # Rate limiting
            output = self._clear_buffer(timeout)

            # Check for command errors
            if any(err in output.lower() for err in ['invalid', 'incomplete', 'ambiguous', '% ']):
                logging.warning(f"Command '{command}' may have returned an error")

            return output

        except socket.timeout:
            logging.error(f"Timeout executing: {command}")
            console.print(f"[red]⚠ Timeout executing: {command}[/red]")
            return ""
        except Exception as e:
            logging.error(f"Failed to execute '{command}': {e}")
            console.print(f"[red]Error executing command: {str(e)}[/red]")
            return ""

    def detect_platform(self):
        """Detect Cisco platform (IOS/IOS-XE, NX-OS, IOS-XR)"""
        console.print("\n[bold cyan]=== Platform Detection ===[/bold cyan]")

        version_output = self.run_command("show version")

        # Detect platform
        if "NX-OS" in version_output or "Nexus" in version_output:
            self.platform = "NX-OS"
        elif "IOS XR" in version_output:
            self.platform = "IOS-XR"
        elif "IOS" in version_output or "IOS-XE" in version_output:
            self.platform = "IOS"
        else:
            self.platform = "Unknown"

        console.print(f"[bold]Detected Platform:[/bold] [yellow]{self.platform}[/yellow]")
        logging.info(f"Detected platform: {self.platform}")

        return self.platform

    def gather_device_info(self):
        """Collect device identification information with robust parsing"""
        console.print("\n[bold cyan]=== Device Information Gathering ===[/bold cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Collecting device details..."),
            transient=True
        ) as progress:
            progress.add_task("gathering", total=None)

            # Get hostname - multiple patterns
            hostname_output = self.run_command("show running-config | include hostname")
            hostname_patterns = [
                r'hostname\s+(\S+)',
                r'^hostname\s+(.+)$'
            ]
            hostname = "Unknown"
            for pattern in hostname_patterns:
                match = re.search(pattern, hostname_output, re.IGNORECASE | re.MULTILINE)
                if match:
                    hostname = match.group(1).strip()
                    break
            self.device_info['hostname'] = hostname

            # Get version info
            version_output = self.run_command("show version")

            # Parse version - multiple patterns
            version_patterns = [
                r'Version\s+([^\s,\)]+)',
                r'Cisco\s+IOS\s+Software[^,]*,\s+Version\s+([^\s,]+)',
                r'Software\s+Version\s+([^\s,]+)',
                r'System\s+version:\s+([^\s,]+)'
            ]
            version = "Unknown"
            for pattern in version_patterns:
                match = re.search(pattern, version_output, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break
            self.device_info['ios_version'] = version

            # Parse model - multiple patterns
            model_patterns = [
                r'cisco\s+(\S+)\s+\(',           # IOS format: cisco WS-C3850 (
                r'Model\s+number\s*:\s*(\S+)',   # Alt format
                r'Hardware:\s+(\S+)',            # NX-OS format
                r'cisco\s+(\S+)\s+processor',    # Alt IOS format
                r'Product\s+Name:\s+(\S+)'       # Another variant
            ]
            model = "Unknown"
            for pattern in model_patterns:
                match = re.search(pattern, version_output, re.IGNORECASE)
                if match:
                    model = match.group(1)
                    break
            self.device_info['model'] = model

            # Parse uptime - multiple patterns
            uptime_patterns = [
                r'uptime is\s+(.+?)(?:\n|$)',
                r'System\s+uptime:\s+(.+?)(?:\n|$)',
                r'Uptime:\s+(.+?)(?:\n|$)'
            ]
            uptime = "Unknown"
            for pattern in uptime_patterns:
                match = re.search(pattern, version_output, re.IGNORECASE)
                if match:
                    uptime = match.group(1).strip()
                    break
            self.device_info['uptime'] = uptime

            # Store platform
            self.device_info['platform'] = self.platform

            # Get full running config for analysis (with longer timeout for large configs)
            self.full_config = self.run_command("show running-config", timeout=30, delay=2.0)

        # Display device info
        info_table = Table(title="[bold]Device Information[/bold]", show_header=True)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="yellow")

        info_table.add_row("Hostname", self.device_info['hostname'])
        info_table.add_row("Platform", self.device_info['platform'])
        info_table.add_row("Model", self.device_info['model'])
        info_table.add_row("IOS Version", self.device_info['ios_version'])
        info_table.add_row("Uptime", self.device_info['uptime'])
        info_table.add_row("IP Address", self.host)

        console.print(info_table)

    def audit_access_security(self):
        """Audit access security controls"""
        console.print("\n[bold cyan]=== Access Security Assessment ===[/bold cyan]")

        checks = [
            {
                "name": "Password Encryption",
                "command": "show running-config | include service password-encryption",
                "check": lambda out: "service password-encryption" in out.lower(),
                "risk": "HIGH",
                "impact": "Passwords stored in cleartext are visible to anyone with config access",
                "recommendation": "Enable: service password-encryption"
            },
            {
                "name": "SSH Version 2 Only",
                "command": "show ip ssh",
                "check": lambda out: "version 2.0" in out.lower() and "version 1.99" not in out.lower(),
                "risk": "HIGH",
                "impact": "SSHv1 has known cryptographic vulnerabilities",
                "recommendation": "Configure: ip ssh version 2"
            },
            {
                "name": "Telnet Disabled",
                "command": "show running-config | section line vty",
                "check": lambda out: "transport input ssh" in out.lower() and "telnet" not in out.lower(),
                "risk": "CRITICAL",
                "impact": "Telnet transmits credentials in cleartext over the network",
                "recommendation": "Configure: line vty 0 15 -> transport input ssh"
            },
            {
                "name": "Login Banner Configured",
                "command": "show running-config | begin banner",
                "check": lambda out: "banner" in out.lower() and ("login" in out.lower() or "motd" in out.lower()),
                "risk": "LOW",
                "impact": "Legal warning banners establish unauthorized access policy",
                "recommendation": "Configure: banner login # [warning message] #"
            },
            {
                "name": "Exec Timeout Configured",
                "command": "show running-config | include exec-timeout",
                "check": lambda out: bool(re.search(r'exec-timeout\s+\d+', out, re.IGNORECASE)),
                "risk": "MEDIUM",
                "impact": "Idle sessions can be exploited if left unattended",
                "recommendation": "Configure: line vty 0 15 -> exec-timeout 10 0"
            },
            {
                "name": "Strong Password Policy",
                "command": "show running-config | include password policy",
                "check": lambda out: "password policy" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Weak passwords are susceptible to brute-force attacks",
                "recommendation": "Configure: password policy strength 4, min-length 10"
            },
            {
                "name": "SSH Timeout Configured",
                "command": "show running-config | include ip ssh time-out",
                "check": lambda out: "ip ssh time-out" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Unresponsive SSH sessions consume resources",
                "recommendation": "Configure: ip ssh time-out 60"
            },
            {
                "name": "SSH Authentication Retries Limited",
                "command": "show ip ssh",
                "check": lambda out: bool(re.search(r'retries\s+[1-9]', out, re.IGNORECASE)),
                "risk": "MEDIUM",
                "impact": "Unlimited retries enable password guessing attacks",
                "recommendation": "Configure: ip ssh authentication-retries 3"
            }
        ]

        self._run_checks("Access Security", checks)

    def audit_management_plane(self):
        """Audit management plane security"""
        console.print("\n[bold cyan]=== Management Plane Security Assessment ===[/bold cyan]")

        checks = [
            {
                "name": "NTP Authentication",
                "command": "show running-config | include ntp",
                "check": lambda out: "ntp authenticate" in out.lower(),
                "risk": "HIGH",
                "impact": "Unauthenticated NTP can be spoofed, causing time-based attacks",
                "recommendation": "Configure: ntp authenticate, ntp authentication-key, ntp trusted-key"
            },
            {
                "name": "Syslog Configuration",
                "command": "show running-config | include logging",
                "check": lambda out: "logging host" in out.lower() or "logging server" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Without centralized logging, security events may go undetected",
                "recommendation": "Configure: logging host [syslog-server], logging trap informational"
            },
            {
                "name": "SNMPv3 Security",
                "command": "show running-config | include snmp",
                "check": lambda out: "snmp-server user" in out.lower() and "v3" in out.lower() and "priv" in out.lower(),
                "risk": "HIGH",
                "impact": "SNMPv1/v2c community strings transmitted in cleartext",
                "recommendation": "Configure: snmp-server user [user] [group] v3 auth sha [pass] priv aes 128 [key]"
            },
            {
                "name": "Management ACL",
                "command": "show running-config | section line vty",
                "check": lambda out: bool(re.search(r'access-class\s+\S+\s+in', out, re.IGNORECASE)),
                "risk": "HIGH",
                "impact": "Unrestricted management access from any network increases attack surface",
                "recommendation": "Configure: access-list [#] permit [mgmt-network], line vty 0 15 -> access-class [#] in"
            },
            {
                "name": "Logging Timestamps",
                "command": "show running-config | include service timestamps",
                "check": lambda out: "service timestamps log datetime" in out.lower(),
                "risk": "LOW",
                "impact": "Accurate timestamps critical for incident response and correlation",
                "recommendation": "Configure: service timestamps log datetime msec show-timezone"
            }
        ]

        self._run_checks("Management Plane Security", checks)

    def audit_service_hardening(self):
        """Audit unnecessary services"""
        console.print("\n[bold cyan]=== Service Hardening Assessment ===[/bold cyan]")

        checks = [
            {
                "name": "HTTP Server Disabled",
                "command": "show running-config | include ip http",
                "check": lambda out: "no ip http server" in out.lower(),
                "risk": "HIGH",
                "impact": "HTTP server provides unauthenticated access to device information",
                "recommendation": "Configure: no ip http server"
            },
            {
                "name": "HTTPS Server Status",
                "command": "show running-config | include ip http secure-server",
                "check": lambda out: "no ip http secure-server" in out.lower() or "ip http secure-server" not in out.lower(),
                "risk": "MEDIUM",
                "impact": "If HTTPS not required for management, disable to reduce attack surface",
                "recommendation": "Configure: no ip http secure-server (unless required)"
            },
            {
                "name": "CDP Global Status",
                "command": "show cdp",
                "check": lambda out: "cdp is not enabled" in out.lower(),
                "risk": "MEDIUM",
                "impact": "CDP discloses device information to potential attackers on local network",
                "recommendation": "Configure: no cdp run (or disable per-interface on untrusted ports)"
            },
            {
                "name": "LLDP Global Status",
                "command": "show lldp",
                "check": lambda out: "lldp is not enabled" in out.lower(),
                "risk": "MEDIUM",
                "impact": "LLDP discloses network topology information",
                "recommendation": "Configure: no lldp run (or disable per-interface on untrusted ports)"
            },
            {
                "name": "Finger Service Disabled",
                "command": "show running-config | include ip finger",
                "check": lambda out: "no ip finger" in out.lower(),
                "risk": "LOW",
                "impact": "Finger service can leak user information",
                "recommendation": "Configure: no ip finger"
            },
            {
                "name": "Source Routing Disabled",
                "command": "show running-config | include ip source-route",
                "check": lambda out: "no ip source-route" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Source routing can be used to bypass network security controls",
                "recommendation": "Configure: no ip source-route"
            },
            {
                "name": "PAD Service Disabled",
                "command": "show running-config | include service pad",
                "check": lambda out: "no service pad" in out.lower(),
                "risk": "LOW",
                "impact": "PAD service is legacy and rarely needed",
                "recommendation": "Configure: no service pad"
            }
        ]

        self._run_checks("Service Hardening", checks)

    def audit_network_security(self):
        """Audit Layer 2 and network security features"""
        console.print("\n[bold cyan]=== Network Security Features Assessment ===[/bold cyan]")

        checks = [
            {
                "name": "Port Security Status",
                "command": "show port-security",
                "check": lambda out: "secure port" in out.lower() and "maxsecureaddr" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Unauthorized devices can connect to access ports without restriction",
                "recommendation": "Configure: switchport port-security on access ports"
            },
            {
                "name": "DHCP Snooping",
                "command": "show running-config | include ip dhcp snooping",
                "check": lambda out: "ip dhcp snooping" in out.lower() and "ip dhcp snooping vlan" in out.lower(),
                "risk": "HIGH",
                "impact": "Rogue DHCP servers can redirect traffic and perform MITM attacks",
                "recommendation": "Configure: ip dhcp snooping, ip dhcp snooping vlan [vlan-range]"
            },
            {
                "name": "Dynamic ARP Inspection",
                "command": "show running-config | include ip arp inspection",
                "check": lambda out: "ip arp inspection vlan" in out.lower(),
                "risk": "HIGH",
                "impact": "ARP spoofing enables man-in-the-middle attacks",
                "recommendation": "Configure: ip arp inspection vlan [vlan-range]"
            },
            {
                "name": "IP Source Guard",
                "command": "show running-config | include ip verify source",
                "check": lambda out: "ip verify source" in out.lower(),
                "risk": "MEDIUM",
                "impact": "IP spoofing can bypass network access controls",
                "recommendation": "Configure: ip verify source on access ports"
            },
            {
                "name": "Storm Control",
                "command": "show running-config | include storm-control",
                "check": lambda out: "storm-control" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Broadcast storms can cause network-wide denial of service",
                "recommendation": "Configure: storm-control broadcast/multicast level on access ports"
            },
            {
                "name": "BPDU Guard",
                "command": "show running-config | include spanning-tree",
                "check": lambda out: bool(re.search(r'spanning-tree.*bpduguard', out, re.IGNORECASE)),
                "risk": "HIGH",
                "impact": "Rogue switches can cause spanning-tree topology manipulation",
                "recommendation": "Configure: spanning-tree portfast bpduguard default"
            },
            {
                "name": "Root Guard",
                "command": "show running-config | include spanning-tree guard root",
                "check": lambda out: "spanning-tree guard root" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Unauthorized devices can become root bridge and disrupt network",
                "recommendation": "Configure: spanning-tree guard root on non-root ports"
            },
            {
                "name": "Loop Guard",
                "command": "show running-config | include loopguard",
                "check": lambda out: "spanning-tree loopguard default" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Unidirectional link failures can cause forwarding loops",
                "recommendation": "Configure: spanning-tree loopguard default"
            },
            {
                "name": "Native VLAN Security",
                "command": "show interfaces trunk",
                "check": lambda out: self._check_native_vlan(out),
                "risk": "MEDIUM",
                "impact": "Default VLAN 1 on trunks vulnerable to VLAN hopping attacks",
                "recommendation": "Configure: switchport trunk native vlan [unused-vlan] on trunks"
            }
        ]

        self._run_checks("Network Security Features", checks)

    def audit_control_plane(self):
        """Audit control plane protection"""
        console.print("\n[bold cyan]=== Control Plane Security Assessment ===[/bold cyan]")

        checks = [
            {
                "name": "Control Plane Policing",
                "command": "show running-config | section control-plane",
                "check": lambda out: "control-plane" in out.lower() and "service-policy" in out.lower(),
                "risk": "HIGH",
                "impact": "Control plane vulnerable to DoS attacks affecting device stability",
                "recommendation": "Configure: control-plane, service-policy input [policy-name]"
            },
            {
                "name": "CPU Protection",
                "command": "show running-config | include control-plane",
                "check": lambda out: "control-plane" in out.lower(),
                "risk": "HIGH",
                "impact": "Unprotected CPU can be overwhelmed by malicious traffic",
                "recommendation": "Implement rate-limiting policies for control plane traffic"
            }
        ]

        self._run_checks("Control Plane Security", checks)

    def audit_aaa(self):
        """Audit AAA configuration"""
        console.print("\n[bold cyan]=== AAA & Authentication Assessment ===[/bold cyan]")

        checks = [
            {
                "name": "AAA New Model Enabled",
                "command": "show running-config | include aaa new-model",
                "check": lambda out: "aaa new-model" in out.lower(),
                "risk": "HIGH",
                "impact": "Without AAA, centralized authentication and accounting unavailable",
                "recommendation": "Configure: aaa new-model"
            },
            {
                "name": "TACACS+ Configuration",
                "command": "show running-config | include tacacs",
                "check": lambda out: "tacacs server" in out.lower() or "tacacs-server host" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Local authentication only, no centralized identity management",
                "recommendation": "Configure: tacacs server [name], address ipv4 [ip]"
            },
            {
                "name": "AAA Authentication",
                "command": "show running-config | include aaa authentication",
                "check": lambda out: "aaa authentication login" in out.lower(),
                "risk": "HIGH",
                "impact": "No centralized authentication policy enforced",
                "recommendation": "Configure: aaa authentication login default group tacacs+ local"
            },
            {
                "name": "AAA Authorization",
                "command": "show running-config | include aaa authorization",
                "check": lambda out: "aaa authorization" in out.lower(),
                "risk": "MEDIUM",
                "impact": "Command authorization not enforced, users have unlimited access",
                "recommendation": "Configure: aaa authorization exec default group tacacs+ local"
            },
            {
                "name": "AAA Accounting",
                "command": "show running-config | include aaa accounting",
                "check": lambda out: "aaa accounting" in out.lower(),
                "risk": "MEDIUM",
                "impact": "User actions not logged for audit trail and compliance",
                "recommendation": "Configure: aaa accounting exec/commands default start-stop group tacacs+"
            }
        ]

        self._run_checks("AAA Configuration", checks)

    def _check_native_vlan(self, output):
        """Check if native VLAN is not VLAN 1 on trunk ports"""
        if not output or "invalid" in output.lower():
            return True  # Command not supported or no trunks
        if "native vlan" not in output.lower():
            return True  # No trunk info
        # Check for "native vlan 1" which is risky
        return not re.search(r'native vlan\s+1\s', output, re.IGNORECASE)

    def _run_checks(self, category, checks):
        """Execute a list of security checks"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            transient=False
        ) as progress:
            task = progress.add_task(f"Running {len(checks)} checks...", total=len(checks))

            for check in checks:
                output = self.run_command(check['command'])
                passed = check['check'](output)

                self.audit_results.append({
                    'category': category,
                    'name': check['name'],
                    'risk': check['risk'],
                    'impact': check['impact'],
                    'recommendation': check['recommendation'],
                    'passed': passed,
                    'output': output[:500]  # Store sample output
                })

                progress.advance(task)
                time.sleep(0.3)  # Rate limiting

    def generate_report(self):
        """Generate comprehensive audit report"""
        console.print("\n[bold cyan]====================================================[/bold cyan]")
        console.print("[bold cyan]           SECURITY AUDIT REPORT                    [/bold cyan]")
        console.print("[bold cyan]====================================================[/bold cyan]\n")

        # Summary statistics
        total_checks = len(self.audit_results)
        passed_checks = sum(1 for r in self.audit_results if r['passed'])
        failed_checks = total_checks - passed_checks
        compliance_score = round((passed_checks / total_checks * 100) if total_checks > 0 else 0, 1)

        # Summary table
        summary_table = Table(title="[bold]Audit Summary[/bold]", show_header=True)
        summary_table.add_column("Metric", style="cyan", width=30)
        summary_table.add_column("Value", style="yellow", width=20)

        summary_table.add_row("Total Checks Performed", str(total_checks))
        summary_table.add_row("Checks Passed", f"[green]{passed_checks}[/green]")
        summary_table.add_row("Checks Failed", f"[red]{failed_checks}[/red]")
        summary_table.add_row("Compliance Score", f"{compliance_score}%")

        # Compliance color coding
        if compliance_score >= 90:
            compliance_status = "[bold green]EXCELLENT[/bold green]"
        elif compliance_score >= 75:
            compliance_status = "[bold yellow]GOOD[/bold yellow]"
        elif compliance_score >= 60:
            compliance_status = "[bold yellow]NEEDS IMPROVEMENT[/bold yellow]"
        else:
            compliance_status = "[bold red]CRITICAL - IMMEDIATE ACTION REQUIRED[/bold red]"

        summary_table.add_row("Overall Status", compliance_status)
        console.print(summary_table)

        # Category breakdown
        console.print("\n[bold]Security Category Breakdown[/bold]")
        category_table = Table(show_header=True)
        category_table.add_column("Category", style="cyan", width=35)
        category_table.add_column("Passed", style="green", width=10)
        category_table.add_column("Failed", style="red", width=10)
        category_table.add_column("Score", style="yellow", width=10)

        categories = {}
        for result in self.audit_results:
            cat = result['category']
            if cat not in categories:
                categories[cat] = {'passed': 0, 'failed': 0}
            if result['passed']:
                categories[cat]['passed'] += 1
            else:
                categories[cat]['failed'] += 1

        for cat, stats in categories.items():
            total = stats['passed'] + stats['failed']
            score = round((stats['passed'] / total * 100) if total > 0 else 0, 1)
            category_table.add_row(cat, str(stats['passed']), str(stats['failed']), f"{score}%")

        console.print(category_table)

        # Failed checks detail
        failed_results = [r for r in self.audit_results if not r['passed']]

        if failed_results:
            console.print("\n[bold red]=== FINDINGS - SECURITY ISSUES DETECTED ===[/bold red]\n")

            for idx, result in enumerate(failed_results, 1):
                risk_color = {
                    'CRITICAL': 'bold red',
                    'HIGH': 'red',
                    'MEDIUM': 'yellow',
                    'LOW': 'blue'
                }.get(result['risk'], 'white')

                finding_panel = f"""
[bold]CHECK:[/bold] {result['name']}
[bold]CATEGORY:[/bold] {result['category']}
[bold]RISK LEVEL:[/bold] [{risk_color}]{result['risk']}[/{risk_color}]

[bold]IMPACT:[/bold]
{result['impact']}

[bold]RECOMMENDATION:[/bold]
{result['recommendation']}

[bold]AUTOMATION:[/bold]
Verify with: {self._get_verification_command(result['name'])}
                """

                console.print(Panel(finding_panel, border_style=risk_color, title=f"Finding #{idx}"))

        else:
            console.print("\n[bold green]✓ EXCELLENT - All security checks passed![/bold green]")

        # Risk summary
        risk_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for result in failed_results:
            risk_summary[result['risk']] = risk_summary.get(result['risk'], 0) + 1

        console.print("\n[bold]Risk Distribution[/bold]")
        risk_table = Table(show_header=True)
        risk_table.add_column("Risk Level", style="cyan")
        risk_table.add_column("Count", style="yellow")

        for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = risk_summary[risk_level]
            if count > 0:
                risk_color = {
                    'CRITICAL': 'bold red',
                    'HIGH': 'red',
                    'MEDIUM': 'yellow',
                    'LOW': 'blue'
                }.get(risk_level, 'white')
                risk_table.add_row(f"[{risk_color}]{risk_level}[/{risk_color}]", str(count))

        console.print(risk_table)

    def _get_verification_command(self, check_name):
        """Get the verification command for a specific check"""
        command_map = {
            "Password Encryption": "show running-config | include service password-encryption",
            "SSH Version 2 Only": "show ip ssh",
            "Telnet Disabled": "show running-config | section line vty",
            "Login Banner Configured": "show running-config | begin banner",
            "Exec Timeout Configured": "show running-config | include exec-timeout",
            "NTP Authentication": "show running-config | include ntp",
            "DHCP Snooping": "show ip dhcp snooping",
            "Dynamic ARP Inspection": "show ip arp inspection",
        }
        return command_map.get(check_name, "show running-config")

    def _generate_audit_summary(self, filename, report_data, timestamp):
        """Generate AUDIT_SUMMARY markdown file (REQUIRED per CLAUDE.md)"""
        failed_results = [r for r in self.audit_results if not r['passed']]
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for result in failed_results:
            risk_counts[result['risk']] = risk_counts.get(result['risk'], 0) + 1

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Security Audit Summary Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"---\n\n")

            # Device Information
            f.write(f"## Device Information\n\n")
            f.write(f"| Property | Value |\n")
            f.write(f"|----------|-------|\n")
            f.write(f"| Hostname | {report_data['device_info']['hostname']} |\n")
            f.write(f"| IP Address | {report_data['device_info']['ip_address']} |\n")
            f.write(f"| Platform | {report_data['device_info']['platform']} |\n")
            f.write(f"| Model | {report_data['device_info']['model']} |\n")
            f.write(f"| IOS Version | {report_data['device_info']['version']} |\n")
            f.write(f"| Audit Date | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |\n\n")

            # Executive Summary
            f.write(f"## Executive Summary\n\n")
            compliance_score = report_data['summary']['compliance_score']
            status = 'CRITICAL - IMMEDIATE ACTION REQUIRED' if compliance_score < 60 else 'NEEDS IMPROVEMENT' if compliance_score < 75 else 'GOOD' if compliance_score < 90 else 'EXCELLENT'
            f.write(f"**Overall Compliance Score:** {compliance_score}%\n\n")
            f.write(f"**Status:** {status}\n\n")
            f.write(f"### Summary Statistics\n\n")
            f.write(f"- **Total Checks:** {report_data['summary']['total_checks']}\n")
            f.write(f"- **Passed:** {report_data['summary']['passed']}\n")
            f.write(f"- **Failed:** {report_data['summary']['failed']}\n\n")

            f.write(f"### Risk Distribution\n\n")
            f.write(f"| Risk Level | Count |\n")
            f.write(f"|------------|-------|\n")
            for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if risk_counts[risk] > 0:
                    f.write(f"| {risk} | {risk_counts[risk]} |\n")
            f.write(f"\n")

            # Detailed Findings
            f.write(f"## Detailed Findings\n\n")
            if failed_results:
                for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    risk_findings = [r for r in failed_results if r['risk'] == risk_level]
                    if risk_findings:
                        f.write(f"### {risk_level} Risk Issues\n\n")
                        for idx, result in enumerate(risk_findings, 1):
                            f.write(f"#### {idx}. {result['name']}\n\n")
                            f.write(f"**Category:** {result['category']}\n\n")
                            f.write(f"**Impact:**\n{result['impact']}\n\n")
                            f.write(f"**Recommendation:**\n{result['recommendation']}\n\n")
                            f.write(f"---\n\n")
            else:
                f.write(f"No security issues detected. All checks passed.\n\n")

            # Recommendations Summary
            f.write(f"## Recommendations Summary\n\n")
            f.write(f"Priority remediation actions based on risk level:\n\n")
            if risk_counts['CRITICAL'] > 0 or risk_counts['HIGH'] > 0:
                f.write(f"1. **IMMEDIATE:** Address {risk_counts['CRITICAL']} CRITICAL and {risk_counts['HIGH']} HIGH risk findings\n")
            if risk_counts['MEDIUM'] > 0:
                f.write(f"2. **SHORT-TERM:** Resolve {risk_counts['MEDIUM']} MEDIUM risk findings within 30 days\n")
            if risk_counts['LOW'] > 0:
                f.write(f"3. **PLANNED:** Address {risk_counts['LOW']} LOW risk findings in next maintenance window\n")
            f.write(f"\n")

            # Next Steps
            f.write(f"## Next Steps\n\n")
            f.write(f"1. Review the Pre-Deployment Checklist: `PRE_DEPLOYMENT_CHECKLIST_{report_data['device_info']['ip_address']}-{timestamp}.md`\n")
            f.write(f"2. Review remediation commands: `remediation_commands_{report_data['device_info']['ip_address']}-{timestamp}.txt`\n")
            f.write(f"3. Schedule maintenance window for critical fixes\n")
            f.write(f"4. Test remediation commands in lab environment first\n")
            f.write(f"5. Create change control ticket\n")
            f.write(f"6. Execute changes with proper backout plan\n")
            f.write(f"7. Re-run audit to verify compliance improvement\n\n")

            f.write(f"---\n\n")
            f.write(f"*Report generated by Cisco Network Device Hardening Auditor*\n")

    def _generate_pre_deployment_checklist(self, filename, report_data, timestamp):
        """Generate PRE_DEPLOYMENT_CHECKLIST markdown file (REQUIRED per CLAUDE.md)"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Pre-Deployment Checklist\n\n")
            f.write(f"**Device:** {report_data['device_info']['hostname']} ({report_data['device_info']['ip_address']})\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}\n\n")
            f.write(f"**Auditor:** [Enter Name]\n\n")
            f.write(f"---\n\n")

            f.write(f"## CRITICAL: Mandatory Pre-Deployment Steps\n\n")
            f.write(f"Complete ALL items before applying any configuration changes:\n\n")
            f.write(f"### 1. Preparation\n\n")
            f.write(f"- [ ] Change control ticket created and approved\n")
            f.write(f"- [ ] Maintenance window scheduled\n")
            f.write(f"- [ ] Network team notified\n")
            f.write(f"- [ ] Out-of-band console access verified and available\n")
            f.write(f"- [ ] Backup administrator credentials tested\n")
            f.write(f"- [ ] Full configuration backup saved to secure location\n")
            f.write(f"- [ ] Running-config saved: `copy running-config startup-config`\n\n")

            f.write(f"### 2. Lab Testing (REQUIRED)\n\n")
            f.write(f"- [ ] Lab device with same platform/version available\n")
            f.write(f"- [ ] All remediation commands tested in lab\n")
            f.write(f"- [ ] Configuration validated to not break connectivity\n")
            f.write(f"- [ ] Management access verified after changes\n")
            f.write(f"- [ ] No syntax errors encountered\n\n")

            f.write(f"### 3. Risk Assessment\n\n")
            f.write(f"- [ ] Impact on production services assessed\n")
            f.write(f"- [ ] Potential downtime documented\n")
            f.write(f"- [ ] Affected users/systems identified\n")
            f.write(f"- [ ] Business stakeholders notified\n\n")

            f.write(f"### 4. Rollback Procedures\n\n")
            f.write(f"- [ ] Configuration backup file path documented: `_______________`\n")
            f.write(f"- [ ] Rollback commands prepared and tested\n")
            f.write(f"- [ ] Rollback timeline estimated (< 5 minutes)\n")
            f.write(f"- [ ] Emergency rollback procedure: `configure replace flash:backup-config force`\n\n")

            f.write(f"---\n\n")

            f.write(f"## Critical Change Validation Steps\n\n")
            f.write(f"Execute AFTER applying configuration changes:\n\n")
            f.write(f"### Connectivity Verification\n\n")
            f.write(f"- [ ] Console access still available\n")
            f.write(f"- [ ] SSH access working: `ssh {report_data['device_info']['ip_address']}`\n")
            f.write(f"- [ ] Management interface responding to ping\n")
            f.write(f"- [ ] No error messages in logs: `show logging | include ERR`\n\n")

            f.write(f"### Configuration Verification\n\n")
            f.write(f"- [ ] All commands applied successfully\n")
            f.write(f"- [ ] No unexpected configuration changes: `show archive config differences`\n")
            f.write(f"- [ ] Configuration saved: `copy running-config startup-config`\n\n")

            f.write(f"### Service Verification\n\n")
            f.write(f"- [ ] Routing protocols stable: `show ip route summary`\n")
            f.write(f"- [ ] Spanning-tree topology stable: `show spanning-tree summary`\n")
            f.write(f"- [ ] No interface errors: `show interfaces | include error`\n")
            f.write(f"- [ ] AAA authentication working (if configured)\n")
            f.write(f"- [ ] SNMP monitoring operational (if configured)\n\n")

            f.write(f"---\n\n")

            f.write(f"## Implementation Log\n\n")
            f.write(f"**Start Time:** _______________\n\n")
            f.write(f"**Commands Applied:**\n")
            f.write(f"```\n")
            f.write(f"[Paste configuration commands here]\n")
            f.write(f"```\n\n")
            f.write(f"**Issues Encountered:**\n")
            f.write(f"- [ ] None\n")
            f.write(f"- [ ] [Describe issue]: _______________\n\n")
            f.write(f"**Resolution:**\n")
            f.write(f"_______________\n\n")
            f.write(f"**End Time:** _______________\n\n")
            f.write(f"**Total Duration:** _______________\n\n")

            f.write(f"---\n\n")

            f.write(f"## Success Criteria\n\n")
            f.write(f"Mark as SUCCESSFUL only if ALL criteria met:\n\n")
            f.write(f"- [ ] All critical and high-priority findings resolved\n")
            f.write(f"- [ ] No loss of connectivity\n")
            f.write(f"- [ ] No service disruption\n")
            f.write(f"- [ ] All validation checks passed\n")
            f.write(f"- [ ] Configuration saved to startup-config\n")
            f.write(f"- [ ] Post-change audit shows compliance improvement\n\n")

            f.write(f"**Final Status:** [ ] SUCCESS  [ ] ROLLBACK REQUIRED\n\n")

            f.write(f"**Approver Signature:** _______________  **Date:** _______________\n\n")

            f.write(f"---\n\n")
            f.write(f"*Generated by Cisco Network Device Hardening Auditor*\n")

    def _generate_remediation_commands(self, filename, report_data, timestamp):
        """Generate remediation_commands text file (REQUIRED per CLAUDE.md)"""
        failed_results = [r for r in self.audit_results if not r['passed']]

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Cisco Network Device Security Remediation Commands\n")
            f.write(f"=" * 70 + "\n\n")
            f.write(f"Device: {report_data['device_info']['hostname']} ({report_data['device_info']['ip_address']})\n")
            f.write(f"Platform: {report_data['device_info']['platform']}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"CRITICAL WARNING:\n")
            f.write(f"- Test ALL commands in lab environment first\n")
            f.write(f"- Create configuration backup before making changes\n")
            f.write(f"- Apply changes during maintenance window only\n")
            f.write(f"- Have console access available during implementation\n")
            f.write(f"- Review Pre-Deployment Checklist before proceeding\n\n")
            f.write(f"=" * 70 + "\n\n")

            # Group findings by risk level
            for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                risk_findings = [r for r in failed_results if r['risk'] == risk_level]
                if risk_findings:
                    f.write(f"\n{'#' * 70}\n")
                    f.write(f"# {risk_level} PRIORITY FIXES\n")
                    f.write(f"{'#' * 70}\n\n")

                    for idx, result in enumerate(risk_findings, 1):
                        f.write(f"--- {risk_level} #{idx}: {result['name']} ---\n\n")
                        f.write(f"Category: {result['category']}\n")
                        f.write(f"Impact: {result['impact']}\n\n")

                        # Extract configuration commands from recommendations
                        f.write(f"Configuration Commands:\n")
                        f.write(f"configure terminal\n")

                        # Parse recommendation to extract commands
                        recommendation = result['recommendation']
                        if 'Configure:' in recommendation:
                            commands = recommendation.split('Configure:')[1].strip()
                            # Clean up the command
                            commands = commands.replace('->', '\n  ')
                            f.write(f"  {commands}\n")
                        else:
                            f.write(f"  ! {recommendation}\n")

                        f.write(f"exit\n")
                        f.write(f"!\n")
                        f.write(f"! Verification command:\n")
                        f.write(f"! {self._get_verification_command(result['name'])}\n")
                        f.write(f"\n")

            # Verification section
            f.write(f"\n{'#' * 70}\n")
            f.write(f"# POST-CONFIGURATION VERIFICATION\n")
            f.write(f"{'#' * 70}\n\n")
            f.write(f"! Execute these commands to verify changes:\n\n")
            f.write(f"show running-config | section line vty\n")
            f.write(f"show ip ssh\n")
            f.write(f"show running-config | include aaa\n")
            f.write(f"show running-config | include ntp\n")
            f.write(f"show running-config | include logging\n")
            f.write(f"show running-config | include snmp\n")
            f.write(f"show running-config | section control-plane\n")
            f.write(f"show ip dhcp snooping\n")
            f.write(f"show ip arp inspection\n")
            f.write(f"show spanning-tree summary\n\n")

            # Save configuration
            f.write(f"\n{'#' * 70}\n")
            f.write(f"# SAVE CONFIGURATION\n")
            f.write(f"{'#' * 70}\n\n")
            f.write(f"! After verifying all changes:\n")
            f.write(f"copy running-config startup-config\n\n")

            # Rollback commands
            f.write(f"\n{'#' * 70}\n")
            f.write(f"# ROLLBACK COMMANDS (if needed)\n")
            f.write(f"{'#' * 70}\n\n")
            f.write(f"! Emergency rollback to previous configuration:\n")
            f.write(f"configure replace flash:backup-config force\n\n")
            f.write(f"! Or restore from startup-config:\n")
            f.write(f"copy startup-config running-config\n\n")
            f.write(f"! Manual rollback (undo specific changes):\n")
            f.write(f"configure terminal\n")
            f.write(f"  ! Use 'no' commands to reverse changes\n")
            f.write(f"  ! Example: no service password-encryption\n")
            f.write(f"exit\n\n")

            f.write(f"=" * 70 + "\n")
            f.write(f"End of Remediation Commands\n")
            f.write(f"=" * 70 + "\n")

    def send_email_report(self, report_files):
        """Send audit results via email using environment variables"""
        try:
            # Load email configuration from environment
            smtp_server = os.getenv('SMTP_SERVER')
            smtp_port = int(os.getenv('SMTP_PORT', 587))
            sender_email = os.getenv('SENDER_EMAIL')
            sender_password = os.getenv('SENDER_PASSWORD')
            recipient_email = os.getenv('RECIPIENT_EMAIL')
            sender_name = os.getenv('SENDER_NAME', 'Network Audit')

            if not all([smtp_server, sender_email, sender_password, recipient_email]):
                console.print("[bold red]✗[/bold red] Email configuration missing in .env file")
                console.print("[yellow]Required: SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL[/yellow]")
                return False

            console.print(f"\n[bold cyan]Preparing email report...[/bold cyan]")

            # Create message
            msg = MIMEMultipart()
            msg['From'] = f"{sender_name} <{sender_email}>"
            msg['To'] = recipient_email
            msg['Subject'] = f"Network Security Audit Report - {self.device_info.get('hostname', self.host)} - {datetime.now().strftime('%Y-%m-%d')}"

            # Email body with audit summary
            total_checks = len(self.audit_results)
            passed_checks = sum(1 for r in self.audit_results if r['passed'])
            failed_checks = total_checks - passed_checks
            compliance_score = round((passed_checks / total_checks * 100) if total_checks > 0 else 0, 1)

            # Count risk levels
            risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for result in self.audit_results:
                if not result['passed']:
                    risk_counts[result['risk']] = risk_counts.get(result['risk'], 0) + 1

            body = f"""
Network Security Audit Report
========================================

Device Information:
- Hostname: {self.device_info.get('hostname', 'Unknown')}
- IP Address: {self.host}
- Platform: {self.device_info.get('platform', 'Unknown')}
- Model: {self.device_info.get('model', 'Unknown')}
- IOS Version: {self.device_info.get('ios_version', 'Unknown')}
- Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Audit Summary:
========================================
Total Checks Performed: {total_checks}
Checks Passed: {passed_checks}
Checks Failed: {failed_checks}
Compliance Score: {compliance_score}%

Risk Distribution:
- CRITICAL: {risk_counts.get('CRITICAL', 0)}
- HIGH: {risk_counts['HIGH']}
- MEDIUM: {risk_counts['MEDIUM']}
- LOW: {risk_counts['LOW']}

Status: {'CRITICAL - IMMEDIATE ACTION REQUIRED' if compliance_score < 60 else 'NEEDS IMPROVEMENT' if compliance_score < 75 else 'GOOD' if compliance_score < 90 else 'EXCELLENT'}

========================================

Please review the attached detailed audit report for complete findings and remediation recommendations.

This is an automated audit report generated by Cisco Network Device Hardening Auditor.
"""

            msg.attach(MIMEText(body, 'plain'))

            # Attach report files
            if not isinstance(report_files, list):
                report_files = [report_files]

            for file_path in report_files:
                if file_path and os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header('Content-Disposition',
                                      f'attachment; filename={os.path.basename(file_path)}')
                        msg.attach(part)
                        console.print(f"[bold green]✓[/bold green] Attached: [cyan]{os.path.basename(file_path)}[/cyan]")

            # Send email
            console.print(f"[bold blue]Connecting to SMTP server {smtp_server}:{smtp_port}...[/bold blue]")
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)

            console.print(f"[bold green]✓[/bold green] Email successfully sent to: [cyan]{recipient_email}[/cyan]")
            return True

        except smtplib.SMTPAuthenticationError:
            console.print("[bold red]✗[/bold red] SMTP Authentication failed - Check email credentials")
            logging.error("SMTP Authentication failed")
            return False
        except Exception as e:
            console.print(f"[bold red]✗[/bold red] Failed to send email: {str(e)}")
            logging.error(f"Email send failed: {e}", exc_info=True)
            return False

    def export_results(self, export_format=None):
        """Export ALL required audit files per CLAUDE.md standards"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = self.device_info.get('hostname', 'unknown')
        device_identifier = self.host if hostname == 'unknown' or hostname == 'hostname' else hostname

        # Prepare report data
        total_checks = len(self.audit_results)
        passed_checks = sum(1 for r in self.audit_results if r['passed'])
        failed_checks = total_checks - passed_checks
        compliance_score = round((passed_checks / total_checks * 100) if total_checks > 0 else 0, 1)

        report_data = {
            'audit_timestamp': datetime.now().isoformat(),
            'device_info': {
                'hostname': hostname,
                'ip_address': self.host,
                'platform': self.device_info.get('platform', 'Unknown'),
                'model': self.device_info.get('model', 'Unknown'),
                'version': self.device_info.get('ios_version', 'Unknown')
            },
            'summary': {
                'total_checks': total_checks,
                'passed': passed_checks,
                'failed': failed_checks,
                'compliance_score': compliance_score
            },
            'findings': self.audit_results
        }

        # Determine output path
        output_dir = self.args.output
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        generated_files = []

        try:
            console.print("\n[bold cyan]Generating Required Audit Files (per CLAUDE.md standards)...[/bold cyan]")

            # 1. REQUIRED: Machine-Readable Audit Report (JSON)
            json_filename = os.path.join(output_dir, f"audit_report_{device_identifier}_{timestamp}.json")
            with open(json_filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            console.print(f"[bold green]✓[/bold green] JSON report: [cyan]{json_filename}[/cyan]")
            generated_files.append(json_filename)

            # 2. REQUIRED: AUDIT_SUMMARY (Comprehensive Markdown)
            summary_filename = os.path.join(output_dir, f"AUDIT_SUMMARY_{device_identifier}-{timestamp}.md")
            self._generate_audit_summary(summary_filename, report_data, timestamp)
            console.print(f"[bold green]✓[/bold green] Audit summary: [cyan]{summary_filename}[/cyan]")
            generated_files.append(summary_filename)

            # 3. REQUIRED: PRE_DEPLOYMENT_CHECKLIST
            checklist_filename = os.path.join(output_dir, f"PRE_DEPLOYMENT_CHECKLIST_{device_identifier}-{timestamp}.md")
            self._generate_pre_deployment_checklist(checklist_filename, report_data, timestamp)
            console.print(f"[bold green]✓[/bold green] Pre-deployment checklist: [cyan]{checklist_filename}[/cyan]")
            generated_files.append(checklist_filename)

            # 4. REQUIRED: remediation_commands
            remediation_filename = os.path.join(output_dir, f"remediation_commands_{device_identifier}-{timestamp}.txt")
            self._generate_remediation_commands(remediation_filename, report_data, timestamp)
            console.print(f"[bold green]✓[/bold green] Remediation commands: [cyan]{remediation_filename}[/cyan]")
            generated_files.append(remediation_filename)

            console.print(f"\n[bold green]✓ All {len(generated_files)} required audit files generated successfully[/bold green]")

            return generated_files

        except Exception as e:
            logging.error(f"Failed to export reports: {e}")
            console.print(f"[bold red]✗[/bold red] Failed to export reports: {str(e)}")
            return None

    def disconnect(self):
        """Close SSH connection"""
        if self.ssh:
            self.ssh.close()
            console.print("\n[bold green]✓[/bold green] Disconnected from device")

    def run_audit(self):
        """Execute complete security audit"""
        self.display_banner()

        if not self.connect():
            return False

        try:
            # Detect platform first (CRITICAL per CLAUDE.md)
            self.detect_platform()

            # Gather device information
            self.gather_device_info()

            # Run all audit categories
            self.audit_access_security()
            self.audit_management_plane()
            self.audit_service_hardening()
            self.audit_network_security()
            self.audit_control_plane()
            self.audit_aaa()

            # Generate comprehensive report
            self.generate_report()

            # Export results (auto-export in non-interactive mode)
            report_files = None
            if self.args.non_interactive:
                console.print("\n[bold cyan]Auto-exporting results (non-interactive mode)[/bold cyan]")
                report_files = self.export_results()
            else:
                if Confirm.ask("\n[bold cyan]Export detailed results?[/bold cyan]", default=True):
                    report_files = self.export_results()

            # Send email if requested
            if self.args.email and report_files:
                self.send_email_report(report_files)
            elif self.args.email and not report_files:
                console.print("[bold yellow]⚠[/bold yellow] Cannot send email - no report files generated")

            return True

        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠[/bold yellow] Audit interrupted by user")
            return False
        except Exception as e:
            console.print(f"\n[bold red]✗[/bold red] Audit failed: {str(e)}")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return False
        finally:
            self.disconnect()


def main():
    """Main entry point with CLI argument parsing"""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Cisco Network Device Hardening Auditor - Enterprise Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (default)
  python cisco_audit.py

  # Non-interactive mode for automation
  python cisco_audit.py --non-interactive --format json --output ./reports/

  # Dry-run mode (show commands without executing)
  python cisco_audit.py --dry-run

  # Verbose logging
  python cisco_audit.py --verbose

  # Export to CSV
  python cisco_audit.py -n -f csv -o /var/reports/
        """
    )

    parser.add_argument('--non-interactive', '-n', action='store_true',
                       help='Run without user prompts (for CI/CD, cron jobs)')
    parser.add_argument('--output', '-o', default='.',
                       help='Output directory for reports (default: current directory)')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'markdown'],
                       default='json', help='Report format (default: json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable detailed logging')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show commands without executing (testing mode)')
    parser.add_argument('--email', '-e', action='store_true',
                       help='Email the audit results (requires email config in .env)')

    args = parser.parse_args()

    # Display banner
    console.print("\n[bold blue]Cisco Network Device Hardening Auditor[/bold blue]")
    console.print("[blue]" + "="*50 + "[/blue]\n")

    if args.dry_run:
        console.print("[bold yellow]⚠ DRY-RUN MODE - No commands will be executed[/bold yellow]\n")

    if args.non_interactive:
        console.print("[bold cyan]Running in NON-INTERACTIVE mode[/bold cyan]")
        console.print(f"[cyan]Output format: {args.format}[/cyan]")
        console.print(f"[cyan]Output directory: {args.output}[/cyan]\n")

    # Create auditor instance
    auditor = CiscoSecurityAuditor(args)

    try:
        auditor.run_audit()

        console.print("\n[bold green]===================================================[/bold green]")
        console.print("[bold green]           AUDIT COMPLETE                          [/bold green]")
        console.print("[bold green]===================================================[/bold green]\n")

    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {str(e)}[/bold red]")
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
