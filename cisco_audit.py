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

    def __init__(self):
        self.ssh = None
        self.channel = None
        self.host = os.getenv("DEVICE_IP")
        self.username = os.getenv("SSH_USERNAME")
        self.password = os.getenv("SSH_PASSWORD")
        self.audit_results = []
        self.device_info = {}
        self.full_config = None

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

    def connect(self):
        """Establish SSH connection to the device"""
        try:
            if not all([self.host, self.username, self.password]):
                console.print("[bold red]✗[/bold red] Missing credentials in .env file")
                console.print("[yellow]Required: DEVICE_IP, SSH_USERNAME, SSH_PASSWORD[/yellow]")
                return False

            console.print(f"\n[bold]Target Device:[/bold] {self.host}")
            console.print(f"[bold]Username:[/bold] {self.username}")

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
                    timeout=15
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
        except paramiko.SSHException as e:
            console.print(f"[bold red]✗[/bold red] SSH error: {str(e)}")
            return False
        except Exception as e:
            console.print(f"[bold red]✗[/bold red] Connection failed: {str(e)}")
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

    def run_command(self, command, timeout=10):
        """Execute a command and return output"""
        try:
            self.channel.send(command + "\n")
            time.sleep(0.5)
            output = self._clear_buffer(timeout)
            return output
        except Exception as e:
            console.print(f"[red]Error executing command: {str(e)}[/red]")
            return ""

    def gather_device_info(self):
        """Collect device identification information"""
        console.print("\n[bold cyan]=== Device Information Gathering ===[/bold cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Collecting device details..."),
            transient=True
        ) as progress:
            progress.add_task("gathering", total=None)

            # Get hostname
            hostname_output = self.run_command("show running-config | include hostname")
            hostname_match = re.search(r'hostname\s+(\S+)', hostname_output, re.IGNORECASE)
            self.device_info['hostname'] = hostname_match.group(1) if hostname_match else "Unknown"

            # Get version info
            version_output = self.run_command("show version")

            # Parse IOS version
            ios_match = re.search(r'Version\s+([^\s,]+)', version_output, re.IGNORECASE)
            self.device_info['ios_version'] = ios_match.group(1) if ios_match else "Unknown"

            # Parse model
            model_match = re.search(r'cisco\s+(\S+)\s+\(', version_output, re.IGNORECASE)
            if not model_match:
                model_match = re.search(r'Model\s+number\s*:\s*(\S+)', version_output, re.IGNORECASE)
            self.device_info['model'] = model_match.group(1) if model_match else "Unknown"

            # Parse uptime
            uptime_match = re.search(r'uptime is\s+(.+?)(?:\n|$)', version_output, re.IGNORECASE)
            self.device_info['uptime'] = uptime_match.group(1).strip() if uptime_match else "Unknown"

            # Get full running config for analysis
            self.full_config = self.run_command("show running-config", timeout=20)

        # Display device info
        info_table = Table(title="[bold]Device Information[/bold]", show_header=True)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="yellow")

        info_table.add_row("Hostname", self.device_info['hostname'])
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
                "recommendation": "Configure: line vty 0 15 → transport input ssh"
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
                "check": lambda out: re.search(r'exec-timeout\s+\d+', out, re.IGNORECASE),
                "risk": "MEDIUM",
                "impact": "Idle sessions can be exploited if left unattended",
                "recommendation": "Configure: line vty 0 15 → exec-timeout 10 0"
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
                "check": lambda out: re.search(r'retries\s+[1-9]', out, re.IGNORECASE),
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
                "check": lambda out: re.search(r'access-class\s+\S+\s+in', out, re.IGNORECASE),
                "risk": "HIGH",
                "impact": "Unrestricted management access from any network increases attack surface",
                "recommendation": "Configure: access-list [#] permit [mgmt-network], line vty 0 15 → access-class [#] in"
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
                "check": lambda out: re.search(r'spanning-tree.*bpduguard', out, re.IGNORECASE),
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

    def export_results(self):
        """Export audit results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{self.device_info.get('hostname', 'unknown')}_{timestamp}.json"

        report_data = {
            'audit_timestamp': datetime.now().isoformat(),
            'device_info': self.device_info,
            'summary': {
                'total_checks': len(self.audit_results),
                'passed': sum(1 for r in self.audit_results if r['passed']),
                'failed': sum(1 for r in self.audit_results if not r['passed']),
                'compliance_score': round((sum(1 for r in self.audit_results if r['passed']) / len(self.audit_results) * 100) if self.audit_results else 0, 1)
            },
            'findings': self.audit_results
        }

        try:
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            console.print(f"\n[bold green]✓[/bold green] Detailed report exported to: [cyan]{filename}[/cyan]")
        except Exception as e:
            console.print(f"[bold red]✗[/bold red] Failed to export report: {str(e)}")

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

            # Ask to export
            if Confirm.ask("\n[bold cyan]Export detailed results to JSON file?[/bold cyan]", default=True):
                self.export_results()

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
    """Main entry point"""
    console.print("\n[bold blue]Cisco Network Device Hardening Auditor[/bold blue]")
    console.print("[blue]" + "="*50 + "[/blue]\n")

    auditor = CiscoSecurityAuditor()

    try:
        auditor.run_audit()

        console.print("\n[bold green]===================================================[/bold green]")
        console.print("[bold green]           AUDIT COMPLETE                          [/bold green]")
        console.print("[bold green]===================================================[/bold green]\n")

    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {str(e)}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
