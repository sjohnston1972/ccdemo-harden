#!/usr/bin/env python3
"""
Cisco Switch hardening checker and remediation tool (v18)
- One progress bar per category (All mode)
- One progress bar for all selected checks (Select mode)
- Debug output via prompt or --debug flag
"""

import re
import sys
import time
import getpass
import os
import paramiko
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import print as rprint



def load_creds(creds_file: str = "creds.txt") -> dict:
    
    """Load credentials from a creds file in key=value format.

    Supported keys (case-insensitive): username, password, enablepass, enable_password.
    Lines starting with # are ignored.
    Returns a dict with any keys found.
    """
    
    creds = {}
    try:
        if os.path.exists(creds_file):
            with open(creds_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k in {"username", "password", "enablepass", "enable_password"}:
                            creds[k] = v
    except Exception as e:
        console.print(f"[yellow]warning: failed to read {creds_file}: {e}[/yellow]")
    # normalise enablepass variants
    if "enable_password" not in creds and "enablepass" in creds:
        creds["enable_password"] = creds["enablepass"]
    return creds
console = Console()

HARDENING_CHECKS = [
    {
        "category": "access security",
        "checks": [
            {
                "name": "password encryption",
                "description": "service password encryption should be enabled",
                "command": "show running-config | include service password-encryption",
                "expected": "service password-encryption",
                "remediation": "service password-encryption",
                "prompt_required": False
            },
            {
                "name": "strong password policy",
                "description": "password policy should enforce complexity",
                "command": "show running-config | include password policy",
                "expected": "password policy",
                "remediation": "password policy strength 4\npassword policy min-length 10\npassword policy max-characters 3\npassword policy min-lower-case 1\npassword policy min-upper-case 1\npassword policy min-numeric-characters 1\npassword policy min-special-characters 1",
                "prompt_required": False
            },
            {
                "name": "strong local passwords",
                "description": "local passwords should use strong encryption (type 9)",
                "command": "show running-config | include username",
                "match_pattern": r"username .+ (secret|algorithm-type) 9",
                "remediation": "username {username} privilege 15 algorithm-type sha512 secret {password}",
                "prompt_required": True,
                "prompt_message": "enter username and password for the local admin account",
                "prompt_example": "admin strongp@ssw0rd123"
            },
            {
                "name": "login banner",
                "description": "legal banner should be configured",
                "command": "show running-config | begin banner",
                "expected": "banner",
                "remediation": "banner login #\nwarning: unauthorized access to this system is prohibited\nall access and usage may be monitored and recorded\n#",
                "prompt_required": False
            },
            {
                "name": "exec timeout",
                "description": "idle session timeout should be enabled",
                "command": "show running-config | include timeout",
                "match_pattern": r"exec-timeout \d+ \d+",
                "remediation": "line vty 0 15\nexec-timeout 10 0\nline console 0\nexec-timeout 10 0",
                "prompt_required": False
            },
            {
                "name": "ssh version 2",
                "description": "only ssh version 2 should be enabled",
                "command": "show ip ssh | include version",
                "expected": "version 2.0",
                "remediation": "ip ssh version 2",
                "prompt_required": False
            },
            {
                "name": "ssh authentication retries",
                "description": "ssh authentication retries should be non-zero",
                "command": "sh ip ssh | i retries",
                "match_pattern": r"retries [1-9][0-9]*",
                "remediation": "ip ssh authentication-retries 3",
                "prompt_required": False
            },
            {
                "name": "ssh timeout",
                "description": "ssh timeout should be configured",
                "command": "show running-config | include ip ssh time-out",
                "expected": "ip ssh time-out 60",
                "remediation": "ip ssh time-out 60",
                "prompt_required": False
            },
            {
                "name": "telnet disabled",
                "description": "telnet should be disabled",
                "command": "show running-config | section line vty",
                "match_pattern": r"transport input ssh",
                "not_match_pattern": r"transport input telnet|transport input all",
                "remediation": "line vty 0 15\ntransport input ssh",
                "prompt_required": False
            },
        ]
    },
    {
        "category": "management plane security",
        "checks": [
            {
                "name": "ntp authentication",
                "description": "ntp should be configured with authentication",
                "command": "show running-config | include ntp authentication",
                "expected": "ntp authenticate",
                "remediation": "ntp authenticate\nntp authentication-key 1 md5 {ntp_key}\nntp trusted-key 1\nntp server {ntp_server} key 1",
                "prompt_required": True,
                "prompt_message": "enter ntp server and authentication key",
                "prompt_example": "10.1.1.1 n7p@uthk3y"
            },
            {
                "name": "logging configuration",
                "description": "syslog should be configured",
                "command": "show running-config | include logging host",
                "match_pattern": r"logging host \d+\.\d+\.\d+\.\d+",
                "remediation": "logging on\nlogging buffered 16384 informational\nlogging host {syslog_server}\nlogging trap informational\nlogging source-interface {source_interface}\nservice timestamps log datetime msec show-timezone",
                "prompt_required": True,
                "prompt_message": "enter syslog server ip and source interface",
                "prompt_example": "10.1.1.5 vlan10"
            },
            {
                "name": "snmp security",
                "description": "snmp v3 should be configured with authentication and privacy",
                "command": "show running-config | include snmp-server",
                "match_pattern": r"snmp-server user .+ .+ v3 auth .+ priv",
                "remediation": "no snmp-server community public\nno snmp-server community private\nsnmp-server group {group_name} v3 priv\nsnmp-server user {user_name} {group_name} v3 auth sha {auth_pass} priv aes 128 {priv_pass}",
                "prompt_required": True,
                "prompt_message": "enter snmp v3 group name, username, auth password, and priv password",
                "prompt_example": "admin_group admin strongauthpass123 strongprivpass456"
            },
            {
                "name": "management interface acl",
                "description": "management interfaces should be protected with acls",
                "command": "show running-config | section line vty|access-list",
                "match_pattern": r"access-class \d+ in",
                "remediation": "ip access-list standard mgmt_acl\npermit {mgmt_network}\ndeny any log\nline vty 0 15\naccess-class mgmt_acl in",
                "prompt_required": True,
                "prompt_message": "enter management network with cidr notation",
                "prompt_example": "10.1.1.0/24"
            },

        ]
    },
    {
        "category": "service security",
        "checks": [
            {
                "name": "unused services disabled",
                "description": "unnecessary services should be disabled",
                "command": "show running-config | include no service",
                "match_lines": [
                    "no service pad",
                    "no service config",
                    "no ip http server",
                    "no ip http secure-server",
                    "no ip finger",
                    "no ip source-route",
                    "no service dhcp"
                ],
                "remediation": "no service pad\nno service config\nno ip http server\nno ip http secure-server\nno ip finger\nno ip source-route\nno service dhcp",
                "prompt_required": False
            },
            {
                "name": "cdp disabled",
                "description": "cdp should be disabled on external interfaces",
                "command": "show cdp neighbors",
                "custom_check": "cdp_check",
                "remediation": "no cdp run",
                "prompt_required": False
            },
            {
                "name": "lldp disabled",
                "description": "lldp should be disabled on external interfaces",
                "command": "show lldp neighbors",
                "custom_check": "lldp_check",
                "remediation": "no lldp run",
                "prompt_required": False
            },
        ]
    },
    {
        "category": "network security features",
        "checks": [
            {
                "name": "port security",
                "description": "port security should be enabled on access ports",
                "command": "show port-security",
                "custom_check": "port_security_check",
                "remediation": "interface range {access_ports}\nswitchport port-security\nswitchport port-security maximum 2\nswitchport port-security mac-address sticky\nswitchport port-security violation restrict",
                "prompt_required": True,
                "prompt_message": "enter the access port range to configure port security",
                "prompt_example": "gigabitethernet1/0/1-24"
            },
            {
                "name": "dhcp snooping",
                "description": "dhcp snooping should be enabled",
                "command": "show running-config | include ip dhcp snooping",
                "expected": "ip dhcp snooping",
                "remediation": "ip dhcp snooping\nip dhcp snooping vlan {vlan_range}\ninterface range {trusted_ports}\nip dhcp snooping trust",
                "prompt_required": True,
                "prompt_message": "enter vlan range and trusted uplink ports for dhcp snooping",
                "prompt_example": "10-20 gigabitethernet1/0/48"
            },
            {
                "name": "dynamic arp inspection",
                "description": "dynamic arp inspection should be enabled",
                "command": "show running-config | include ip arp inspection",
                "expected": "ip arp inspection",
                "remediation": "ip arp inspection vlan {vlan_range}\ninterface range {trusted_ports}\nip arp inspection trust",
                "prompt_required": True,
                "prompt_message": "enter vlan range and trusted ports for arp inspection",
                "prompt_example": "10-20 gigabitethernet1/0/48"
            },
            {
                "name": "ip source guard",
                "description": "ip source guard should be enabled on access ports",
                "command": "show running-config | include ip verify source",
                "match_pattern": r"ip verify source",
                "remediation": "interface range {access_ports}\nip verify source",
                "prompt_required": True,
                "prompt_message": "enter access port range to configure ip source guard",
                "prompt_example": "gigabitethernet1/0/1-24"
            },
            {
                "name": "storm control",
                "description": "storm control should be configured",
                "command": "show running-config | include storm-control",
                "match_pattern": r"storm-control",
                "remediation": "interface range {access_ports}\nstorm-control broadcast level 30\nstorm-control multicast level 40\nstorm-control unicast level 50",
                "prompt_required": True,
                "prompt_message": "enter access port range to configure storm control",
                "prompt_example": "gigabitethernet1/0/1-24"
            },
            {
                "name": "bpdu guard",
                "description": "bpdu guard should be enabled on access ports",
                "command": "show running-config | include spanning-tree bpduguard",
                "match_pattern": r"spanning-tree bpduguard enable|spanning-tree portfast (edge )?bpduguard default",
                "remediation": "spanning-tree portfast bpduguard default\ninterface range {access_ports}\nspanning-tree portfast\nspanning-tree bpduguard enable",
                "prompt_required": True,
                "prompt_message": "enter access port range to configure bpdu guard",
                "prompt_example": "gigabitethernet1/0/1-24"
            },
            {
                "name": "root guard",
                "description": "root guard should be enabled on non-root ports",
                "command": "show running-config | include spanning-tree guard root",
                "match_pattern": r"spanning-tree guard root",
                "remediation": "interface range {non_root_ports}\nspanning-tree guard root",
                "prompt_required": True,
                "prompt_message": "enter non-root ports to configure root guard",
                "prompt_example": "gigabitethernet1/0/25-48"
            },
            {
                "name": "loop guard",
                "description": "loop guard should be enabled globally",
                "command": "show running-config | include spanning-tree loopguard",
                "expected": "spanning-tree loopguard default",
                "remediation": "spanning-tree loopguard default",
                "prompt_required": False
            },
            {
                "name": "vlan security",
                "description": "unused vlans should be shutdown/removed",
                "command": "show vlan brief",
                "custom_check": "vlan_check",
                "remediation": "vlan {unused_vlan_id}\nshutdown",
                "prompt_required": True,
                "prompt_message": "enter unused vlan id to shutdown",
                "prompt_example": "100,200,300-400"
            },
            {
                "name": "native vlan security",
                "description": "native vlan should not be vlan 1 on trunk ports",
                "command": "show interfaces trunk",
                "custom_check": "native_vlan_check",
                "remediation": "interface {trunk_port}\nswitchport trunk native vlan {new_native_vlan}",
                "prompt_required": True,
                "prompt_message": "enter trunk port and new native vlan id",
                "prompt_example": "gigabitethernet1/0/48 999"
            },
        ]
    },
    {
        "category": "control plane security",
        "checks": [
            {
                "name": "control plane policing",
                "description": "control plane policing should be configured",
                "command": "show running-config | include control-plane",
                "match_pattern": r"control-plane",
                "remediation": "control-plane\nservice-policy input control_plane_policy",
                "prompt_required": False,
                "complex_config": True
            },
            {
                "name": "broadcast suppression",
                "description": "broadcast suppression should be enabled",
                "command": "show running-config | include storm-control broadcast",
                "match_pattern": r"storm-control broadcast",
                "remediation": "interface range {access_ports}\nstorm-control broadcast level 30",
                "prompt_required": True,
                "prompt_message": "enter access port range to configure broadcast suppression",
                "prompt_example": "gigabitethernet1/0/1-24"
            },
        ]
    },
    {
        "category": "aaa configuration",
        "checks": [
            {
                "name": "aaa configuration",
                "description": "aaa authentication should be configured",
                "command": "show running-config | include aaa",
                "match_pattern": r"aaa new-model",
                "remediation": "aaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local\naaa accounting exec default start-stop group tacacs+\naaa accounting commands 15 default start-stop group tacacs+",
                "prompt_required": True,
                "prompt_message": "enter tacacs+ server ip and key",
                "prompt_example": "10.1.1.10 tacacskey123",
                "complex_config": True
            },
            {
                "name": "tacacs+ configuration",
                "description": "tacacs+ should be configured for authentication",
                "command": "show running-config | include tacacs",
                "match_pattern": r"tacacs server",
                "remediation": "tacacs server tacacs-server\naddress ipv4 {tacacs_ip}\nkey {tacacs_key}\nsource-interface {source_interface}",
                "prompt_required": True,
                "prompt_message": "enter tacacs+ server ip, key and source interface",
                "prompt_example": "10.1.1.10 tacacskey123 vlan10"
            },
        ]
    }
]


class CiscoSwitchHardener:
    def __init__(self):
        self.ssh = None
        self.host = None
        self.username = None
        self.password = None
        self.enable_password = None
        self.check_results = []
        self.debug = False
        self.hostname = None
        self.full_config = None

    def connect(self, reuse_credentials=False):
        """connect to the cisco switch via ssh, optionally reusing stored credentials"""
        try:
            # Load creds from file if present (username=, password=, enablepass=)
            file_creds = load_creds("creds.txt")
            if file_creds:
                self.username = self.username or file_creds.get("username", self.username)
                self.password = self.password or file_creds.get("password", self.password)
                self.enable_password = self.enable_password or file_creds.get("enable_password", self.enable_password)

            # Ask for host/IP if not already provided or not reusing
            if not reuse_credentials or not self.host:
                self.host = Prompt.ask("[bold cyan]enter switch ip address")

            # Only prompt for creds if missing
            if not self.username:
                self.username = Prompt.ask("[bold cyan]enter username")
            if not self.password:
                self.password = getpass.getpass("enter password: ")

            # Determine enable mode
            if self.enable_password:
                use_enable = True  # creds file provided it, assume enable mode is needed
            else:
                use_enable = Confirm.ask("[bold cyan]do you need to use enable mode?")
                if use_enable and not self.enable_password:
                    self.enable_password = getpass.getpass("enter enable password: ")

            self._display_banner()

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]connecting to {0}...".format(self.host)),
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
                    timeout=10
                )

                self.channel = self.ssh.invoke_shell()
                time.sleep(1)
                _ = self._read_output()

                if use_enable and self.enable_password:
                    self.channel.send("enable\n")
                    time.sleep(0.5)
                    output = self._read_output()
                    if "password:" in output.lower():
                        self.channel.send(f"{self.enable_password}\n")
                        time.sleep(0.5)

                self.channel.send("terminal length 0\n")
                time.sleep(0.5)
                _ = self._read_output()

            # --- snapshot hostname and full running-config all ---
            try:
                hn_out = self.run_command("show running-config | include hostname")
                mhost = re.search(r"^\s*hostname\s+(\S+)", hn_out, re.IGNORECASE | re.MULTILINE)
                self.hostname = mhost.group(1) if mhost else "unknown"
            except Exception:
                self.hostname = "unknown"

            # Capture once per session
            self.full_config = self.run_command("show running-config all")

            # Save snapshot to file with hostname header
            try:
                with open("running_config_all.txt", "w", encoding="utf-8") as f:
                    f.write(f"# Hostname: {self.hostname}\n")
                    f.write(self.full_config if self.full_config else "")
            except Exception as _e:
                console.print(f"[yellow]warning: could not write running_config_all.txt: {_e}[/yellow]")
            # --- end snapshot ---

            rprint("[bold green]✓[/bold green] successfully connected to switch")
            return True

        except Exception as e:
            rprint(f"[bold red]✗[/bold red] connection failed: {str(e)}")
            return False

    def _display_banner(self):
        banner = """
        ╔═══════════════════════════════════════════════════════════════╗
        ║                                                               ║
        ║           cisco switch security hardening tool                ║
        ║                                                               ║
        ║   comprehensive security assessment and remediation tool      ║
        ║                                                               ║
        ╚═══════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold blue"))

    def _read_output(self, timeout=5):
        output = ""
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096).decode('utf-8')
                output += chunk
                if any(p in chunk for p in ['#', '>']):
                    break
            else:
                time.sleep(0.1)
        return output



    def _config_query(self, command: str) -> str:
        """Return output for 'show running-config*' using cached full config.
        Supports '| include <regex or text>' locally. For '| begin' or '| section', returns full snapshot.
        """
        data = self.full_config or ""
        cmd = command.strip().lower()
        if "| section" in cmd or "| begin" in cmd:
            return data
        if "| include" in cmd:
            inc = command.split("| include", 1)[1].strip()
            try:
                rx = re.compile(inc, re.IGNORECASE)
                return "\n".join([line for line in data.splitlines() if rx.search(line)])
            except re.error:
                inc_l = inc.lower()
                return "\n".join([line for line in data.splitlines() if inc_l in line.lower()])
        return data


    def run_command(self, command):
        try:
            if self.debug:
                console.print(f"[dim]running: {command}[/dim]", highlight=False)
            self.channel.send(command + "\n")
            time.sleep(1)
            output = self._read_output()
            if "% invalid input" in output.lower() or "% incomplete command" in output.lower():
                console.print(f"[yellow]warning: command '{command}' returned an error[/yellow]")
            return output
        except Exception as e:
            error_msg = f"error running command: {str(e)}"
            console.print(f"[red]{error_msg}[/red]")
            return error_msg

    def run_selected_checks(self):
        """allow user to select and run specific security checks (one progress bar for all selected)"""
        console.print("\n[bold]available security checks:[/bold]")
        check_list = []
        check_index = 1
        for category in HARDENING_CHECKS:
            for check in category["checks"]:
                console.print(f"[bold]{check_index}.[/bold] {category['category']} - {check['name']}")
                check_list.append((category, check))
                check_index += 1

        selected = Prompt.ask(
            "\n[bold yellow]enter check numbers to run (comma-separated, or 'all')[/bold yellow]",
            default="all"
        )

        if selected.lower() == "all":
            selected_checks = check_list
        else:
            try:
                selected_indices = [int(x.strip()) - 1 for x in selected.split(",")]
                selected_checks = [check_list[i] for i in selected_indices if 0 <= i < len(check_list)]
            except ValueError:
                console.print("[bold red]invalid selection. please enter valid numbers.[/bold red]")
                return

        self.check_results = []
        console.print(f"\n[bold]running {len(selected_checks)} selected checks...[/bold]")

        with Progress(
            BarColumn(bar_width=None),
            TextColumn(" {task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("running checks...", total=len(selected_checks))

            for category, check in selected_checks:
                check_name = check["name"]
                description = check["description"]
                command = check["command"]
                output = self._config_query(command) if command.strip().lower().startswith('show running-config') else self.run_command(command)

                console.print(f"\n[bold cyan]check: {check_name}[/bold cyan]")
                console.print(f"[cyan]command:[/cyan] {command}")
                console.print(f"[cyan]switch output:[/cyan]")
                console.print(Panel(output.strip(), style="dim"))

                result = False
                details = ""
                if "custom_check" in check:
                    check_function = getattr(self, check["custom_check"])
                    result, details = check_function(output)
                elif "expected" in check:
                    result = check["expected"] in output.lower()
                    details = f"found: '{check['expected']}'" if result else f"expected '{check['expected']}' not found"
                elif "match_pattern" in check:
                    pattern_match = re.search(check["match_pattern"], output, re.IGNORECASE)
                    result = bool(pattern_match)
                    if "not_match_pattern" in check and result:
                        not_match = re.search(check["not_match_pattern"], output, re.IGNORECASE)
                        result = not bool(not_match)
                        details = "pattern match found but excluded pattern also found" if not result else "pattern match found correctly"
                    else:
                        details = "found matching pattern" if result else f"pattern '{check['match_pattern']}' not found"
                elif "match_lines" in check:
                    matched_lines = [line for line in check["match_lines"] if line in output.lower()]
                    result = len(matched_lines) == len(check["match_lines"])
                    if result:
                        details = f"all required lines found ({len(matched_lines)}/{len(check['match_lines'])})"
                    else:
                        missing_lines = [line for line in check["match_lines"] if line not in output.lower()]
                        details = f"missing {len(missing_lines)}/{len(check['match_lines'])} lines: {', '.join(missing_lines)}"

                self.check_results.append({
                    "category": category["category"],
                    "name": check_name,
                    "description": description,
                    "result": result,
                    "details": details,
                    "remediation": check.get("remediation", ""),
                    "prompt_required": check.get("prompt_required", False),
                    "prompt_message": check.get("prompt_message", ""),
                    "prompt_example": check.get("prompt_example", ""),
                    "complex_config": check.get("complex_config", False)
                })

                progress.advance(task)

            progress.update(task, completed=len(selected_checks), description="✔ all checks complete")

        self._display_results()

        console.print("\n[bold yellow]what would you like to do next?[/bold yellow]")
        choice = Prompt.ask(
            "[bold yellow]select an option[/bold yellow]",
            choices=["select", "main"],
            default="main"
        )
        if choice == "select":
            console.print("[bold cyan]selecting another check...[/bold cyan]")
            self.run_selected_checks()
        else:
            console.print("[bold cyan]returning to main menu...[/bold cyan]")
            return

    def check_security(self):
        """run all security checks (one bar per category)"""
        console.print("\n[bold]starting security checks...[/bold]")
        self.check_results = []

        for category in HARDENING_CHECKS:
            category_name = category["category"]
            console.print(f"\n[bold cyan]checking {category_name}...[/bold cyan]")
            checks = category["checks"]
            with Progress(
                BarColumn(bar_width=None),
                TextColumn(" {task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("running checks...", total=len(checks))
                for check in checks:
                    check_name = check["name"]
                    description = check["description"]
                    command = check["command"]
                    output = self._config_query(command) if command.strip().lower().startswith('show running-config') else self.run_command(command)

                    # Live display similar to 'select' mode
                    console.print(f"\n[bold cyan]check: {check_name}[/bold cyan]")
                    console.print(f"[cyan]command:[/cyan] {command}")
                    console.print("[cyan]switch output:[/cyan]")
                    console.print(Panel(output.strip(), style="dim"))

                    result = False
                    details = ""
                    if "custom_check" in check:
                        check_function = getattr(self, check["custom_check"])
                        result, details = check_function(output)
                    elif "expected" in check:
                        result = check["expected"] in output.lower()
                        details = f"found: '{check['expected']}'" if result else f"expected '{check['expected']}' not found"
                    elif "match_pattern" in check:
                        pattern_match = re.search(check["match_pattern"], output, re.IGNORECASE)
                        result = bool(pattern_match)
                        if "not_match_pattern" in check and result:
                            not_match = re.search(check["not_match_pattern"], output, re.IGNORECASE)
                            result = not bool(not_match)
                            details = "pattern match found but excluded pattern also found" if not result else "pattern match found correctly"
                        else:
                            details = "found matching pattern" if result else f"pattern '{check['match_pattern']}' not found"
                    elif "match_lines" in check:
                        matched_lines = [line for line in check["match_lines"] if line in output.lower()]
                        result = len(matched_lines) == len(check["match_lines"])
                        if result:
                            details = f"all required lines found ({len(matched_lines)}/{len(check['match_lines'])})"
                        else:
                            missing_lines = [line for line in check["match_lines"] if line not in output.lower()]
                            details = f"missing {len(missing_lines)}/{len(check['match_lines'])} lines: {', '.join(missing_lines)}"

                    self.check_results.append({
                        "category": category_name,
                        "name": check_name,
                        "description": description,
                        "result": result,
                        "details": details,
                        "remediation": check.get("remediation", ""),
                        "prompt_required": check.get("prompt_required", False),
                        "prompt_message": check.get("prompt_message", ""),
                        "prompt_example": check.get("prompt_example", ""),
                        "complex_config": check.get("complex_config", False)
                    })

                    progress.advance(task)

                progress.update(task, completed=len(checks), description="✔ all checks complete")

        self._display_results()

    
    def _display_results(self):
        """display the results of security checks"""
        console.print("\n[bold]security check results:[/bold]")
        
        # create categories table
        categories_table = Table(title="[bold]categories summary[/bold]")
        categories_table.add_column("category", style="cyan")
        categories_table.add_column("passed", style="green")
        categories_table.add_column("failed", style="red")
        categories_table.add_column("compliance", style="yellow")
        
        # create detailed table
        details_table = Table(title="[bold]detailed results[/bold]")
        details_table.add_column("category", style="cyan")
        details_table.add_column("check", style="blue")
        details_table.add_column("description")
        details_table.add_column("status", width=10)
        details_table.add_column("details", width=30)
        
        # group results by category
        results_by_category = {}
        for result in self.check_results:
            category = result["category"]
            if category not in results_by_category:
                results_by_category[category] = []
            results_by_category[category].append(result)
        
        # fill tables
        for category, results in results_by_category.items():
            passed = sum(1 for r in results if r["result"])
            failed = len(results) - passed
            compliance = round((passed / len(results)) * 100) if results else 0
            
            categories_table.add_row(
                category,
                str(passed),
                str(failed),
                f"{compliance}%"
            )
            
            for result in results:
                status = Text("✓ PASS", style="bold green") if result["result"] else Text("✗ FAIL", style="bold red")
                detail_text = result["details"]
                if len(detail_text) > 30:
                    detail_text = detail_text[:27] + "..."
                    
                details_table.add_row(
                    category,
                    result["name"],
                    result["description"],
                    status,
                    detail_text
                )
        
        # print tables
        console.print(categories_table)
        console.print(details_table)
        
        # calculate overall compliance
        total_passed = sum(1 for r in self.check_results if r["result"])
        total_checks = len(self.check_results)
        overall_compliance = round((total_passed / total_checks) * 100) if total_checks else 0
        
        # display overall compliance
        compliance_text = f"overall compliance: {overall_compliance}%"
        if overall_compliance >= 90:
            console.print(f"[bold green]{compliance_text}[/bold green]")
        elif overall_compliance >= 70:
            console.print(f"[bold yellow]{compliance_text}[/bold yellow]")
        else:
            console.print(f"[bold red]{compliance_text}[/bold red]")
            
        # display remediation options
        if not all(r["result"] for r in self.check_results):
            self._offer_remediation()
    
    def _offer_remediation(self):
        """offer remediation options for failed checks"""
        console.print("\n[bold yellow]remediation options[/bold yellow]")
        
        failed_checks = [r for r in self.check_results if not r["result"]]
        
        options_panel = """
        [bold yellow]remediation options:[/bold yellow]

        [bold]1.[/bold] [green]remediate all issues[/green]
           automatically fix all failed security checks

        [bold]2.[/bold] [cyan]select specific issues to remediate[/cyan]
           choose which specific checks to fix

        [bold]3.[/bold] [blue]export remediation plan[/blue]
           save commands to a file without making changes

        [bold]4.[/bold] [red]exit without remediation[/red]
           make no changes to the switch

        [bold]5.[/bold] [magenta]restart script from scratch[/magenta]
           restart the script reusing stored credentials
        """
        
        console.print(Panel(options_panel))
        
        choice = Prompt.ask(
            "[bold yellow]choose an option[/bold yellow]",
            choices=["1", "2", "3", "4", "5"],
            default="4"
        )
        
        if choice == "1":
            self._remediate_all()
        elif choice == "2":
            self._remediate_selected()
        elif choice == "3":
            self._export_remediation_plan()
        elif choice == "5":
            console.print("[magenta]restarting script with stored credentials...[/magenta]")
            self.disconnect()
            main(hardener=self)  # restart with the same hardener instance
        else:
            console.print("[yellow]exiting without remediation[/yellow]")
    
    def _remediate_all(self):

        """remediate all failed security checks (no spinner; clear prompts)"""
        failed_checks = [r for r in self.check_results if not r["result"]]
        console.print(f"\n[bold]remediating {len(failed_checks)} issues...[/bold]")
        for check in failed_checks:
            console.print(f"[bold cyan]fixing {check['name']}...[/bold cyan]")
            self._apply_remediation(check)
        console.print("[bold green]✓[/bold green] remediation complete! run the check again to verify fixes.")

    
    def _remediate_selected(self):

        """allow user to select specific issues to remediate (no spinner; clear prompts)"""
        failed_checks = [r for r in self.check_results if not r["result"]]

        console.print("\n[bold]failed checks:[/bold]")
        for i, check in enumerate(failed_checks, 1):
            console.print(f"[bold]{i}.[/bold] {check['category']} - {check['name']}")

        selected = Prompt.ask(
            "\n[bold yellow]enter check numbers to remediate (comma-separated, or 'all')[/bold yellow]",
            default="all"
        )

        if selected.lower() == "all":
            to_remediate = failed_checks
        else:
            try:
                selected_indices = [int(x.strip()) - 1 for x in selected.split(",")]            
                to_remediate = [failed_checks[i] for i in selected_indices if 0 <= i < len(failed_checks)]
            except ValueError:
                console.print("[bold red]invalid selection. please enter valid numbers.[/bold red]")
                return

        console.print(f"\n[bold]remediating {len(to_remediate)} issues...[/bold]")
        for check in to_remediate:
            console.print(f"[bold cyan]fixing {check['name']}...[/bold cyan]")
            self._apply_remediation(check)

        console.print("[bold green]✓[/bold green] remediation complete! run the check again to verify fixes.")

    
    def _export_remediation_plan(self):
        """export a remediation plan to a file"""
        failed_checks = [r for r in self.check_results if not r["result"]]
        
        filename = Prompt.ask(
            "[bold yellow]enter filename for remediation plan[/bold yellow]",
            default="remediation_plan.txt"
        )
        
        try:
            with open(filename, 'w') as f:
                f.write("# cisco switch hardening remediation plan\n\n")
                f.write(f"generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"switch ip: {self.host}\n\n")
                
                for check in failed_checks:
                    f.write(f"## {check['category']} - {check['name']}\n")
                    f.write(f"description: {check['description']}\n")
                    f.write("remediation commands:\n")
                    f.write("```\n")
                    f.write(check['remediation'])
                    f.write("\n```\n\n")
            
            console.print(f"[bold green]✓[/bold green] remediation plan exported to {filename}")
        except Exception as e:
            console.print(f"[bold red]✗[/bold red] failed to export remediation plan: {str(e)}")
    
    def _apply_remediation(self, check):


        """apply remediation for a check (enter config mode; prompt per command)"""
        remediation_commands = check["remediation"]

        console.print(f"[bold]applying remediation for {check['name']}...[/bold]")
        console.print(f"[dim]check prompt_required: {check.get('prompt_required', False)}[/dim]")

        if check.get("complex_config", False):
            console.print(f"[bold yellow]note:[/bold yellow] {check['name']} requires complex configuration.")
            console.print("manual configuration recommended for this check.")
            console.print(f"template commands:\n{remediation_commands}")
            return

        if check.get("prompt_required", False):
            console.print(f"[bold cyan]configuration required for {check['name']}[/bold cyan]")
            console.print(f"[cyan]prompt: {check['prompt_message']}[/cyan]")
            console.print(f"[cyan]example: {check['prompt_example']}[/cyan]")
            try:
                console.file.flush()
                user_input = Prompt.ask("[bold cyan]enter configuration parameters (or 'skip' to skip)[/bold cyan]")
                console.print(f"[dim]received input: {user_input}[/dim]")
                if user_input.lower() == 'skip' or not user_input.strip():
                    console.print(f"[bold yellow]skipping remediation for {check['name']} due to no input[/bold yellow]")
                    return
                parts = user_input.split()
                if check["name"] == "snmp security":
                    if len(parts) != 4:
                        console.print(f"[bold red]error: snmp security requires exactly 4 parameters: group_name, user_name, auth_pass, priv_pass[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    group_name, user_name, auth_pass, priv_pass = parts
                    remediation_commands = remediation_commands.replace("{group_name}", group_name).replace("{user_name}", user_name).replace("{auth_pass}", auth_pass).replace("{priv_pass}", priv_pass)

                elif check["name"] == "ntp authentication":
                    if len(parts) < 2:
                        console.print(f"[bold red]error: ntp authentication requires at least 2 parameters: server, key[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    server, key = parts[0], parts[1]
                    remediation_commands = remediation_commands.replace("{ntp_server}", server).replace("{ntp_key}", key)

                elif check["name"] == "logging configuration":
                    if len(parts) < 2:
                        console.print(f"[bold red]error: logging configuration requires at least 2 parameters: server, interface[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    server, interface = parts[0], parts[1]
                    remediation_commands = remediation_commands.replace("{syslog_server}", server).replace("{source_interface}", interface)

                elif check["name"] == "management interface acl":
                    if not parts:
                        console.print(f"[bold red]error: management interface acl requires management network in CIDR notation[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    remediation_commands = remediation_commands.replace("{mgmt_network}", parts[0])

                elif check["name"] in ["port security", "ip source guard", "storm control", "bpdu guard", "broadcast suppression"]:
                    if not parts:
                        console.print(f"[bold red]error: {check['name']} requires access port range[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    remediation_commands = remediation_commands.replace("{access_ports}", parts[0])

                elif check["name"] in ["dhcp snooping", "dynamic arp inspection"]:
                    if len(parts) < 2:
                        console.print(f"[bold red]error: {check['name']} requires at least 2 parameters: vlan_range, trusted_ports[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    vlan_range, trusted_ports = parts[0], parts[1]
                    remediation_commands = remediation_commands.replace("{vlan_range}", vlan_range).replace("{trusted_ports}", trusted_ports)

                elif check["name"] == "root guard":
                    if not parts:
                        console.print(f"[bold red]error: root guard requires non-root ports[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    remediation_commands = remediation_commands.replace("{non_root_ports}", parts[0])

                elif check["name"] == "vlan security":
                    if not parts:
                        console.print(f"[bold red]error: vlan security requires unused vlan id[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    remediation_commands = remediation_commands.replace("{unused_vlan_id}", parts[0])

                elif check["name"] == "native vlan security":
                    if len(parts) < 2:
                        console.print(f"[bold red]error: native vlan security requires at least 2 parameters: trunk_port, new_vlan[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    trunk_port, new_vlan = parts[0], parts[1]
                    remediation_commands = remediation_commands.replace("{trunk_port}", trunk_port).replace("{new_native_vlan}", new_vlan)

                elif check["name"] == "strong local passwords":
                    if len(parts) < 2:
                        console.print(f"[bold red]error: strong local passwords requires at least 2 parameters: username, password[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    username, password = parts[0], parts[1]
                    remediation_commands = remediation_commands.replace("{username}", username).replace("{password}", password)

                elif check["name"] == "tacacs+ configuration":
                    if len(parts) < 3:
                        console.print(f"[bold red]error: tacacs+ configuration requires at least 3 parameters: ip, key, interface[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    ip, key, interface = parts[0], parts[1], parts[2]
                    remediation_commands = remediation_commands.replace("{tacacs_ip}", ip).replace("{tacacs_key}", key).replace("{source_interface}", interface)

                elif check["name"] == "aaa configuration":
                    if len(parts) < 2:
                        console.print(f"[bold red]error: aaa configuration requires at least 2 parameters: ip, key[/bold red]")
                        console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                        return
                    ip, key = parts[0], parts[1]
                    remediation_commands = remediation_commands.replace("{tacacs_ip}", ip).replace("{tacacs_key}", key)

            except Exception as e:
                console.print(f"[bold red]error: failed to process input for {check['name']}: {str(e)}[/bold red]")
                console.print(f"[yellow]skipping remediation for {check['name']}[/yellow]")
                return

        try:
            # Enter configuration mode
            console.print("[dim]entering configuration mode...[/dim]")
            self.channel.send("configure terminal\n")
            time.sleep(0.4)
            _ = self._read_output()

            commands = [c for c in remediation_commands.strip().split('\n') if c.strip()]
            for cmd in commands:
                raw_cmd = cmd.strip()
                if not raw_cmd:
                    continue

                first_word = raw_cmd.split()[0].lower()
                needs_do = first_word in {"show", "write", "copy", "dir", "ping", "reload"}
                exec_cmd = raw_cmd if (raw_cmd.startswith("do ") or not needs_do) else f"do {raw_cmd}"

                console.file.flush()
                run_it = Confirm.ask(f"Run: [cyan]{exec_cmd}[/cyan]?", default=True)
                if not run_it:
                    console.print(f"[yellow]skipped:[/yellow] {exec_cmd}")
                    continue

                console.print(f"[dim]> {exec_cmd}[/dim]")
                output = self.run_command(exec_cmd)

                low = output.lower()
                if any(err in low for err in ["invalid input", "% ", "error"]):
                    console.print(f"[bold red]✗ error executing command[/bold red]: {exec_cmd}")
                    console.print(f"[dim]{output.strip()}[/dim]")
                else:
                    console.print(f"[bold green]✔ ok[/bold green]")

        except KeyboardInterrupt:
            console.print("\n[bold red]remediation cancelled by user[/bold red]")
        finally:
            try:
                self.channel.send("end\n")
                time.sleep(0.3)
                _ = self._read_output()
            except Exception:
                pass

        console.print(f"[bold green]✓[/bold green] applied remediation for {check['name']}")


    
    def save_config(self):
        """save the switch configuration"""
        console.print("\n[bold]saving configuration...[/bold]")
        output = self.run_command("write memory")
        
        if "ok" in output.lower() or "complete" in output.lower():
            console.print("[bold green]✓[/bold green] configuration saved successfully")
        else:
            console.print("[bold red]✗[/bold red] failed to save configuration")
            console.print(f"[dim]{output.strip()}[/dim]")
    
    def disconnect(self):
        """disconnect from the switch"""
        if self.ssh:
            self.ssh.close()
            self.ssh = None
            self.channel = None
            console.print("[bold green]✓[/bold green] disconnected from switch")
    
    def cdp_check(self, output):
        """check if cdp is enabled on any interface"""
        output = output.lower()
        if "cdp is not enabled" in output:
            return True, "cdp is disabled globally"
        elif "no cdp neighbors" in output:
            return False, "cdp is enabled but no neighbors found"
        else:
            return False, "cdp is enabled and neighbors found"
    
    def lldp_check(self, output):
        """check if lldp is enabled on any interface"""
        output = output.lower()
        if "lldp is not enabled" in output:
            return True, "lldp is disabled globally"
        elif "total entries displayed: 0" in output:
            return False, "lldp is enabled but no neighbors found"
        else:
            return False, "lldp is enabled and neighbors found"
    
    def port_security_check(self, output):
        """check if port security is configured on access ports"""
        output = output.lower()
        if "feature not enabled" in output or "command rejected" in output:
            return False, "port security is not enabled"
        elif "port security : disabled" in output:
            return False, "port security is disabled globally"
        elif "secure port" in output and "maxsecureaddr" in output:
            secure_ports_count = output.count("secure port")
            return True, f"port security is enabled on {secure_ports_count} ports"
        else:
            return False, "port security not properly configured"
    
    def vlan_check(self, output):
        """check if there are unused vlans that should be shut down"""
        output = output.lower()
        lines = output.strip().split('\n')
        unused_vlans = []
        active_vlans = []
        
        for line in lines:
            if "vlan name" in line or "----" in line:
                continue
                
            parts = line.split()
            if len(parts) >= 4:
                vlan_id = parts[0]
                vlan_name = parts[1]
                vlan_status = parts[2]
                
                if vlan_status == "active" and vlan_id != "1":
                    active_vlans.append(vlan_id)
                    
                    if any(term in vlan_name for term in ["unused", "test", "temp", "old"]):
                        unused_vlans.append(f"{vlan_id} ({vlan_name})")
        
        if active_vlans:
            try:
                numeric_vlans = sorted([int(v) for v in active_vlans if v.isdigit()])
                if numeric_vlans and len(numeric_vlans) >= 10:
                    suspicious_gaps = []
                    for i in range(len(numeric_vlans)-1):
                        if numeric_vlans[i+1] - numeric_vlans[i] > 20:
                            suspicious_gaps.append(f"{numeric_vlans[i]}-{numeric_vlans[i+1]}")
                    
                    if suspicious_gaps:
                        details = f"found large vlan number gaps: {', '.join(suspicious_gaps)}"
                        if unused_vlans:
                            details += f" and potential unused vlans: {', '.join(unused_vlans)}"
                        return False, details
            except (ValueError, TypeError):
                pass
        
        if unused_vlans:
            return False, f"found potentially unused vlans: {', '.join(unused_vlans)}"
        else:
            return True, f"no obviously unused vlans found among {len(active_vlans)} active vlans"
    
    def native_vlan_check(self, output):
        """check if native vlan is vlan 1 on trunk ports"""
        output = output.lower()
        if not output or "invalid input" in output:
            return True, "no trunk ports found or command not supported"
            
        if "vlans allowed on trunk" not in output:
            return True, "no trunk ports configured"
            
        trunk_ports = []
        native_vlan_1_ports = []
        
        port = None
        for line in output.split('\n'):
            if "port" in line and "mode" in line:
                continue
            elif line.strip().startswith(("gi", "fa", "te")):
                port = line.strip().split()[0]
                trunk_ports.append(port)
            elif "native vlan" in line and port:
                native_vlan = line.split("native vlan")[1].strip()
                if native_vlan.startswith("1 ") or native_vlan == "1":
                    native_vlan_1_ports.append(port)
        
        if native_vlan_1_ports:
            return False, f"native vlan is set to vlan 1 on trunk ports: {', '.join(native_vlan_1_ports)}"
        elif trunk_ports:
            return True, f"native vlan is not vlan 1 on all {len(trunk_ports)} trunk ports"
        else:
            return True, "no trunk ports configured"


def main(hardener=None):
    """main function to run the script"""
    try:
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--debug", action="store_true", help="Enable debug output")
        args = parser.parse_args()

        console.print("\n[bold blue]cisco switch hardening tool[/bold blue]")
        console.print("[blue]------------------------------[/blue]")

        if hardener is None:
            hardener = CiscoSwitchHardener()

        if not hardener.connect(reuse_credentials=hardener.username is not None):
            sys.exit(1)

        run_mode = Prompt.ask(
            "\n[bold cyan]select run mode[/bold cyan]",
            choices=["all", "select"],
            default="all"
        )

        debug_mode = Confirm.ask("\n[bold cyan]enable debug mode (shows more detailed output)?[/bold cyan]", default=False)
        if debug_mode or args.debug:
            console.print("[yellow]debug mode enabled - showing detailed command output[/yellow]")
            hardener.debug = True
        else:
            hardener.debug = False

        if run_mode == "all":
            hardener.check_security()
        else:
            hardener.run_selected_checks()

        if Confirm.ask("\n[bold cyan]save configuration changes?[/bold cyan]", default=False):
            hardener.save_config()

        hardener.disconnect()
        console.print("\n[bold green]finished![/bold green]")

    except KeyboardInterrupt:
        console.print("\n[bold red]operation cancelled by user[/bold red]")
        if hardener:
            hardener.disconnect()
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]error: {str(e)}[/bold red]")
        if hardener:
            hardener.disconnect()
        sys.exit(1)

if __name__ == "__main__":
    main()