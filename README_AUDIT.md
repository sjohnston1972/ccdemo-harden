# Cisco Network Device Hardening Auditor

## Overview
Enterprise-grade security auditor for Cisco network devices. Performs comprehensive read-only security assessments following industry best practices.

## Features

### ✅ Comprehensive Security Coverage
- **Access Security**: Password policies, SSH configuration, authentication
- **Management Plane**: NTP, Syslog, SNMP, Management ACLs
- **Service Hardening**: Disable unnecessary services (HTTP, Telnet, CDP, LLDP)
- **Network Security**: Port security, DHCP snooping, ARP inspection, BPDU guard
- **Control Plane**: CoPP, CPU protection
- **AAA**: Centralized authentication, authorization, accounting

### ✅ Safe & Professional
- **Read-only operations** - No configuration changes
- **Detailed risk assessment** - CRITICAL, HIGH, MEDIUM, LOW ratings
- **Compliance scoring** - Percentage-based security posture
- **Structured reporting** - JSON export for integration
- **Rich CLI interface** - Color-coded, professional output

### ✅ Enterprise Ready
- Secure credential handling via `.env` file
- Automated device discovery and information gathering
- Category-based assessment with progress tracking
- Exportable audit reports for compliance

## Installation

### Prerequisites
- Python 3.7 or higher
- Network connectivity to target device
- SSH access credentials

### Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure credentials in `.env` file:
```bash
DEVICE_IP=192.168.20.117
SSH_USERNAME=your_username
SSH_PASSWORD=your_password
```

**⚠️ Security Note**: Never commit `.env` file to version control!

## Usage

### Run Complete Audit
```bash
python cisco_audit.py
```

### Expected Output
```
╔═══════════════════════════════════════════════════════════════╗
║        CISCO NETWORK DEVICE HARDENING AUDITOR                 ║
║     Enterprise Security Posture Assessment Tool               ║
╚═══════════════════════════════════════════════════════════════╝

Target Device: 192.168.20.117
✓ Successfully connected to device

═══ Device Information Gathering ═══
┌─────────────────────────────────────┐
│ Device Information                  │
├────────────┬────────────────────────┤
│ Hostname   │ Switch01               │
│ Model      │ WS-C3850-24P           │
│ IOS Version│ 16.12.4                │
└────────────┴────────────────────────┘

═══ Access Security Assessment ═══
Running 8 checks...
✓ All checks complete

═══ Management Plane Security Assessment ═══
...
```

### Audit Report Sections

#### 1. Summary Statistics
- Total checks performed
- Passed/Failed count
- Overall compliance score (0-100%)
- Risk-based status rating

#### 2. Category Breakdown
| Category | Passed | Failed | Score |
|----------|--------|--------|-------|
| Access Security | 6 | 2 | 75.0% |
| Management Plane | 3 | 2 | 60.0% |
| ... | ... | ... | ... |

#### 3. Detailed Findings
Each failed check includes:
- **Risk Level**: CRITICAL / HIGH / MEDIUM / LOW
- **Impact**: Why this matters for security
- **Recommendation**: Specific remediation steps
- **Automation**: Verification commands

Example:
```
┌─ Finding #1 ─────────────────────────────────────┐
│ CHECK: Telnet Disabled                           │
│ RISK LEVEL: CRITICAL                             │
│                                                  │
│ 1️⃣ IMPACT:                                       │
│ Telnet transmits credentials in cleartext       │
│                                                  │
│ 2️⃣ RECOMMENDATION:                               │
│ Configure: line vty 0 15 → transport input ssh  │
│                                                  │
│ 3️⃣ AUTOMATION:                                   │
│ Verify with: show run | section line vty        │
└──────────────────────────────────────────────────┘
```

#### 4. Risk Distribution
Counts of findings by severity:
- CRITICAL: Issues requiring immediate attention
- HIGH: Significant security risks
- MEDIUM: Important improvements needed
- LOW: Best practice recommendations

#### 5. JSON Export (Optional)
Structured data export for:
- Integration with SIEM/ticketing systems
- Compliance documentation
- Trend analysis over time

## Audit Categories Explained

### 🔐 Access Security (8 checks)
- Password encryption enabled
- SSH version 2 enforcement
- Telnet disabled
- Login banners configured
- Session timeouts
- Password policies
- SSH authentication limits

### 🖥️ Management Plane Security (5 checks)
- NTP authentication
- Centralized syslog
- SNMPv3 with encryption
- Management interface ACLs
- Timestamp configuration

### ⚙️ Service Hardening (7 checks)
- HTTP/HTTPS server status
- CDP protocol control
- LLDP protocol control
- Finger service disabled
- Source routing disabled
- PAD service disabled

### 🌐 Network Security Features (9 checks)
- Port security on access ports
- DHCP snooping enabled
- Dynamic ARP inspection
- IP Source Guard
- Storm control
- BPDU guard
- Root guard
- Loop guard
- Native VLAN security

### 🛑 Control Plane Security (2 checks)
- Control Plane Policing (CoPP)
- CPU protection policies

### 🔑 AAA Configuration (5 checks)
- AAA new-model enabled
- TACACS+ configuration
- Centralized authentication
- Command authorization
- Accounting enabled

## Risk Level Definitions

| Level | Definition | Action Required |
|-------|------------|-----------------|
| **CRITICAL** | Severe vulnerability, immediate exploitation possible | Fix immediately |
| **HIGH** | Significant risk, could lead to compromise | Fix within 24-48 hours |
| **MEDIUM** | Important security gap, increases attack surface | Plan remediation |
| **LOW** | Best practice violation, minimal immediate risk | Address in maintenance window |

## Compliance Scoring

- **90-100%**: Excellent security posture
- **75-89%**: Good, minor improvements needed
- **60-74%**: Needs improvement, multiple gaps
- **0-59%**: Critical - immediate action required

## Output Files

### audit_report_[hostname]_[timestamp].json
Complete audit results in JSON format:
```json
{
  "audit_timestamp": "2026-02-15T10:30:00",
  "device_info": {
    "hostname": "Switch01",
    "model": "WS-C3850-24P",
    "ios_version": "16.12.4"
  },
  "summary": {
    "total_checks": 36,
    "passed": 28,
    "failed": 8,
    "compliance_score": 77.8
  },
  "findings": [...]
}
```

## Safety Features

✅ **Read-only operations** - No configuration changes
✅ **Credential security** - Environment variable storage
✅ **Rate limiting** - Prevents device overload
✅ **Error handling** - Graceful failure on connectivity issues
✅ **Interrupt handling** - Safe Ctrl+C cancellation

## Troubleshooting

### Connection Failed
```
✗ Authentication failed - Check credentials
```
**Solution**: Verify `.env` file contains correct credentials

### Timeout Issues
```
✗ Connection failed: timed out
```
**Solution**:
- Check network connectivity
- Verify device IP address
- Check firewall rules for SSH (port 22)

### Missing Commands
Some checks may fail on older IOS versions that don't support certain commands. This is expected and will be noted in the report.

## Integration Examples

### Schedule Regular Audits (Linux/Mac)
```bash
# Daily audit at 2 AM
0 2 * * * cd /path/to/audit && python cisco_audit.py >> audit.log 2>&1
```

### Parse JSON Results (Python)
```python
import json

with open('audit_report_Switch01_20260215.json') as f:
    report = json.load(f)

critical_findings = [
    f for f in report['findings']
    if not f['passed'] and f['risk'] == 'CRITICAL'
]

print(f"Found {len(critical_findings)} critical issues")
```

## Best Practices

1. **Regular Audits**: Run weekly to track security posture trends
2. **Document Exceptions**: Some findings may be accepted risks - document them
3. **Track Compliance**: Monitor compliance score over time
4. **Integrate with Change Management**: Run after configuration changes
5. **Export Results**: Keep JSON exports for compliance evidence

## Support & Feedback

For issues or feature requests:
- GitHub: https://github.com/sjohnston1972/ccdemo-harden
- Review CLAUDE.md for AI agent usage guidelines

## License

Enterprise use authorized. Follow organizational security policies.

---

**Generated by Claude Code - Network Device Hardening Auditor AI Agent**
