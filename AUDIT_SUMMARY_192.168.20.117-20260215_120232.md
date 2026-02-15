# Security Audit Summary Report

**Generated:** 2026-02-15 12:02:32

---

## Device Information

| Property | Value |
|----------|-------|
| Hostname | hostname |
| IP Address | 192.168.20.117 |
| Platform | IOS |
| Model | Unknown |
| IOS Version | Cisco |
| Audit Date | 2026-02-15 12:02:32 |

## Executive Summary

**Overall Compliance Score:** 47.2%

**Status:** CRITICAL - IMMEDIATE ACTION REQUIRED

### Summary Statistics

- **Total Checks:** 36
- **Passed:** 17
- **Failed:** 19

### Risk Distribution

| Risk Level | Count |
|------------|-------|
| HIGH | 9 |
| MEDIUM | 7 |
| LOW | 3 |

## Detailed Findings

### HIGH Risk Issues

#### 1. NTP Authentication

**Category:** Management Plane Security

**Impact:**
Unauthenticated NTP can be spoofed, causing time-based attacks

**Recommendation:**
Configure: ntp authenticate, ntp authentication-key, ntp trusted-key

---

#### 2. SNMPv3 Security

**Category:** Management Plane Security

**Impact:**
SNMPv1/v2c community strings transmitted in cleartext

**Recommendation:**
Configure: snmp-server user [user] [group] v3 auth sha [pass] priv aes 128 [key]

---

#### 3. Management ACL

**Category:** Management Plane Security

**Impact:**
Unrestricted management access from any network increases attack surface

