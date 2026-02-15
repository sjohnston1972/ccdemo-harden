# Pre-Deployment Checklist for Hardening Changes

## ⚠️ MANDATORY STEPS - DO NOT SKIP

### Before Making ANY Changes

- [ ] **Backup current configuration**
  ```
  copy running-config tftp://backup-server/hostname-pre-hardening-2026-02-15.cfg
  copy startup-config tftp://backup-server/hostname-startup-pre-hardening-2026-02-15.cfg
  ```

- [ ] **Have console access ready** (physical or remote console)
  - Do NOT rely solely on SSH during configuration changes

- [ ] **Schedule maintenance window**
  - Notify stakeholders
  - Document change control ticket
  - Plan for 1-2 hours

- [ ] **Identify critical information**
  - [ ] Your management network(s): `_______________________`
  - [ ] NTP server IP: `_______________________`
  - [ ] TACACS+ server IP: `_______________________`
  - [ ] TACACS+ shared secret: `_______________________`
  - [ ] Syslog server IP: `_______________________`
  - [ ] SNMPv3 auth password: `_______________________`
  - [ ] SNMPv3 priv password: `_______________________`

- [ ] **Verify device role and interfaces**
  - [ ] This is NOT a core/critical device (or apply extra caution)
  - [ ] Management interface is: `_______________________`
  - [ ] Trunk/uplink ports are: `_______________________`
  - [ ] Access ports range: `_______________________`

### Testing Requirements (HIGHLY RECOMMENDED)

- [ ] **Test in lab environment first**
  - Use identical hardware/IOS version if possible
  - Verify all commands work without errors
  - Test rollback procedures

- [ ] **Test with dry-run mode**
  ```
  python cisco_audit.py --dry-run
  ```

- [ ] **Review all placeholders replaced**
  - Search files for `<` and `>` characters
  - Ensure no placeholder values remain

### During Configuration

- [ ] **Apply changes in sections** (HIGH → MEDIUM → LOW)
- [ ] **Test after each HIGH RISK change**
  - Especially Management ACL
  - Especially AAA configuration
- [ ] **Keep a second SSH session open**
  - Don't close your working session until verified
- [ ] **Save after each successful section**
  ```
  write memory
  ```

### Critical Change Validation

#### After Management ACL (MUST TEST)
```bash
# From another terminal/workstation:
ssh username@192.168.20.117

# If successful, you're good
# If it fails, use console to rollback:
# config t
# line vty 0 4
#  no access-class 10 in
# exit
```

#### After AAA Configuration (MUST TEST)
```bash
# Test TACACS+ authentication:
test aaa group TACACS-GROUP <username> <password> new-code

# Try SSH from new session
ssh tacacs-user@192.168.20.117

# If fails, use console:
# config t
# no aaa new-model
# exit
```

#### After DHCP Snooping/DAI
```bash
# Verify clients can still get DHCP addresses
# Check for unexpected port shutdowns
show ip dhcp snooping binding
show ip arp inspection statistics
show interface status
```

### Post-Configuration Verification

- [ ] **Run full verification commands** (from remediation guide)
  ```
  show ip ssh
  show aaa servers
  show ntp status
  show ip dhcp snooping
  show ip arp inspection
  show spanning-tree summary
  show policy-map control-plane
  show logging
  show access-lists
  ```

- [ ] **Save configuration**
  ```
  write memory
  ```

- [ ] **Backup new configuration**
  ```
  copy running-config tftp://backup-server/hostname-post-hardening-2026-02-15.cfg
  ```

- [ ] **Re-run security audit**
  ```
  python cisco_audit.py --non-interactive --format json
  ```
  - Expected score: **90%+** (up from 47.2%)

- [ ] **Verify no service disruptions**
  - [ ] Can still SSH from management network
  - [ ] Routing protocols stable (if applicable)
  - [ ] End users not reporting issues
  - [ ] Monitoring systems can still reach device

### Rollback Plan (If Things Go Wrong)

#### Quick Rollback Options

1. **Remove Management ACL** (if locked out)
   ```
   # From console:
   configure terminal
   line vty 0 4
    no access-class 10 in
   exit
   ```

2. **Disable AAA** (if authentication broken)
   ```
   # From console:
   configure terminal
   no aaa new-model
   exit
   ```

3. **Full Configuration Restore**
   ```
   # From console or SSH:
   copy tftp://backup-server/hostname-pre-hardening-2026-02-15.cfg running-config
   reload
   ```

4. **ROMMON Password Recovery** (last resort)
   - Boot into ROMMON mode
   - Set config register: `confreg 0x2142`
   - Reboot, restore from backup

### Success Criteria

- [ ] All HIGH priority issues resolved
- [ ] Compliance score improved to 90%+
- [ ] No service disruptions reported
- [ ] All verification commands passed
- [ ] Monitoring systems operational
- [ ] Documentation updated

### Documentation Requirements

- [ ] Update change management system
- [ ] Document applied changes
- [ ] Update network diagrams (if ACLs/VLANs changed)
- [ ] Notify team of hardening changes
- [ ] Archive audit reports (before/after)
- [ ] Update runbooks with new security configs

## 🔒 Security Best Practices

### Never Do This
- ❌ Apply all changes at once without testing
- ❌ Configure Management ACL without console access ready
- ❌ Test AAA with only one session open
- ❌ Apply during business hours (unless emergency)
- ❌ Skip backup before changes
- ❌ Modify management VRF or interface Ethernet3/3

### Always Do This
- ✅ Test in lab first (if possible)
- ✅ Have console access ready
- ✅ Keep backup SSH session open
- ✅ Save config after each successful section
- ✅ Document everything
- ✅ Verify before moving to next section

## 📞 Emergency Contacts

**If issues occur during implementation:**
- Network Team Lead: `_______________________`
- TAC/Support: `_______________________`
- Console Access: `_______________________`

## 📝 Implementation Log

| Section | Start Time | End Time | Status | Notes |
|---------|-----------|----------|--------|-------|
| Backup Config | | | ⬜ | |
| NTP Auth | | | ⬜ | |
| SNMPv3 | | | ⬜ | |
| Mgmt ACL | | | ⬜ | **TEST BEFORE PROCEEDING** |
| HTTP Disable | | | ⬜ | |
| DHCP Snooping | | | ⬜ | |
| DAI | | | ⬜ | |
| BPDU Guard | | | ⬜ | |
| CoPP | | | ⬜ | |
| AAA/TACACS+ | | | ⬜ | **TEST BEFORE DISCONNECTING** |
| SSH Hardening | | | ⬜ | |
| Syslog | | | ⬜ | |
| CDP Security | | | ⬜ | |
| Loop Guard | | | ⬜ | |
| Banners | | | ⬜ | |
| Legacy Services | | | ⬜ | |
| Final Verification | | | ⬜ | |
| Re-run Audit | | | ⬜ | Target: 90%+ |

---

**Date:** 2026-02-15
**Device:** 192.168.20.117 (hostname)
**Engineer:** `_______________________`
**Change Ticket:** `_______________________`

---

## Final Sign-Off

- [ ] All changes applied successfully
- [ ] All tests passed
- [ ] No service disruptions
- [ ] Configuration saved and backed up
- [ ] Audit shows compliance improvement
- [ ] Team notified of changes

**Completed by:** `_______________________`
**Date/Time:** `_______________________`
**New Compliance Score:** `______%` (was 47.2%)
