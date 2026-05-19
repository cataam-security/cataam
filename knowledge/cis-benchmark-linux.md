# CIS Benchmark Linux Hardening Guide

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

**Framework:** CIS Benchmark for Linux v3.0.0  
**Applies to:** Ubuntu 22.04 LTS, RHEL 9, Debian 12, Rocky Linux 9

This guide is the human-readable companion to [`env-hardener.sh`](../tools/env-hardener.sh). It explains the *why* behind each CIS control, not just the *what*.

---

## Section 1: Filesystem Configuration

### 1.1 Disable Unused Filesystems

**Why it matters:** Unused filesystem modules expand the kernel attack surface. If an attacker gains code execution, loading `cramfs` or `udf` could enable privilege escalation through known kernel vulnerabilities in those modules.

```bash
# Disable unused filesystems permanently
for fs in cramfs squashfs udf freevxfs jffs2 hfs hfsplus; do
  echo "install $fs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
done
```

**CIS Controls:** 1.1.1.1 – 1.1.1.8  
**ISO 27001:** A.8.9 (Configuration management)

### 1.2 /tmp Partition Hardening

**Why it matters:** World-writable `/tmp` with execute permissions is a classic vector for privilege escalation — an attacker drops a malicious binary, executes it from `/tmp`. The `noexec` mount option breaks this chain.

```bash
# /etc/fstab entry for /tmp
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0
```

**CIS Control:** 1.1.2.1  
**ISO 27001:** A.8.3 (Information access restriction)

---

## Section 3: Network Configuration

### 3.1 IP Forwarding

**Why it matters:** If IP forwarding is enabled on a server that shouldn't be a router, a compromised host can relay traffic between network segments that would otherwise be isolated.

```bash
# Disable permanently in /etc/sysctl.d/99-cis.conf
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
```

### 3.2 TCP SYN Cookies

**Why it matters:** Mitigates SYN flood denial-of-service attacks by responding to SYN packets with a cryptographic cookie rather than allocating connection state immediately.

```bash
net.ipv4.tcp_syncookies = 1
```

### 3.3 ICMP and Redirect Hardening

```bash
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
```

**CIS Controls:** 3.1 – 3.3  
**ISO 27001:** A.8.20 (Networks security)

---

## Section 4: Access Control

### 4.1 Password Policy (pam_pwquality)

**Why it matters:** Weak password policies are consistently the root cause of initial access in breach reports. A 14-character minimum with complexity requirements dramatically increases offline cracking resistance.

```bash
# /etc/security/pwquality.conf
minlen = 14
minclass = 4
maxrepeat = 3
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
```

**CIS Control:** 4.1.1 – 4.1.7  
**ISO 27001:** A.9.4 (Use of privileged utility programs)

### 4.2 sudo Configuration

**Why it matters:** Unrestricted sudo access (NOPASSWD, ALL) removes an important audit checkpoint. Every privileged action should require re-authentication.

```bash
# Good — require password for sudo
avinash ALL=(ALL:ALL) ALL

# Bad — never use in production
avinash ALL=(ALL) NOPASSWD:ALL
```

**CIS Control:** 4.3  
**ISO 27001:** A.9.2 (User registration and de-registration)

---

## Section 5: SSH Hardening

### Recommended sshd_config

```
# Disable root login
PermitRootLogin no

# Disable password authentication (use keys)
PasswordAuthentication no
PermitEmptyPasswords no

# Disable unnecessary features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no

# Logging and limits
LogLevel INFO
MaxAuthTries 4
MaxSessions 10
LoginGraceTime 60

# Restrict to specific users or groups (customize)
AllowGroups sshusers

# Use only modern algorithms
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

**CIS Controls:** 5.1.1 – 5.1.9  
**ISO 27001:** A.8.20 (Networks security)  
**PCI DSS:** Requirement 2.2 (System components configured securely)

---

## Section 6: Logging and Auditing

### 6.1 rsyslog

**Why it matters:** Centralized logging is the foundation of incident detection and forensic investigation. Without it, an attacker who compromises a host can erase local evidence.

```bash
# Verify rsyslog is running
systemctl is-active rsyslog

# Forward logs to central syslog server (optional but recommended)
# /etc/rsyslog.conf
*.* @@syslog.internal:514   # TCP forwarding
```

### 6.2 auditd — Key Rules

```bash
# Monitor privileged command execution
-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=unset -k setuid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F auid!=unset -k setgid

# Monitor /etc/passwd and /etc/shadow modifications
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers

# Monitor SSH key files
-w /root/.ssh -p wa -k ssh_keys

# Monitor cron modifications
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Make audit log immutable (restart required to change rules)
-e 2
```

**CIS Controls:** 6.1 – 6.3  
**ISO 27001:** A.8.15 (Logging), A.8.17 (Clock synchronization)  
**SOC 2:** CC7.2 (Detection and monitoring)

---

## Quick Reference: Verification Commands

```bash
# Check all sysctl hardening settings
sysctl -a | grep -E "net.ipv4.(ip_forward|conf.all|tcp_syncookies|icmp)"

# Verify no world-writable files outside /tmp
find / -xdev -type f -perm -0002 2>/dev/null | grep -v /tmp

# Check for SUID/SGID files
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null

# Verify auditd rules
auditctl -l

# Check for users with empty passwords
awk -F: '($2 == "") { print $1 }' /etc/shadow
```

---

*Maintained by the [Cataam](https://cataam.com) team. See [`env-hardener.sh`](../tools/env-hardener.sh) to automate these checks.*
