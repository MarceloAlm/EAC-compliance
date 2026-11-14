# Arch Linux Hardening Guide: CIS Benchmark Alignment & Defense-in-Depth

[![Arch Linux](https://img.shields.io/badge/Arch%20Linux-Hardened-1793d1?logo=arch-linux&logoColor=white)](https://archlinux.org/)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-Level%201%20%26%202-success)](https://www.cisecurity.org/cis-benchmarks/)
[![Secure Boot](https://img.shields.io/badge/UEFI-Secure%20Boot%20Enabled-blue?logo=linux&logoColor=white)](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> Leia este guia em português: **[Português (Brasil)](HARDENING.pt-BR.md)**  
> This guide is the companion security hardening reference for the repository, building directly on the boot and kernel foundation established in the **[EAC Linux v2 Guide](README.md)**.

This document consolidates production-grade technical hardening procedures to transform an **Arch Linux** installation into a high-security operational environment. Recommendations strictly follow the **CIS Linux Benchmark** (*Center for Internet Security*), spanning from firmware integrity to user space, without disrupting daily workstation productivity, browser security, or GPU gaming performance.

---

## Table of Contents

- [1. Defense-in-Depth Principles & CIS Levels](#1-defense-in-depth-principles--cis-levels)
- [2. Layer 1: Firmware, Boot & Ring-0 Integrity (The Base Foundation)](#2-layer-1-firmware-boot--ring-0-integrity-the-base-foundation)
- [3. Layer 2: Kernel & Memory Hardening via Sysctl (CIS 1.5 & 3.x)](#3-layer-2-kernel--memory-hardening-via-sysctl-cis-15--3x)
- [4. Layer 3: Filesystem Protections & Legacy Module Blacklisting (CIS 1.1)](#4-layer-3-filesystem-protections--legacy-module-blacklisting-cis-11)
- [5. Layer 4: TCP/IP Network Stack Hardening (CIS 3.1 & 3.2)](#5-layer-4-tcpip-network-stack-hardening-cis-31--32)
- [6. Layer 5: Privilege Control, PAM & Secure Sudo (CIS 5.x)](#6-layer-5-privilege-control-pam--secure-sudo-cis-5x)
- [7. Layer 6: System Event Auditing with `auditd` (CIS 4.x)](#7-layer-6-system-event-auditing-with-auditd-cis-4x)
- [8. Continuous Verification & Health Checklist](#8-continuous-verification--health-checklist)
- [Official References](#official-references)

---

## 1. Defense-in-Depth Principles & CIS Levels

The **Defense-in-Depth** model assumes that no single security measure is impenetrable. The system is fortified through concentric protective rings:

```
[ User / Applications ]
        │
        ▼ (Secure Sudo, PAM, umask 027, Core Dumps Disabled)
[ Operating System ]
        │
        ▼ (Filesystem protections, noexec/nosuid mounts, obsolete fs blacklisting)
[ Network & Transport ]
        │
        ▼ (SYN Cookies, strict rp_filter, ICMP redirects disabled)
[ Kernel & Memory ]
        │
        ▼ (Sysctl Hardening, ASLR 2, Yama ptrace_scope 2, BPF JIT harden)
[ Firmware & Hardware ]
          (UEFI Secure Boot, TPM 2.0 PCRs, IOMMU DMA pt, Kernel Lockdown)
```

### CIS Benchmark Profiles:
* **Level 1 (Workstation / Baseline):** Practical configurations that provide strong defense posture without breaking desktop applications, web browsers, development toolchains, or gaming engines.
* **Level 2 (High Security / Hardened):** Stricter posture with restricted debuggers, strict syscall auditing, and rigorous memory boundaries.

---

## 2. Layer 1: Firmware, Boot & Ring-0 Integrity (The Base Foundation)

The foundational integrity layers leverage the architecture configured in the primary guide:

1. **UEFI Secure Boot in User Mode (`SetupMode = 0`):**
   * Enforces cryptographic verification on all boot binaries via the UEFI `db` and MOK keyring.
   * Automated signing of kernels and UKIs via `sbctl`.
2. **TPM 2.0 & Measured Boot:**
   * Strict measurement across PCRs (0 through 11), auditing firmware, bootloader stages, and initramfs transitions.
3. **`kexec` Disabled:**
   * Prevents loading unverified kernels in RAM (`kernel.kexec_load_disabled = 1`).
4. **IOMMU Bus Isolation (`intel_iommu=on iommu=pt`):**
   * Active DMAR memory table protection preventing malicious physical DMA attacks from PCIe, Thunderbolt, or USB4 devices.
5. **Kernel Lockdown (`lockdown=integrity`):**
   * Ring-0 barrier disabling `/dev/mem`, CPU MSR write access, and unsigned module execution.

---

## 3. Layer 2: Kernel & Memory Hardening via Sysctl (CIS 1.5 & 3.x)

The following parameters protect against memory corruption, pointer leaks, and unprivileged kernel tampering at runtime.

### Configuration: `/etc/sysctl.d/50-security-hardening.conf`

Create the configuration file with the following documented directives:

```ini
# ==============================================================================
# Kernel & Memory Hardening (CIS Benchmark Level 1 & 2)
# ==============================================================================

# 1. Full Address Space Layout Randomization (ASLR)
# 2 = Fully randomize stack, heap, and shared library locations (CIS 1.5.3)
kernel.randomize_va_space = 2

# 2. Kernel Log Buffer Restrictions (dmesg)
# Prevents unprivileged users from reading kernel addresses and pointers via dmesg (CIS 1.5.2)
kernel.dmesg_restrict = 1

# 3. Kernel Pointer Concealment (/proc/kallsyms)
# 2 = Hides kernel pointers from all users (including root unless CAP_SYSLOG is active)
kernel.kptr_restrict = 2

# 4. Process Tracing Scope (LSM Yama)
# 1 = Only direct parent processes can attach ptrace
# 2 = Only processes with CAP_SYS_PTRACE (admin) can trace (prevents unauthorized process injection)
kernel.yama.ptrace_scope = 2

# 5. eBPF JIT Compiler Hardening
# 1 = Disables unprivileged eBPF usage
# 2 = Applies constant blinding against speculative execution (Spectre) on JIT code
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# 6. Filesystem Race Condition Protections (Symlinks & Hardlinks)
# Prevents symlink/hardlink spoofing attacks in world-writable directories like /tmp (CIS 1.5.1)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# 7. Magic SysRq Key Hardening
# Restricts Magic SysRq to emergency sync/unmount/reboot (176) or disables entirely (0)
kernel.sysrq = 176

# 8. Disable Core Dumps for SUID Programs
# Prevents sensitive process memory (passwords, tokens) from being written to disk on crashes
fs.suid_dumpable = 0
```

Apply immediately with:
```bash
sudo sysctl --system
```

---

## 4. Layer 3: Filesystem Protections & Legacy Module Blacklisting (CIS 1.1)

### 4.1. Restrictive Mount Options for Temporary Filesystems

Directories with world-writable permissions (`/tmp`, `/dev/shm`, `/var/tmp`) should have binary execution and privilege escalation disabled.

#### 1. Secure `/tmp` Mount (via systemd `tmp.mount`):
Arch Linux mounts `/tmp` as `tmpfs` automatically. Enable and enforce secure mount flags:

```bash
sudo cp /usr/share/systemd/tmp.mount /etc/systemd/system/tmp.mount
sudo vim /etc/systemd/system/tmp.mount
```
Ensure the `Options` line contains:
```ini
Options=mode=1777,strictatime,nosuid,nodev,noexec
```
Reload and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tmp.mount
```

#### 2. Secure `/dev/shm` Mount:
Append to `/etc/fstab` to lock POSIX shared memory:
```text
tmpfs   /dev/shm    tmpfs   defaults,nosuid,nodev,noexec    0   0
```

---

### 4.2. Blacklist Obsolete Filesystems (CIS 1.1.1)

Unused, legacy filesystem formats pose unnecessary kernel attack surface when inserting untrusted USB drives.

Create `/etc/modprobe.d/blacklist-filesystems.conf`:
```ini
# Disable unused, legacy, or vulnerable filesystem drivers
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
```

---

## 5. Layer 4: TCP/IP Network Stack Hardening (CIS 3.1 & 3.2)

For endpoints and workstations, the network stack should discard malformed packets, enforce strict path filtering, and disable routing capabilities.

### Configuration: `/etc/sysctl.d/60-network-hardening.conf`

```ini
# ==============================================================================
# TCP/IP Network Stack Hardening (CIS Benchmark 3.1, 3.2 & 3.3)
# ==============================================================================

# 1. Disable Packet Forwarding (Endpoint is not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 2. Strict Reverse Path Filtering (Mitigates IP Spoofing - CIS 3.2.7)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 3. Block ICMP Redirects (Prevents Man-in-the-Middle routing attacks - CIS 3.2.2)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 4. Block Source-Routed Packets (CIS 3.2.1)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 5. TCP SYN Cookies & RFC 1337 Protection (Mitigates SYN Flood attacks - CIS 3.2.8)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# 6. Ignore Broadcast ICMP & Bogus Errors (CIS 3.2.4 & 3.2.5)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 7. Log Packets with Impossible Addresses (Martians - CIS 3.2.3)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 8. Ignore Unsolicited IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
```

### 5.2. Blacklist Uncommon Network Protocols (CIS 3.4)

Create `/etc/modprobe.d/blacklist-protocols.conf`:
```ini
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
```

---

## 6. Layer 5: Privilege Control, PAM & Secure Sudo (CIS 5.x)

### 6.1. Secure `sudo` Configuration (CIS 5.3)

Ensure `sudo` executes inside its own dedicated pseudoterminal (PTY) and logs all administrative executions.

Create `/etc/sudoers.d/01-security-hardening` with syntax validation:

```bash
sudo visudo -f /etc/sudoers.d/01-security-hardening
```

Insert the following rules:
```text
# Run sudo in a dedicated pseudo-terminal to prevent terminal hijacking (CIS 5.3.2)
Defaults use_pty

# Log administrative command executions to a dedicated log file (CIS 5.3.3)
Defaults logfile="/var/log/sudo.log"

# Limit password timeout to 5 minutes (CIS 5.3.4)
Defaults timestamp_timeout=5

# Limit incorrect password attempts before exiting
Defaults passwd_tries=3
```

### 6.2. Disable User-Space Core Dumps (CIS 1.5.1)

Core dumps can leak sensitive operational memory (tokens, passwords, encryption keys).

1. In `/etc/security/limits.d/10-coredump.conf`:
   ```text
   * hard core 0
   * soft core 0
   ```
2. In `/etc/systemd/coredump.conf`:
   ```ini
   [Coredump]
   Storage=none
   ProcessSizeMax=0
   ```

---

## 7. Layer 6: System Event Auditing with `auditd` (CIS 4.x)

The Linux Audit Daemon (`auditd`) provides tamper-evident logging for critical syscalls, privilege escalation, and credential modifications.

### 1. Install & Enable `auditd`:
```bash
sudo pacman -S audit
sudo systemctl enable --now auditd
```

### 2. Essential Audit Rules (`/etc/audit/rules.d/50-security.rules`):

```ini
# Reset existing rules
-D

# Buffer size
-b 8192

# Failure mode: 1 = silent log failure (avoids kernel panic on buffer overflow)
-f 1

# Audit system time modifications (CIS 4.1.3)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change

# Audit identity and authentication changes (CIS 4.1.4)
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Audit network environment changes (CIS 4.1.5)
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system_locale
-w /etc/issue -p wa -k system_locale
-w /etc/hosts -p wa -k system_locale

# Audit sudoers configuration modifications (CIS 4.1.10)
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Lock audit configuration immutable until reboot (CIS 4.1.17)
-e 2
```

Reload audit rules:
```bash
sudo augenrules --load
```

---

## 8. Continuous Verification & Health Checklist

Run these quick inspection commands to verify active defenses:

| Component | Audit Command | Expected Output |
| :--- | :--- | :--- |
| **Secure Boot** | `sbctl status` | `Secure Boot: ✓ Enabled` |
| **ASLR** | `sysctl kernel.randomize_va_space` | `kernel.randomize_va_space = 2` |
| **Yama ptrace** | `sysctl kernel.yama.ptrace_scope` | `kernel.yama.ptrace_scope = 2` |
| **Reverse Path** | `sysctl net.ipv4.conf.all.rp_filter` | `net.ipv4.conf.all.rp_filter = 1` |
| **SYN Cookies** | `sysctl net.ipv4.tcp_syncookies` | `net.ipv4.tcp_syncookies = 1` |
| **Auditd** | `auditctl -s` | `enabled 2, pid ...` |
| **Core Dumps** | `ulimit -c` | `0` |

---

## Official References

* [CIS Center for Internet Security: Distribution-Independent Linux Benchmark](https://www.cisecurity.org/benchmark/distribution_independent_linux)
* [ArchWiki: Security Hardening](https://wiki.archlinux.org/title/Security)
* [ArchWiki: Sysctl Hardening](https://wiki.archlinux.org/title/Sysctl#Security)
* [Kernel.org: Admin Guide - Linux Security Hardening](https://docs.kernel.org/admin-guide/index.html)
* [Kernel.org: Yama LSM Documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
