# Debian 13 (Trixie) Hardening Guide for Virtual Machines: CIS Benchmark & Defense-in-Depth

[![Debian](https://img.shields.io/badge/Debian%2013-Trixie%20(Testing%2FStable)-d70a53?logo=debian&logoColor=white)](https://www.debian.org/)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-Debian%20Level%201%20Server-success)](https://www.cisecurity.org/cis-benchmarks/)
[![Virtualization](https://img.shields.io/badge/Virtualization-KVM%20%7C%20Proxmox%20%7C%20VMware-blue)](https://wiki.debian.org/KVM)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> Leia este guia em português: **[Português (Brasil)](HARDENING-DEBIAN13-VM.pt-BR.md)**  
> This guide is dedicated to virtualized servers and instances running **Debian 13 (Trixie)** across modern hypervisors (KVM/QEMU, Proxmox VE, VMware ESXi, Hyper-V, and VirtualBox). For our bare-metal Arch Linux hardening guide, see **[HARDENING.md](HARDENING.md)**.

This document establishes the operational security baseline and defensive hardening standards for virtual instances running **Debian 13**. The configuration adheres strictly to the **CIS Debian Linux Benchmark** (Level 1 Server) and incorporates virtualization-specific mitigations to minimize the attack surface and enforce boundary isolation between the guest operating system and the hypervisor.

---

## Table of Contents

- [1. Threat Model & Virtualization Principles](#1-threat-model--virtualization-principles)
- [2. Layer 1: Virtual Hardware & Firmware (OVMF & Hypervisor)](#2-layer-1-virtual-hardware--firmware-ovmf--hypervisor)
- [3. Layer 2: Kernel, Memory & Sysctl on Debian 13 (CIS 1.5 & 3.x)](#3-layer-2-kernel-memory--sysctl-on-debian-13-cis-15--3x)
- [4. Layer 3: Filesystem Partitioning & Obsolete Modules (CIS 1.1)](#4-layer-3-filesystem-partitioning--obsolete-modules-cis-11)
- [5. Layer 4: TCP/IP Network Stack Hardening & `nftables` Firewall](#5-layer-4-tcpip-network-stack-hardening--nftables-firewall)
- [6. Layer 5: OpenSSH Server Hardening & Privilege Control (CIS 5.x)](#6-layer-5-openssh-server-hardening--privilege-control-cis-5x)
- [7. Layer 6: Mandatory Access Control with AppArmor (Debian Default)](#7-layer-6-mandatory-access-control-with-apparmor-debian-default)
- [8. Layer 7: Continuous Auditing with `auditd` & Unattended Upgrades](#8-layer-7-continuous-auditing-with-auditd--unattended-upgrades)
- [9. Continuous Verification & Health Checklist](#9-continuous-verification--health-checklist)
- [Official References](#official-references)

---

## 1. Threat Model & Virtualization Principles

Virtual machines operate under different security dynamics than bare-metal hosts:
1. **Shared Physical Hardware:** Microarchitectural side-channel attacks (*Spectre*, *Meltdown*, *L1TF*) require memory space layout protections.
2. **Paravirtualized Devices:** `virtio` drivers provide high performance, but unused virtual bus emulators must be pruned.
3. **Hypervisor Guest Agents:** Tools like `qemu-guest-agent` allow the hypervisor to execute arbitrary root commands unless explicitly restricted via blacklists.
4. **Pruning Unused Virtual Hardware:** VMs do not require Bluetooth, audio devices, legacy serial controllers, or floppy disk drives. Removing emulated hardware reduces potential QEMU escape vulnerabilities.

---

## 2. Layer 1: Virtual Hardware & Firmware (OVMF & Hypervisor)

Configure your VM settings on the hypervisor (Proxmox, KVM/QEMU, or VMware) prior to production deployment:

### 2.1. Recommended Hypervisor Configuration (Proxmox / KVM)
* **BIOS / Firmware:** Choose **OVMF (UEFI)** rather than legacy SeaBIOS.
* **Secure Boot:** Enable Secure Boot (Debian officially signs its kernel and GRUB binaries with the Microsoft UEFI CA).
* **vTPM (Virtual TPM 2.0):** Enable TPM 2.0 emulation (via `swtpm` on Proxmox/KVM or vTPM on ESXi).
* **Remove Unnecessary Virtual Devices:**
  * Remove emulated audio controllers (*Audio Device*).
  * Disable unneeded serial/parallel ports.
  * Remove floppy drive controllers.
  * Utilize **VirtIO SCSI** or **VirtIO Block** for disks and **VirtIO Network** with multiqueue.

### 2.2. Hypervisor Agent Hardening (`qemu-guest-agent`)

In KVM/Proxmox environments, `qemu-guest-agent` is critical for clock synchronization, filesystem freezing during backups, and IP discovery. However, by default, the hypervisor can inject arbitrary commands into the guest via `guest-exec`.

1. **Install the Agent:**
   ```bash
   sudo apt update
   sudo apt install -y qemu-guest-agent
   ```
2. **Restrict Arbitrary Remote Command Execution:**
   Edit `/etc/default/qemu-guest-agent` to blacklist remote execution commands (`guest-exec` and `guest-exec-status`):
   ```ini
   DAEMON_ARGS="--blacklist=guest-exec,guest-exec-status"
   ```
   Restart the service:
   ```bash
   sudo systemctl restart qemu-guest-agent
   ```

---

## 3. Layer 2: Kernel, Memory & Sysctl on Debian 13 (CIS 1.5 & 3.x)

Create `/etc/sysctl.d/50-security-hardening.conf` to enforce CIS Level 1 Server memory and kernel controls:

```ini
# ==============================================================================
# Kernel & Memory Hardening - Debian 13 (CIS Level 1 Server)
# ==============================================================================

# 1. Full Address Space Layout Randomization (ASLR - CIS 1.5.3)
kernel.randomize_va_space = 2

# 2. Kernel Log Buffer Restrictions (dmesg - CIS 1.5.2)
kernel.dmesg_restrict = 1

# 3. Kernel Pointer Concealment (/proc/kallsyms)
kernel.kptr_restrict = 2

# 4. Process Tracing Restrictions (LSM Yama - CIS 1.5.4)
# Allows ptrace only with CAP_SYS_PTRACE (admin/root)
kernel.yama.ptrace_scope = 2

# 5. Restrict Unprivileged eBPF & Enable JIT Hardening
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# 6. Filesystem Race Condition Protections (Symlinks & Hardlinks - CIS 1.5.1)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# 7. Disable Core Dumps
fs.suid_dumpable = 0

# 8. Magic SysRq Key Hardening (Restrict to emergency sync/unmount/reboot)
kernel.sysrq = 176

# 9. Virtual Memory Swappiness Tuning
# Avoid aggressive swap page eviction on virtualized hosts
vm.swappiness = 10
```

Apply immediately:
```bash
sudo sysctl --system
```

---

## 4. Layer 3: Filesystem Partitioning & Obsolete Modules (CIS 1.1)

### 4.1. Secure Mount Flags in `/etc/fstab`

Ensure temporary and world-writable directories are mounted with restrictive execution flags:

```text
# Secure /tmp mount in volatile memory (CIS 1.1.2 - 1.1.5)
tmpfs   /tmp        tmpfs   defaults,nosuid,nodev,noexec,mode=1777  0   0

# Secure POSIX shared memory (CIS 1.1.6 - 1.1.8)
tmpfs   /dev/shm    tmpfs   defaults,nosuid,nodev,noexec            0   0
```

Or enable the native systemd mount unit:
```bash
sudo systemctl enable --now tmp.mount
```

### 4.2. Blacklist Obsolete Filesystem Drivers (CIS 1.1.1)

Because virtual machines communicate over virtual network interfaces and block devices, unneeded legacy filesystems should be disabled.

Create `/etc/modprobe.d/blacklist-filesystems.conf`:
```ini
# CIS Benchmark 1.1.1 - Disable unused filesystem drivers
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
```

---

## 5. Layer 4: TCP/IP Network Stack Hardening & `nftables` Firewall

### 5.1. Network Sysctl Hardening: `/etc/sysctl.d/60-network-hardening.conf`

```ini
# ==============================================================================
# TCP/IP Network Hardening - Debian 13 (CIS 3.1 & 3.2)
# ==============================================================================

# 1. Disable IP Forwarding (VM is not an edge router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 2. Strict Reverse Path Filtering (Mitigate IP spoofing on shared bridges - CIS 3.2.7)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 3. Block All ICMP Redirects (CIS 3.2.2)
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

# 5. SYN Flood Mitigation & RFC 1337 Protection (CIS 3.2.8)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# 6. Ignore Broadcast ICMP & Bogus Errors (CIS 3.2.4 & 3.2.5)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 7. Log Martians (Impossible Route Logging - CIS 3.2.3)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 8. Ignore Unsolicited IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
```

### 5.2. Native Firewall with `nftables` (Debian Official Standard)

Debian 13 relies on **`nftables`** as the default packet filtering framework. Configure a default drop policy:

1. **Install and Enable:**
   ```bash
   sudo apt install -y nftables
   sudo systemctl enable --now nftables
   ```
2. **Define Rules in `/etc/nftables.conf`:**
   ```text
   #!/usr/sbin/nft -f

   flush ruleset

   table inet filter {
       chain input {
           type filter hook input priority filter; policy drop;

           # Accept loopback traffic
           iif "lo" accept

           # Accept established/related connections
           ct state established,related accept

           # Drop invalid connection states
           ct state invalid drop

           # Rate-limited ICMP ping
           ip protocol icmp icmp type echo-request limit rate 5/second accept
           ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 5/second accept

           # SSH Access with rate limiting
           tcp dport 22 ct state new limit rate 10/minute accept
       }

       chain forward {
           type filter hook forward priority filter; policy drop;
       }

       chain output {
           type filter hook output priority filter; policy accept;
       }
   }
   ```
3. **Apply & Verify:**
   ```bash
   sudo nft -f /etc/nftables.conf
   sudo systemctl restart nftables
   sudo nft list ruleset
   ```

---

## 6. Layer 5: OpenSSH Server Hardening & Privilege Control (CIS 5.x)

### 6.1. SSH Hardening: `/etc/ssh/sshd_config.d/01-hardening.conf`

```ini
# ==============================================================================
# OpenSSH Server Hardening - Debian 13 (CIS 5.2)
# ==============================================================================

# 1. Disable Direct Root Login (CIS 5.2.8)
PermitRootLogin no

# 2. Disable Password Authentication (Enforce Public Key Auth - CIS 5.2.9)
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no

# 3. Enforce Public Key Authentication
PubkeyAuthentication yes

# 4. Limit Authentication Attempts (CIS 5.2.5)
MaxAuthTries 3

# 5. Modern Cryptography Only (CIS 5.2.11)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# 6. Disable Unnecessary Port & Agent Forwarding (CIS 5.2.6)
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no

# 7. Idle Session Timeouts (CIS 5.2.13)
ClientAliveInterval 300
ClientAliveCountMax 2

# 8. Verbose Auditing Logs (CIS 5.2.3)
LogLevel VERBOSE
```

Test and reload SSH:
```bash
sudo sshd -t
sudo systemctl reload ssh
```

### 6.2. Secure `sudo` Configuration (CIS 5.3)

Create `/etc/sudoers.d/01-security-hardening`:

```bash
sudo visudo -f /etc/sudoers.d/01-security-hardening
```

Insert:
```text
# Enforce execution in dedicated PTY to prevent terminal hijacking (CIS 5.3.2)
Defaults use_pty

# Log administrative actions (CIS 5.3.3)
Defaults logfile="/var/log/sudo.log"

# Limit ticket timeout to 5 minutes (CIS 5.3.4)
Defaults timestamp_timeout=5

# Limit invalid password attempts
Defaults passwd_tries=3
```

---

## 7. Layer 6: Mandatory Access Control with AppArmor (Debian Default)

Unlike distributions where MAC systems must be installed manually, **Debian installs and enables AppArmor by default**.

1. **Verify AppArmor Status:**
   ```bash
   sudo aa-status
   ```
2. **Install Extra Profiles & Utilities:**
   ```bash
   sudo apt install -y apparmor-profiles apparmor-utils
   ```
3. **Enforce All Loaded Profiles:**
   ```bash
   sudo aa-enforce /etc/apparmor.d/*
   ```

---

## 8. Layer 7: Continuous Auditing with `auditd` & Unattended Upgrades

### 8.1. Audit Logging with `auditd` (CIS 4.x)

1. **Install `auditd`:**
   ```bash
   sudo apt install -y auditd
   sudo systemctl enable --now auditd
   ```
2. **Rules Configuration (`/etc/audit/rules.d/50-security.rules`):**
   ```ini
   -D
   -b 8192
   -f 1

   # Audit account and password database modifications (CIS 4.1.4)
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

   # Audit filesystem mount operations (CIS 4.1.13)
   -a always,exit -F arch=b64 -S mount,umount2 -k mounts

   # Make configuration immutable until reboot (CIS 4.1.17)
   -e 2
   ```
3. **Apply Rules:**
   ```bash
   sudo augenrules --load
   sudo auditctl -s
   ```

### 8.2. Automated Security Patches with `unattended-upgrades`

1. **Install Packages:**
   ```bash
   sudo apt install -y unattended-upgrades apt-listchanges
   ```
2. **Enable Service:**
   ```bash
   sudo dpkg-reconfigure -plow unattended-upgrades
   ```
3. **Verify Security Origins in `/etc/apt/apt.conf.d/50unattended-upgrades`:**
   ```text
   Unattended-Upgrade::Origins-Pattern {
       "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
   };
   Unattended-Upgrade::AutoFixInterruptedDpkg "true";
   Unattended-Upgrade::MinimalSteps "true";
   Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
   Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
   ```

### 8.3. File Integrity Verification with `debsums`

Detect tampered or corrupted system binaries against Debian's official package checksums:

```bash
sudo apt install -y debsums
sudo debsums -c
```

---

## 9. Continuous Verification & Health Checklist

| Control | Audit Command | Expected Output |
| :--- | :--- | :--- |
| **AppArmor** | `aa-status` | `apparmor module is loaded; ... profiles in enforce mode` |
| **Firewall** | `nft list ruleset` | `chain input { type filter ... policy drop; }` |
| **SSH Root** | `sshd -T \| grep permitrootlogin` | `permitrootlogin no` |
| **SSH Passwords** | `sshd -T \| grep passwordauthentication` | `passwordauthentication no` |
| **ASLR** | `sysctl kernel.randomize_va_space` | `kernel.randomize_va_space = 2` |
| **Yama ptrace** | `sysctl kernel.yama.ptrace_scope` | `kernel.yama.ptrace_scope = 2` |
| **Auditd** | `auditctl -s` | `enabled 2` (immutable) |
| **Reverse Path** | `sysctl net.ipv4.conf.all.rp_filter` | `net.ipv4.conf.all.rp_filter = 1` |
| **SYN Cookies** | `sysctl net.ipv4.tcp_syncookies` | `net.ipv4.tcp_syncookies = 1` |
| **Integrity** | `debsums -c` | Empty output (zero tampered files) |

---

## Official References

* [CIS Center for Internet Security: Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux)
* [Debian Wiki: Securing Debian Manual](https://www.debian.org/doc/manuals/securing-debian-manual/)
* [Debian Wiki: AppArmor](https://wiki.debian.org/AppArmor)
* [Debian Wiki: nftables](https://wiki.debian.org/nftables)
* [Debian Wiki: UnattendedUpgrades](https://wiki.debian.org/UnattendedUpgrades)
* [QEMU Documentation: Guest Agent Security Considerations](https://www.qemu.org/docs/master/interop/qemu-ga.html)
