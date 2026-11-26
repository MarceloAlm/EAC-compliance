# Arch Linux Guide: Secure Boot, TPM 2.0, and CachyOS Signed Kernel for EAC Linux v2

[![Arch Linux](https://img.shields.io/badge/Arch%20Linux-Kernel%206.x%2F7.x-1793d1?logo=arch-linux&logoColor=white)](https://archlinux.org/)
[![CachyOS EAC](https://img.shields.io/badge/CachyOS-linux--cachyos--eac-00a896?logo=linux&logoColor=white)](https://wiki.cachyos.org/configuration/easy_anti_cheat/)
[![Secure Boot](https://img.shields.io/badge/UEFI-Secure%20Boot%20Enabled-success?logo=linux&logoColor=white)](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
[![Lockdown](https://img.shields.io/badge/Kernel%20Lockdown-integrity-blue)](https://docs.kernel.org/admin-guide/module-signing.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> Read this document in Portuguese: **[Português (Brasil)](README.pt-BR.md)**  
> Also check out our companion security guide: **[Hardening & CIS Benchmark Guide](HARDENING.md)**  
> Reference documentation for the legacy manual approach (Shim + MOK): **[SHIM-MOK-REFERENCIA.pt-BR.md](SHIM-MOK-REFERENCIA.pt-BR.md)** *(Portuguese)*  
> Migration guide from Shim/MOK to `linux-cachyos-eac`: **[MIGRACAO-CACHYOS-EAC.md](MIGRACAO-CACHYOS-EAC.md)** *(Portuguese)*

This document records the configurations, official references, and complete step-by-step instructions to deploy and maintain an **Arch Linux** system in full compliance with the strict requirements of **Easy Anti-Cheat (EAC) Linux v2** using the official pre-signed CachyOS kernel (**`linux-cachyos-eac`**) and signed **`systemd-boot`**, while keeping the standard Arch kernel (`linux`) intact for daily use (hibernation, VirtualBox/DKMS, and productivity).

> [!IMPORTANT]
> **Why `linux-cachyos-eac` instead of local MOK keys?**
> To prevent cheats from signing malicious modules with self-generated keys, Epic Games maintains a **closed list of recognized public keys** (*Well-Known Key List*) and **does not accept locally user-generated MOK keys**. CachyOS maintains an official Certificate Authority (`CachyOS EAC CA`) recognized by EAC Linux v2 and distributes the `linux-cachyos-eac` kernel + pre-compiled modules (`linux-cachyos-eac-nvidia-open`) + `systemd-boot-cachyos-signed` directly in its `[cachyos]` repository.

---

## Table of Contents

- [1. Easy Anti-Cheat Linux v2 Technical Requirements](#1-easy-anti-cheat-linux-v2-technical-requirements)
  - [1.1. Defense Vector Matrix & Practical System Restrictions](#11-defense-vector-matrix--practical-system-restrictions)
- [2. Dual-Boot Architecture on Arch Linux (Daily Use vs. EAC v2)](#2-dual-boot-architecture-on-arch-linux-daily-use-vs-eac-v2)
- [3. Manual Step-by-Step Implementation (Without `eac-setup`)](#3-manual-step-by-step-implementation-without-eac-setup)
  - [Phase 1: Base Secure Boot with `sbctl` (Standard Kernel Only)](#phase-1-base-secure-boot-with-sbctl-standard-kernel-only)
  - [Phase 2: Add Only the `[cachyos]` Repository on Arch Linux](#phase-2-add-only-the-cachyos-repository-on-arch-linux)
  - [Phase 3: Install EAC Kernel, Signed Bootloader, and NVIDIA Driver](#phase-3-install-eac-kernel-signed-bootloader-and-nvidia-driver)
  - [Phase 4: Manually Configure the EAC Entry and Protect Signatures](#phase-4-manually-configure-the-eac-entry-and-protect-signatures)
  - [Phase 5: Enroll Keys in UEFI (`--microsoft --custom`) and Enable Secure Boot](#phase-5-enroll-keys-in-uefi---microsoft---custom-and-enable-secure-boot)
  - [Optional Alternative: Automation with `cachyos-settings` (`eac-setup`)](#optional-alternative-automation-with-cachyos-settings-eac-setup)
- [4. Automated Direct Kernel Auditor (`check-eac-compliance.sh`)](#4-automated-direct-kernel-auditor-check-eac-compliancesh)
- [5. Post-Boot Verification Guide](#5-post-boot-verification-guide)
- [6. Maintenance and Updates](#6-maintenance-and-updates)
- [7. Official References](#7-official-references)
- [License](#license)

---

## 1. Easy Anti-Cheat Linux v2 Technical Requirements

EAC Linux v2 replaces invasive ring-0 drivers with an on-demand **`systemd`** service coupled with **`eBPF`** programs, requiring a strict chain of trust across the operating system:

1. **UEFI [Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) Enabled** in User Mode (`SetupMode = 0`) with recognized keys (`CachyOS EAC CA` + Microsoft).
2. **TPM 2.0 & Measured Boot** operational with an active SHA-256 bank.
3. **Cryptographically Signed Kernel, Bootloader, and Modules** (`module.sig_enforce=1`).
4. **Kernel Lockdown in `integrity` Mode** (`/sys/kernel/security/lockdown` set to `[integrity]`), blocking kernel-space modifications even by the `root` user.
5. **`kexec` Disabled** (`kernel.kexec_load_disabled = 1`), preventing injection of unverified kernels via RAM.
6. **IOMMU Enabled** (Intel VT-d with `intel_iommu=on iommu=pt iommu.passthrough=0`, or AMD-Vi equivalent), blocking DMA attacks from physical peripherals.
7. **LSM BPF Enabled** (`lsm=landlock,lockdown,yama,integrity,bpf`), allowing the anti-cheat integrity probes to be audited via the Security Module.

### 1.1. Defense Vector Matrix & Practical System Restrictions

| # | Technical Requirement | EAC Defense Vector | Practical System Consequence |
| :--- | :--- | :--- | :--- |
| **1** | **UEFI Secure Boot** (`SetupMode = 0`) | Prevents loading tampered bootloaders, kernels, or EFI binaries before the OS starts. | **Unsigned binaries fail to boot.** Live USBs without a recognized signature trigger `Security Violation`. |
| **2** | **TPM 2.0 & Measured Boot** (PCRs) | Audits changes to firmware, BIOS, bootloader, and `cmdline`. | **TPM-bound LUKS is sensitive:** BIOS updates or `cmdline` changes alter PCRs. |
| **3** | **Module Signing** (`module.sig_enforce=1`) | Blocks injection of unsigned drivers into Ring-0. | **DKMS does not work on the EAC kernel.** Use the pre-compiled packages (`linux-cachyos-eac-nvidia-open`); keep VirtualBox/DKMS on the standard `linux` kernel. |
| **4** | **Kernel Lockdown** (`[integrity]`) | Isolates kernel memory from user space (even `root`). | **Hibernation blocked** in the EAC boot; MSR writes blocked (prevents software undervolting); `debugfs` restricted. |
| **5** | **`kexec` Disabled** (`kexec_load_disabled = 1`) | Prevents hot-jumping between kernels in RAM without going through UEFI. | **`systemctl kexec` disabled.** Kernel switches require a full hardware reboot. |
| **6** | **IOMMU Isolation** (`intel_iommu=on iommu.passthrough=0`) | Mitigates DMA attacks via PCIe / Thunderbolt hardware. | DMA traffic is filtered by IOMMU hardware. |
| **7** | **LSM BPF Enabled** (`bpf`) | Allows EAC to inspect and veto syscalls via eBPF. | Memory debuggers (GDB, Cheat Engine via Proton) are blocked when inspecting the game. |

---

## 2. Dual-Boot Architecture on Arch Linux (Daily Use vs. EAC v2)

By keeping both kernels side by side, you avoid all Lockdown restrictions in day-to-day usage:

| Profile | Boot Entry | Kernel | NVIDIA Driver | Features |
| :--- | :--- | :--- | :--- | :--- |
| **Desktop / Work (Default)** | `/boot/EFI/Linux/arch-linux.efi` (UKI signed by `sbctl`) | `linux` (official Arch) | `nvidia-open` | Hibernation (`resume=`), VirtualBox (`virtualbox-host-dkms`), undervolting |
| **Gaming / EAC Linux v2** | `/boot/loader/entries/cachyos-eac.conf` | `linux-cachyos-eac` (signed by CachyOS) | `linux-cachyos-eac-nvidia-open` | `lockdown=integrity`, `module.sig_enforce=1`, `CachyOS EAC CA`, 100% EAC v2 compliant |

> [!NOTE]
> For the alternative/legacy architecture using **Shim (`shimx64.efi`) + local MOK**, see [SHIM-MOK-REFERENCIA.pt-BR.md](SHIM-MOK-REFERENCIA.pt-BR.md) *(Portuguese)*.

---

## 3. Manual Step-by-Step Implementation (Without `eac-setup`)

### Phase 1: Base Secure Boot with `sbctl` (Standard Kernel Only)

Refer to the official [ArchWiki: sbctl](https://wiki.archlinux.org/title/Sbctl) guide:

1. **Install `sbctl` and create your local keys** (if you haven't already):
   ```bash
   sudo pacman -S sbctl
   sudo sbctl create-keys
   ```

2. **Sign only your default UKI (and/or standard kernel) with `sbctl`:**
   ```bash
   sudo sbctl sign -s /boot/EFI/Linux/arch-linux.efi
   ```
   > [!IMPORTANT]
   > **Do not** add `/boot/EFI/systemd/systemd-bootx64.efi`, `/boot/EFI/BOOT/BOOTX64.EFI`, or `/boot/vmlinuz-linux-cachyos-eac` to the `sbctl` database. Those files will use the official **CachyOS EAC CA** signature (installed in Phase 3). If `sbctl` re-signs them with your local key, EAC verification will fail.

---

### Phase 2: Add Only the `[cachyos]` Repository on Arch Linux

To keep your system **pure Arch Linux** (without replacing system packages with CachyOS `x86-64-v3` builds), add the repositories using the official script and keep **only `[cachyos]`** at the end of `/etc/pacman.conf`:

1. **Download and run the repository installer in `/tmp`:**
   ```bash
   cd /tmp
   curl -O https://mirror.cachyos.org/cachyos-repo.tar.xz
   tar xvf cachyos-repo.tar.xz && cd cachyos-repo
   sudo ./cachyos-repo.sh
   ```
   *(When the script prompts `Starting full system upgrade`, press **`N`** before adjusting `/etc/pacman.conf` so it does not replace Arch packages from the `*-v3` repositories).*

2. **Adjust `/etc/pacman.conf` (`sudo vim /etc/pacman.conf`):**
   - Remove or comment out `[cachyos-v3]`, `[cachyos-core-v3]`, and `[cachyos-extra-v3]`.
   - Move the `[cachyos]` block to the **end** of the file (below `[core]`, `[extra]`, and `[multilib]`):
     ```ini
     [cachyos]
     Include = /etc/pacman.d/cachyos-mirrorlist
     ```

3. **Optional — clean up unused mirrorlists and ensure `pacman` comes from `core`:**
   ```bash
   sudo pacman -S core/pacman
   sudo pacman -Rns cachyos-v3-mirrorlist cachyos-v4-mirrorlist
   sudo pacman -Syu
   ```

---

### Phase 3: Install EAC Kernel, Signed Bootloader, and NVIDIA Driver

1. **Install the required packages from Arch and `[cachyos]`:**
   ```bash
   sudo pacman -S sbsigntools tpm2-tools efibootmgr \
     cachyos-eac-signing-key linux-cachyos-eac systemd-boot-cachyos-signed \
     linux-cachyos-eac-nvidia-open nvidia-open
   ```
   *(For Turing or newer NVIDIA GPUs — GTX 16xx / RTX 20xx+ — use `linux-cachyos-eac-nvidia-open` + `nvidia-open`. For Maxwell/Pascal/Volta, use `linux-cachyos-eac-nvidia-580xx`).*

2. **Optional — avoid `virtualbox-host-dkms` headers error on the EAC kernel:**
   Since `linux-cachyos-eac` does not use DKMS, the default `pacman` hook displays an error when looking for headers for `*-cachyos-eac`. To filter out `*-cachyos-eac*` only in the DKMS hook without affecting the standard `linux` kernel:
   ```bash
   cat << 'EOF' | sudo tee /usr/local/bin/dkms-alpm-filter
   #!/bin/sh
   { grep -v -- '-cachyos-eac' || true; } | /usr/share/libalpm/scripts/dkms "$@"
   EOF
   sudo chmod +x /usr/local/bin/dkms-alpm-filter

   sudo cp /usr/share/libalpm/hooks/70-dkms-install.hook /etc/pacman.d/hooks/70-dkms-install.hook
   sudo sed -i 's|^Exec = /usr/share/libalpm/scripts/dkms|Exec = /usr/local/bin/dkms-alpm-filter|' /etc/pacman.d/hooks/70-dkms-install.hook
   ```

---

### Phase 4: Manually Configure the EAC Entry and Protect Signatures

1. **Ensure `sbctl` does not manage CachyOS-signed binaries:**
   If you previously registered `systemd-boot` or `BOOTX64.EFI` in `sbctl`, remove them from the local database and restore the official CachyOS signature:
   ```bash
   sudo sbctl remove-file /boot/EFI/BOOT/BOOTX64.EFI 2>/dev/null || true
   sudo sbctl remove-file /boot/EFI/systemd/systemd-bootx64.efi 2>/dev/null || true
   sudo sbctl remove-file /boot/vmlinuz-linux-cachyos-eac 2>/dev/null || true

   sudo cp -f /usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed /boot/EFI/systemd/systemd-bootx64.efi
   sudo cp -f /usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed /boot/EFI/BOOT/BOOTX64.EFI
   ```

2. **Identify the root partition `PARTUUID` and create `/boot/loader/entries/cachyos-eac.conf`:**
   Check the GPT identifier of your root partition (`/`):
   ```bash
   lsblk -o NAME,FSTYPE,LABEL,PARTUUID,MOUNTPOINTS
   ```
   Create `/boot/loader/entries/cachyos-eac.conf` (replacing `<YOUR-ROOT-PARTUUID>` with the actual value; on AMD CPUs, replace `intel_iommu=on` with `amd_iommu=on`):
   ```bash
   cat << 'EOF' | sudo tee /boot/loader/entries/cachyos-eac.conf
   title   CachyOS (EAC)
   linux   /vmlinuz-linux-cachyos-eac
   initrd  /initramfs-linux-cachyos-eac.img
   options root=PARTUUID=<YOUR-ROOT-PARTUUID> rw rootfstype=ext4 zswap.enabled=0 quiet splash nvidia_drm.modeset=1 iommu=pt lockdown=integrity lsm=landlock,lockdown,yama,integrity,bpf iommu.passthrough=0 intel_iommu=on module.sig_enforce=1 sysctl.kernel.kexec_load_disabled=1
   EOF
   ```

3. **Confirm signed `systemd-boot` is in NVRAM and verify signatures:**
   ```bash
   sudo bootctl install
   sudo sbverify --list /boot/vmlinuz-linux-cachyos-eac
   sudo sbverify --list /boot/EFI/systemd/systemd-bootx64.efi
   ```
   *(Both should display `subject: /CN=CachyOS EAC Signing ...` issued by `issuer: /CN=CachyOS EAC CA/O=CachyOS`).*

---

### Phase 5: Enroll Keys in UEFI (`--microsoft --custom`) and Enable Secure Boot

1. **Put the BIOS/UEFI into *Setup Mode*:**
   Reboot directly into firmware setup:
   ```bash
   systemctl reboot --firmware-setup
   ```
   In BIOS/UEFI, go to **Security → Secure Boot**, select the option to clear/reset keys (*Reset to Setup Mode* / *Clear Secure Boot Keys*), save, and boot into Arch Linux.

2. **Confirm `Setup Mode` and enroll keys:**
   ```bash
   sudo sbctl status
   sudo sbctl enroll-keys --microsoft --custom
   ```
   - `--microsoft`: **mandatory** for GPU Option ROMs (NVIDIA/laptops) and Windows dual-boot.
   - `--custom`: automatically enrolls the `CachyOS EAC CA` certificate installed by the `cachyos-eac-signing-key` package alongside your `sbctl` keys.

3. **Enable Secure Boot in BIOS/UEFI:**
   Reboot into BIOS/UEFI again (`systemctl reboot --firmware-setup`), set **Secure Boot → Enabled**, save, and exit.

---

### Optional Alternative: Automation with `cachyos-settings` (`eac-setup`)

If you prefer to automate Phases 4 and 5 instead of creating `/boot/loader/entries/cachyos-eac.conf` manually, CachyOS provides the `eac-setup` and `eac-status` utilities in the **optional** `cachyos-settings` package:

```bash
sudo pacman -S cachyos-settings
sudo eac-setup
```

> [!NOTE]
> The `cachyos-settings` package installs and enables additional services (`ananicy-cpp`, `systemd-oomd`, `cachyos-iw-set-regdomain`) and CachyOS-specific sysctls. Once setup is complete, you can disable those services or even remove `cachyos-settings` (`sudo pacman -Rns cachyos-settings`) while keeping `/boot/loader/entries/cachyos-eac.conf` working normally.

---

## 4. Automated Direct Kernel Auditor (`check-eac-compliance.sh`)

After booting into the **`CachyOS (EAC)`** entry, run the auditor script included in this repository ([`check-eac-compliance.sh`](check-eac-compliance.sh)) to directly verify kernel interfaces and signatures:

```bash
chmod +x check-eac-compliance.sh
sudo ./check-eac-compliance.sh
```

### Audited Interfaces and Signatures:

| Target | Source / Interface | Pass Criterion |
|---|---|---|
| **Secure Boot** | `/sys/firmware/efi/efivars/SecureBoot-*` | 5th byte == `0x01` |
| **Setup Mode** | `/sys/firmware/efi/efivars/SetupMode-*` | 5th byte == `0x00` (User Mode active) |
| **TPM 2.0** | `/sys/class/tpm/tpm0/tpm_version_major` | Reports version `2` |
| **Measured Boot** | `/sys/kernel/security/tpm0/binary_bios_measurements` | Event log > 0 bytes |
| **Kernel Lockdown** | `/sys/kernel/security/lockdown` | Contains `[integrity]` |
| **kexec Lock** | `/proc/sys/kernel/kexec_load_disabled` | Equal to `1` |
| **IOMMU Groups** | `/sys/kernel/iommu_groups` | Group count > 0 |
| **LSM BPF** | `/sys/kernel/security/lsm` | Contains `bpf` |
| **EFI Signature** | `sbverify --list` (`/boot/vmlinuz-linux-cachyos-eac` & `systemd-bootx64.efi`) | Signed by `CachyOS EAC CA` |
| **module.sig_enforce** | `/sys/module/module/parameters/sig_enforce` | Equal to `Y` |
| **Kernel Keys** | `/proc/keys` | Asymmetric keys active in kernel |
| **Loaded Modules** | `/proc/modules` + `modinfo` | 100% of loaded modules signed |
| **Kernel Taint** | `/proc/sys/kernel/tainted` | Bit 13 (`8192` - Unsigned) is `0`; Bit 12 (`4096` - OOT) allowed |
| **Active Cmdline** | `/proc/cmdline` | Contains `lockdown=integrity` and `intel_iommu=on` |

---

## 5. Post-Boot Verification Guide

To reboot directly into the EAC entry from the terminal (without holding **Spacebar** at boot):

```bash
sudo bootctl set-oneshot cachyos-eac.conf && systemctl reboot
```

Inside the EAC session, you can run targeted checks:

| Metric | Direct Audit Command | Expected Output |
|---|---|---|
| **Full Auditor** | `sudo ./check-eac-compliance.sh` | `19/19 PASS` (`0 FAIL`, `0 WARN`) |
| **Optional CachyOS Validator** | `sudo eac-status` *(if `cachyos-settings` installed)* | All `[ OK ]` |
| **Lockdown Status** | `cat /sys/kernel/security/lockdown` | `none [integrity] confidentiality` |
| **kexec Disabled** | `cat /proc/sys/kernel/kexec_load_disabled` | `1` |
| **Module Signing** | `modinfo -F signer nvidia` | `Build time autogenerated kernel key` |
| **EFI Signatures** | `sbverify --list /boot/vmlinuz-linux-cachyos-eac` | Signed by `CachyOS EAC Signing ...` / `CachyOS EAC CA` |
| **Kernel Taint** | `cat /proc/sys/kernel/tainted` | `4096` (out-of-tree open module) or `0` (clean) |
| **NVIDIA 3D Driver** | `nvidia-smi` | GPU operational on Wayland/X11 |

---

## 6. Maintenance and Updates

1. **Normal updates (`sudo pacman -Syu`):**
   - When `linux` or `mkinitcpio` updates, the default UKI `/boot/EFI/Linux/arch-linux.efi` is automatically rebuilt and signed by the `sbctl` hook.
   - When `linux-cachyos-eac` or `systemd-boot-cachyos-signed` updates, the packages' own hooks update `initramfs-linux-cachyos-eac.img` and the signed `systemd-boot` without manual intervention.
2. **NVIDIA driver synchronization (`nvidia-open` vs. `linux-cachyos-eac-nvidia-open`):**
   Both modules share the same userspace `nvidia-utils`. If one repository (Arch `extra` vs. `cachyos`) publishes a new driver version before the other, wait for them to sync before running `pacman -Syu` (or update once both match the same `nvidia-utils` version).
3. **Never run `sbctl sign-all` including EAC binaries:**
   Because `/boot/vmlinuz-linux-cachyos-eac`, `/boot/EFI/systemd/systemd-bootx64.efi`, and `/boot/EFI/BOOT/BOOTX64.EFI` are **not** registered in `/var/lib/sbctl/files.json`, the `zz-sbctl.hook` leaves them untouched.

---

## 7. Official References

* [CachyOS Wiki: Easy Anti-Cheat (Linux v2)](https://wiki.cachyos.org/configuration/easy_anti_cheat/)
* [CachyOS Wiki: Optimized Repositories](https://wiki.cachyos.org/configuration/optimized_repositories/)
* [GitHub: CachyOS Linux Kernel (`linux-cachyos-eac`)](https://github.com/CachyOS/linux-cachyos)
* [GitHub: CachyOS-Settings (`eac-setup` / `eac-status`)](https://github.com/CachyOS/CachyOS-Settings)
* [Introducing Easy Anti-Cheat Linux v2 - Epic Online Services](https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2)
* [ArchWiki: Unified Extensible Firmware Interface/Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
* [ArchWiki: sbctl](https://wiki.archlinux.org/title/Sbctl)
* [ArchWiki: Unified Kernel Image (UKI)](https://wiki.archlinux.org/title/Unified_kernel_image)
* [ArchWiki: systemd-boot](https://wiki.archlinux.org/title/Systemd-boot)
* [Linux Kernel Module Signing Documentation](https://docs.kernel.org/admin-guide/module-signing.html)

---

## License

Released under the [MIT License](LICENSE).
