# Arch Linux Guide: Secure Boot, TPM 2.0, and Kernel Lockdown Meeting EAC Linux v2 Requirements

[![Arch Linux](https://img.shields.io/badge/Arch%20Linux-Kernel%206.x%2F7.x-1793d1?logo=arch-linux&logoColor=white)](https://archlinux.org/)
[![Secure Boot](https://img.shields.io/badge/UEFI-Secure%20Boot%20Enabled-success?logo=linux&logoColor=white)](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
[![Lockdown](https://img.shields.io/badge/Kernel%20Lockdown-integrity-blue)](https://docs.kernel.org/admin-guide/module-signing.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> Read this document in other languages: **[Português (Brasil)](README.pt-BR.md)**

A comprehensive, production-grade guide and standalone verification tool to configure **Arch Linux** in full compliance with the strict security requirements of **Easy Anti-Cheat (EAC) Linux v2** (announced by Epic Games), while preserving full support for **NVIDIA GPU drivers** and any out-of-tree [DKMS](https://wiki.archlinux.org/title/Dynamic_Kernel_Module_Support#Secure_Boot) modules (e.g., VirtualBox, v4l2loopback, Razer drivers, custom Wi-Fi/NICs).

> [!IMPORTANT]
> **Technical Scope: Epic Games' "Well-Known Key List" vs. Local MOK Keys:**
> According to official details published by Epic Games:
> 1. **System & Kernel Parameters (100% Compliant):** All operating system requirements covered in this guide (UEFI Secure Boot, TPM 2.0 & Measured Boot, Kernel Lockdown in `[integrity]` mode, `kexec` disabled, IOMMU isolation, and LSM BPF) strictly satisfy all EAC Linux v2 criteria **without restrictions**.
> 2. **The "Well-Known" Key List:** To prevent cheat developers from signing rogue kernel drivers with self-generated private keys, Epic Games enforces a curated **"Well-Known Key List"**. The initial list exclusively trusts centralized distribution signing authorities (Ubuntu/Canonical, Fedora, Debian, openSUSE, Universal Blue/Bazzite, and Microsoft UEFI CA).
> 3. **The Role of Arch Linux Maintainers:** Epic Games **does not trust self-generated user MOK keys** for anti-cheat verification. Epic explicitly invited distribution maintainers (including Arch Linux) to coordinate directly with Epic Games to align configurations and submit their official distribution CA keys for inclusion into the trusted list. This guide ensures your system architecture is fully prepared and compliant as official Arch signing matures.

---

## Table of Contents

- [1. Official EAC Linux v2 Requirements](#1-official-eac-linux-v2-requirements)
- [2. The Dual-Keyring Architecture (Problem & Solution)](#2-the-dual-keyring-architecture-problem--solution)
- [3. Step-by-Step Implementation](#3-step-by-step-implementation)
  - [Phase 1: Base Secure Boot with `sbctl`](#phase-1-base-secure-boot-with-sbctl)
  - [Phase 2: Sysctl & Kernel Modular Command Line](#phase-2-sysctl--kernel-modular-command-line)
  - [Phase 3: Shim Boot Chain & MOK Infrastructure](#phase-3-shim-boot-chain--mok-infrastructure)
  - [Phase 4: Install & Validate DKMS Modules (NVIDIA & Gaming Drivers)](#phase-4-install--validate-dkms-modules-nvidia--gaming-drivers)
  - [Phase 5: Enabling Kernel Lockdown](#phase-5-enabling-kernel-lockdown)
  - [Alternative Option: Dual-Boot UKI Profiles (Desktop/Hibernation vs. Gaming/Lockdown)](#alternative-option-dual-boot-uki-profiles-desktophibernation-vs-gaminglockdown)
- [4. Automated Direct Kernel Auditor (`check-eac-compliance.sh`)](#4-automated-direct-kernel-auditor-check-eac-compliancesh)
- [5. Post-Boot Verification Checklist](#5-post-boot-verification-checklist)
- [6. Maintenance: How to Re-sign and Rebuild DKMS Modules](#6-maintenance-how-to-re-sign-and-rebuild-dkms-modules)
- [7. Official References](#7-official-references)
- [License](#license)

---

## 1. Official EAC Linux v2 Requirements

Unlike Windows ring-0 anti-cheat drivers, EAC Linux v2 leverages an on-demand **`systemd`** daemon coupled with **`eBPF`** programs. To prevent cheating, memory tampering, and unauthorized kernel alterations, EAC mandates a strict chain of trust:

1. **UEFI [Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) Enabled** in User Mode (`SetupMode = 0`) with recognized keys.
2. **TPM 2.0 & Measured Boot** active, logging PCR measurements through systemd and firmware.
3. **Signed Kernel and Modules** (`CONFIG_MODULE_SIG=y`).
4. **Kernel Lockdown in `integrity` Mode** (`/sys/kernel/security/lockdown` set to `[integrity]`), locking ring-0 against modification even by the `root` user.
5. **`kexec` Permanently Disabled** (`kernel.kexec_load_disabled = 1`), preventing in-memory execution of unverified kernels.
6. **IOMMU Enabled** (`intel_iommu=on iommu=pt` or AMD-Vi equivalent), blocking physical DMA attacks from PCIe/Thunderbolt peripherals.
7. **LSM BPF Enabled** (`CONFIG_BPF_LSM=y`), allowing the anti-cheat security module to audit eBPF hooks.

---

## 2. The Dual-Keyring Architecture (Problem & Solution)

### The Upstream Kernel Keyring Isolation Issue
When configuring [Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) on Arch Linux using [sbctl](https://wiki.archlinux.org/title/Sbctl), your root key (`Database Key`) is enrolled directly into the motherboard NVRAM UEFI `db`.

During Linux boot:
* The kernel reads the UEFI `db` and populates the **`.platform`** keyring.
* **Upstream Security Restriction:** The upstream Linux kernel **strictly forbids** the `.platform` keyring from validating kernel modules (`.ko`). This prevents arbitrary third-party code signed with Microsoft OEM vendor keys from executing in kernel space.
* **Consequence under Lockdown:** When `lockdown=integrity` is active, the kernel ignores your `Database Key` in `.platform`, treats NVIDIA and any other DKMS modules as **unsigned**, and blocks loading with `Operation not permitted`.

### The Solution: Shim + MOK + `sbctl` Chain
To bypass this limitation without compromising security, we establish a dual-keyring architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Firmware UEFI (NVRAM)                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                         Executes shimx64.efi (MS / sbctl signed)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                              Shim Bootloader                           │
│  - Reads MOK list (MokList) from NVRAM                                 │
│  - Creates runtime EFI variable 'MokListRT'                            │
│  - Executes 'grubx64.efi' (sbctl-signed copy of systemd-boot)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 systemd-bootx64.efi -> arch-linux.efi (UKI)            │
│  - Boots the Linux Kernel with unified parameters                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                             Linux Kernel                               │
│                                                                        │
│  [Keyring .platform] (via UEFI db)   │ [Keyring .machine] (via MokList)│
│  - Validates bootloaders & UKIs      │ - Validates Kernel Modules      │
│  - Key: Database Key (sbctl)         │ - Key: Machine Owner Key (MOK)  │
│                                      │   (NVIDIA + Any DKMS OK!)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Step-by-Step Implementation

### Phase 1: Base Secure Boot with `sbctl`

Follow the official [ArchWiki sbctl guide](https://wiki.archlinux.org/title/Sbctl) to prepare the platform:

1. **Enter UEFI Firmware & Activate Setup Mode (Key Installation Mode):**
   Before Linux can enroll cryptographic keys into the motherboard's NVRAM, the firmware must be placed in **Setup Mode** (where write permissions to PK, KEK, and db are open). The exact terminology and menu layout vary significantly across motherboard manufacturers and BIOS vendors:
   * **Lenovo (Insyde / ThinkPad):** Go to `Security` -> `Secure Boot` -> Select `Reset to Setup Mode` or `Clear All Secure Boot Keys`.
   * **ASUS:** Navigate to `Boot` -> `Secure Boot` -> `Key Management` -> Select `Clear Secure Boot Keys` (firmware automatically shifts into Setup Mode).
   * **MSI:** Go to `Settings` -> `Security` -> `Secure Boot` -> Change mode from `Standard` to `Custom` -> Select `Delete all Secure Boot variables`.
   * **Gigabyte / AORUS:** Navigate to `BIOS` -> `Secure Boot` -> Toggle to `Custom` -> Select `Delete PK` / `Clear Keys`.
   * **Dell:** Go to `Secure Boot` -> `Expert Key Management` -> Select `Enable Custom Mode` -> `Delete All Keys`.
   * **HP:** Go to `Security` -> `Secure Boot Configuration` -> Select `Clear Secure Boot keys`.

   Save changes and reboot into Arch Linux. Check with `sudo sbctl status` (it should display `Setup Mode: ✓ Enabled` and `Secure Boot: ✗ Disabled`).

2. **Install `sbctl` and Generate Keys:**
   ```bash
   sudo pacman -S sbctl
   sudo sbctl create-keys
   ```

3. **Enroll Keys with Microsoft Vendor Support:**
   > [!IMPORTANT]
   > As documented in [ArchWiki: Secure Boot - Microsoft keys](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot#Microsoft_keys), the `-m` (`--microsoft`) flag is **mandatory** for systems with dedicated NVIDIA GPUs to prevent black screens caused by GPU Option ROMs during POST.
   ```bash
   sudo sbctl enroll-keys -m
   ```

4. **Sign Boot Binaries and UKI:**
   ```bash
   sudo sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI
   sudo sbctl sign -s /boot/EFI/systemd/systemd-bootx64.efi
   sudo sbctl sign -s /boot/EFI/Linux/arch-linux.efi
   ```

---

### Phase 2: Sysctl & Kernel Modular Command Line

1. **Disable `kexec` via Sysctl:**
   ```bash
   cat << 'EOF' | sudo tee /etc/sysctl.d/99-eac-security.conf
   kernel.kexec_load_disabled = 1
   EOF
   ```
   Apply immediately:
   ```bash
   sudo sysctl -p /etc/sysctl.d/99-eac-security.conf
   ```

2. **Modularize Kernel Cmdline (`/etc/cmdline.d/`):**
   Modern `mkinitcpio` generators parse `/etc/cmdline.d/*.conf` in alphanumerical order to assemble the [Unified Kernel Image (UKI)](https://wiki.archlinux.org/title/Unified_kernel_image).

   #### Step 2.1: Identify your Root Drive PARTUUID
   Before configuring boot parameters, retrieve the GPT partition identifier for your root partition:
   ```bash
   lsblk -o NAME,FSTYPE,LABEL,PARTUUID,MOUNTPOINTS
   ```
   * **`PARTUUID` (Partition UUID):** Defined at the GPT partition table level. It persists even if the filesystem is reformatted, making it the most resilient choice for `root=PARTUUID=...` (locate the row mounted at `/`).

   > [!NOTE]
   > **Note on Hibernation (Suspend-to-Disk):**
   > Under Linux Kernel Lockdown (`[integrity]`), traditional suspend-to-disk (hibernation) is strictly disabled by upstream design to prevent memory tampering via swap. Standard Suspend-to-RAM (`suspend`) remains fully functional. Therefore, no swap `resume=` parameters are configured.

   #### Step 2.2: Backup Existing Cmdline and Create Drop-ins
   Instead of deleting your legacy configuration, safely back it up and use it as the base:

   ```bash
   # 1. Create the modular drop-in directory:
   sudo mkdir -p /etc/cmdline.d

   # 2. Copy existing cmdline to 10-root.conf as a starting point:
   sudo cp /etc/kernel/cmdline /etc/cmdline.d/10-root.conf

   # 3. Safely move the original monolithic file to a backup:
   sudo mv /etc/kernel/cmdline /etc/kernel/cmdline.backup
   ```

   * **Inspect and Clean Root Parameters (`/etc/cmdline.d/10-root.conf`):**
     Print your copied configuration:
     ```bash
     cat /etc/cmdline.d/10-root.conf
     ```
     Now open it with **Vim** (`sudo vim /etc/cmdline.d/10-root.conf`) and refine the parameters according to these rules:
     * **What to KEEP:**
       * Root partition reference: Ensure `root=PARTUUID=<YOUR-ROOT-PARTUUID>` matches your discovered partition. If the original used `root=/dev/...` or `root=UUID=...`, switch to `PARTUUID` for maximum boot resilience.
       * Filesystem type and write mode: `rootfstype=ext4` (or `btrfs`), `rw`.
       * Base boot flags: `quiet`, `splash`, `zswap.enabled=...`, or distribution-specific parameters.
     * **What to REMOVE from this file:**
       * **Hibernation arguments:** Delete any `resume=UUID=...` and `resume_offset=...` options (since hibernation is restricted under Lockdown).
       * **Security and IOMMU arguments:** Remove any `intel_iommu=...`, `iommu=...`, or `lockdown=...` (these belong exclusively in `90-security.conf`).

   * **Security parameters (`/etc/cmdline.d/90-security.conf`):**
     Positioned at `90` to evaluate after base root parameters:
     ```bash
     cat << 'EOF' | sudo tee /etc/cmdline.d/90-security.conf
     intel_iommu=on iommu=pt
     EOF
     ```
     *(Use `amd_iommu=on` on AMD systems. Note: `lockdown=integrity` will be added in Phase 5 once the MOK boot chain is active).*

#### Step 2.3: Pre-Reboot Safety Checklist & Base Secure Boot Validation

Before rebooting to validate your base Secure Boot setup, observe these critical safety precautions:

> [!CAUTION]
> **Essential Pre-Reboot Precautions:**
> 1. **Verify ESP Signatures:** Run `sudo sbctl verify`. Every boot binary (`/boot/EFI/BOOT/BOOTX64.EFI`, `/boot/EFI/systemd/systemd-bootx64.efi`, and your UKI `/boot/EFI/Linux/arch-linux.efi`) **must** show a green tick `✓ is signed`. If an unsigned UKI boots with Secure Boot enforced, the UEFI will halt with an *Access Denied / Security Violation* error.
> 2. **Double-Check Root PARTUUID:** Inspect `/etc/cmdline.d/10-root.conf` against your `lsblk -o NAME,PARTUUID,MOUNTPOINTS` output. A typo in the PARTUUID will cause the initramfs to drop into an emergency rescue shell.
> 3. **Confirm Microsoft Vendor Keys (`-m`):** Ensure you executed `sudo sbctl enroll-keys -m`. Omitting `-m` blocks dedicated GPU Option ROMs from initializing video output during POST.
> 4. **Keep an Arch Live USB Handy:** Keep a bootable Arch Linux USB drive accessible. In the unlikely event of a boot misconfiguration, you can boot from the USB (temporarily disabling Secure Boot in UEFI if necessary) and run `arch-chroot` to fix settings.

**Compile and Reboot to Test Base Secure Boot:**
```bash
# 1. Assemble the UKI incorporating the new modular cmdline:
sudo mkinitcpio -P

# 2. Confirm the generated UKI was automatically signed by sbctl's hook:
sudo sbctl verify

# 3. Reboot the machine:
sudo reboot
```

**Post-Reboot Validation:**
Once booted back into Arch, run:
```bash
bootctl status | grep "Secure Boot:"
```
*Expected output: `Secure Boot: enabled (user)`.*
With your base Secure Boot and modular UKI validated, proceed to Phase 3 to configure the Shim and MOK infrastructure.

---

### Phase 3: Shim Boot Chain & MOK Infrastructure

Before installing GPU drivers, set up the cryptographic MOK keys and configure the Shim preloader boot chain.

1. **Generate Dedicated MOK Keypair:**
   ```bash
   sudo openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 \
     -subj "/CN=Arch Linux Kernel Modules MOK/" \
     -keyout /etc/dkms/mok.key \
     -outform DER -out /etc/dkms/mok.der

   sudo openssl x509 -in /etc/dkms/mok.der -inform DER -out /etc/dkms/mok.pem
   ```

2. **Configure DKMS Signing Framework:**
   Setting up [DKMS Secure Boot](https://wiki.archlinux.org/title/Dynamic_Kernel_Module_Support#Secure_Boot) signing in advance ensures that pacman hooks automatically sign all compiled modules upon install:
   ```bash
   sudo mkdir -p /etc/dkms/framework.conf.d
   cat << 'EOF' | sudo tee /etc/dkms/framework.conf.d/signing.conf
   sign_file="/usr/lib/modules/$kernelver/build/scripts/sign-file"
   mok_signing_key="/etc/dkms/mok.key"
   mok_certificate="/etc/dkms/mok.pem"
   EOF
   ```

3. **Install `mokutil` and Queue MOK Import:**
   Install `mokutil` from the official Arch repositories:
   ```bash
   sudo pacman -S mokutil
   sudo mokutil --import /etc/dkms/mok.der
   ```
   *Enter a temporary password when prompted (remember it for the upcoming reboot).*

4. **Install `shim-signed` via `makepkg`:**
   The bootloader preloader `shimx64.efi` must be obtained from the [AUR package: `shim-signed`](https://aur.archlinux.org/packages/shim-signed).

   > [!WARNING]
   > **Arch User Repository (AUR) Security Notice & Best Practices:**
   > PKGBUILD scripts submitted to the AUR are maintained by the community and are **not vetted or audited** by the Arch Linux security team. Malicious or poorly maintained scripts can compromise your system. Always adhere to these safety practices:
   > 1. **Audit the PKGBUILD:** Always inspect the `PKGBUILD` and any `.install` scripts before compilation. Verify the upstream download URLs (`source=`) and ensure the cryptographic hashes (`sha256sums=`) match. For `shim-signed`, confirm that the binary originates directly from trusted Fedora/Red Hat official RPM repositories signed by the Microsoft UEFI CA.
   > 2. **Never build as root:** `makepkg` should strictly run under a standard unprivileged user.
   > 3. **Avoid Blind Automation:** Do not rely on automated AUR parsers/helpers; manually inspect and build using Arch's native `makepkg`.
   >
   > **Official Native Installation via `makepkg`:**
   > ```bash
   > git clone https://aur.archlinux.org/shim-signed.git
   > cd shim-signed
   > vim PKGBUILD   # Thoroughly inspect sources, RPM URLs, and checksums
   > makepkg -si
   > cd .. && rm -rf shim-signed
   > ```

5. **Install Shim on ESP and Sign `mmx64.efi`:**
   ```bash
   sudo cp /usr/share/shim-signed/shimx64.efi /boot/EFI/systemd/
   sudo cp /usr/share/shim-signed/mmx64.efi /boot/EFI/systemd/
   sudo sbctl sign -s /boot/EFI/systemd/mmx64.efi
   ```

6. **Prepare `grubx64.efi` Payload ([systemd-boot](https://wiki.archlinux.org/title/Systemd-boot)):**
   ```bash
   sudo cp /boot/EFI/systemd/systemd-bootx64.efi /boot/EFI/systemd/grubx64.efi
   sudo sbctl sign -s /boot/EFI/systemd/grubx64.efi
   ```

7. **Create NVRAM Boot Entry:**
   ```bash
   sudo efibootmgr --create --disk /dev/nvme0n1 --part 1 \
     --label "Arch Linux (Shim MOK)" \
     --loader '\EFI\systemd\shimx64.efi'
   ```

8. **Enroll MOK via MokManager on Reboot:**
   Reboot the system (`sudo reboot`). When the blue **MokManager** screen appears:
   * Press any key -> **Enroll MOK** -> **Continue** -> **Yes** -> Type your temporary password -> **Reboot**.

---

### Phase 4: Install & Validate DKMS Modules (NVIDIA & Gaming Drivers)

Now that Shim is booting the system and the `.machine` keyring contains your MOK key, install your graphics drivers and DKMS modules:

1. **Install NVIDIA Drivers (and Any Other DKMS Modules):**
   With `signing.conf` already in place, pacman hooks automatically compile and sign the modules:
   ```bash
   # Primary gaming GPU driver:
   sudo pacman -S nvidia-open-dkms

   # Any other required DKMS modules (e.g., VirtualBox, v4l2loopback, Wi-Fi):
   # sudo pacman -S virtualbox-host-dkms v4l2loopback-dkms
   ```

2. **Verify Module Signatures:**
   ```bash
   modinfo nvidia | grep signer
   # Or for any other DKMS module:
   # modinfo vboxdrv | grep signer
   ```
   *Expected: `signer: Arch Linux Kernel Modules MOK`.*

3. **Verify GPU Acceleration:**
   ```bash
   nvidia-smi
   ```

---

### Phase 5: Enabling Kernel Lockdown

With all out-of-tree modules signed and validated by the `.machine` keyring, activate kernel lockdown to satisfy the EAC v2 integrity requirements:

1. **Add `lockdown=integrity` to `/etc/cmdline.d/90-security.conf`:**
   ```bash
   cat << 'EOF' | sudo tee /etc/cmdline.d/90-security.conf
   intel_iommu=on iommu=pt lockdown=integrity
   EOF
   ```

2. **Regenerate UKI and Reboot:**
   Regenerate your [Unified Kernel Image (UKI)](https://wiki.archlinux.org/title/Unified_kernel_image) to bake `lockdown=integrity` into the cryptographically signed `.cmdline`:
   ```bash
   sudo mkinitcpio -P
   sudo reboot
   ```

---

### Alternative Option: Dual-Boot UKI Profiles (Desktop/Hibernation vs. Gaming/Lockdown)

Because Linux Kernel Lockdown in `[integrity]` mode strictly blocks resume from hibernation (`LOCKDOWN_HIBERNATION`), users who rely on daily **hibernation** can configure `systemd-boot` with **two independent UKI entries**:
* **Default Entry (`arch-linux.efi`):** Everyday desktop productivity with active swap/hibernation support (no `lockdown=integrity`).
* **Gaming Entry (`arch-linux-lockdown.efi`):** Fully hardened environment for anti-cheat games with `lockdown=integrity`, `intel_iommu=on iommu=pt`, and `efi=disable_early_pci_dma`.

> [!NOTE]
> The `kexec` block (`kernel.kexec_load_disabled = 1`) remains enforced globally via `/etc/sysctl.d/99-security.conf` (Phase 2). It is not passed on the kernel `cmdline` because upstream Linux parses and enforces this setting strictly via `sysctl`.

#### 1. Structure `/etc/cmdline.d/` with an Isolated Subdirectory

`mkinitcpio` evaluates `*.conf` files inside `/etc/cmdline.d/` non-recursively. You can isolate gaming parameters inside a `lockdown/` subfolder:

1. **Base system and hibernation parameters in root `/etc/cmdline.d/` (Default Entry):**
   ```bash
   # System base
   cat << 'EOF' | sudo tee /etc/cmdline.d/10-root.conf
   root=PARTUUID=<YOUR-ROOT-PARTUUID> rw rootfstype=ext4 zswap.enabled=0 quiet splash
   EOF

   # Hibernation / Swapfile
   cat << 'EOF' | sudo tee /etc/cmdline.d/20-resume.conf
   resume=UUID=<YOUR-SWAP-UUID> resume_offset=<YOUR-SWAPFILE-OFFSET>
   EOF

   # Base IOMMU
   cat << 'EOF' | sudo tee /etc/cmdline.d/30-security.conf
   intel_iommu=on iommu=pt
   EOF
   ```

2. **Create the `lockdown/` subfolder with root symlink and security parameters:**
   ```bash
   sudo mkdir -p /etc/cmdline.d/lockdown

   # Symlink to reuse root parameters without duplication
   sudo ln -sf /etc/cmdline.d/10-root.conf /etc/cmdline.d/lockdown/10-root.conf

   # Hardened parameters & Kernel Lockdown
   cat << 'EOF' | sudo tee /etc/cmdline.d/lockdown/30-security.conf
   lockdown=integrity intel_iommu=on iommu=pt efi=disable_early_pci_dma
   EOF
   ```

#### 2. Configure Presets in `/etc/mkinitcpio.d/linux.preset`

Edit `/etc/mkinitcpio.d/linux.preset` (`sudo vim /etc/mkinitcpio.d/linux.preset`):

```ini
ALL_kver="/boot/vmlinuz-linux"

PRESETS=('default' 'lockdown')

# --- Entry 1: Desktop / Hibernation (Default) ---
default_uki="/boot/EFI/Linux/arch-linux.efi"
default_options="--splash /boot/loader/background.bmp"

# --- Entry 2: Gaming / EAC Anti-Cheat (Lockdown) ---
lockdown_uki="/boot/EFI/Linux/arch-linux-lockdown.efi"
lockdown_options="--splash /boot/loader/background.bmp --cmdline /etc/cmdline.d/lockdown"
```

#### 3. Build, Sign, and Set Default Boot

```bash
# 1. Compile both UKI images
sudo mkinitcpio -P

# 2. Register lockdown UKI in sbctl database (if not auto-signed by post-hook)
sudo sbctl sign -s /boot/EFI/Linux/arch-linux-lockdown.efi

# 3. Ensure default boot points to the hibernation image
sudo bootctl set-default arch-linux.efi

# 4. Verify detected boot entries
bootctl list
```

When powering on your computer, the system boots into your desktop environment with working hibernation. When launching games requiring EAC v2, press the **Spacebar** during boot and select `Arch Linux (...~lockdown)`.

---

## 4. Automated Direct Kernel Auditor (`check-eac-compliance.sh`)

Immediately after rebooting, verify your system's compliance using the standalone auditor script included in this repository ([`check-eac-compliance.sh`](check-eac-compliance.sh)). It audits kernel security interfaces directly without relying on high-level tools:

```bash
chmod +x check-eac-compliance.sh
sudo ./check-eac-compliance.sh
```

### Audited Sysfs/Procfs Interfaces:

| Target | Direct Kernel Path | Compliance Criterion |
|---|---|---|
| **Secure Boot** | `/sys/firmware/efi/efivars/SecureBoot-*` | 5th byte == `0x01` |
| **Setup Mode** | `/sys/firmware/efi/efivars/SetupMode-*` | 5th byte == `0x00` (User Mode enforcement) |
| **TPM 2.0** | `/sys/class/tpm/tpm0/tpm_version_major` | Reports `2` |
| **Measured Boot** | `/sys/kernel/security/tpm0/binary_bios_measurements` | Event log > 0 bytes |
| **Kernel Lockdown** | `/sys/kernel/security/lockdown` | Contains `[integrity]` |
| **kexec Lock** | `/proc/sys/kernel/kexec_load_disabled` | Equal to `1` |
| **IOMMU Groups** | `/sys/kernel/iommu_groups` | Group count > 0 |
| **LSM BPF** | `/sys/kernel/security/lsm` | Contains `bpf` |
| **Shim MokListRT**| `/sys/firmware/efi/efivars/MokListRT-*` | Exported runtime table present |
| **MOK Keyring** | `/proc/keys` | Certificate exists in kernel keyring table |
| **Kernel Taint** | `/proc/sys/kernel/tainted` | Bitwise: Bit 13 (`8192` - Unsigned) is `0`; Bit 12 (`4096` - OOT DKMS) allowed |
| **Active Cmdline** | `/proc/cmdline` | Contains `lockdown=integrity` & `intel_iommu=on` |

---

## 5. Post-Boot Verification Checklist

You can also run quick manual checks against core security interfaces:

| Metric | Direct Check Command | Expected Output |
|---|---|---|
| **Lockdown Status** | `cat /sys/kernel/security/lockdown` | `none [integrity] confidentiality` |
| **kexec Disabled** | `cat /proc/sys/kernel/kexec_load_disabled` | `1` |
| **MOK Keyring** | `keyctl show %:.machine` or `cat /proc/keys` | Contains `Arch Linux Kernel Modules MOK` |
| **Kernel Taint** | `cat /proc/sys/kernel/tainted` | `4096` (OOT DKMS) or `0` (clean) |
| **Host Security ID** | `fwupdmgr security` | HSI-1 valid, Intel BootGuard enabled |
| **NVIDIA 3D Driver**| `nvidia-smi` | GPU operational with Wayland/X11 |

---

## 6. Maintenance: How to Re-sign and Rebuild DKMS Modules

Whenever a kernel update occurs or you install new out-of-tree hardware drivers in the future, use these standard procedures:

### A. Automatic Rebuild & Signing (Recommended)
Because `/etc/dkms/framework.conf.d/signing.conf` is persistent, `pacman` hooks automatically rebuild and re-sign all DKMS modules on every kernel update. To manually trigger this:
```bash
sudo dkms autoinstall
```

### B. Force Rebuilding a Specific Module
To completely purge and recompile a specific module (replace with your module name and version):
```bash
# Check installed DKMS modules:
dkms status

# Cleanly rebuild and re-sign:
sudo dkms remove <module>/<version> --all
sudo dkms install <module>/<version>
```
*Example for NVIDIA:*
```bash
sudo dkms remove nvidia/615.78.08 --all && sudo dkms install nvidia/615.78.08
```

### C. Manual Direct Module Signing with `sign-file`
If you compile an independent `.ko` outside of the DKMS tree, sign it manually using the kernel's built-in tool:
```bash
sudo /usr/lib/modules/$(uname -r)/build/scripts/sign-file sha256 \
  /etc/dkms/mok.key \
  /etc/dkms/mok.pem \
  /path/to/module.ko
```

---

## 7. Official References

* [Introducing Easy Anti-Cheat Linux v2 - Epic Online Services](https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2)
* [ArchWiki: Unified Extensible Firmware Interface/Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
* [ArchWiki: sbctl](https://wiki.archlinux.org/title/Sbctl)
* [ArchWiki: Unified Kernel Image (UKI)](https://wiki.archlinux.org/title/Unified_kernel_image)
* [ArchWiki: systemd-boot](https://wiki.archlinux.org/title/Systemd-boot)
* [ArchWiki: DKMS Secure Boot](https://wiki.archlinux.org/title/Dynamic_Kernel_Module_Support#Secure_Boot)
* [Linux Kernel Module Signing Documentation](https://docs.kernel.org/admin-guide/module-signing.html)

---

## License

Released under the [MIT License](LICENSE).
