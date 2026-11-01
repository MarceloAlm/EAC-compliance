#!/bin/sh
# ==============================================================================
# Direct Kernel-Level Integrity Checker (/sys, /proc, /dev, /run)
# Compatibility with Easy Anti-Cheat (EAC) Linux v2
# ==============================================================================

set -u

# Cores ANSI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

print_header() {
    printf "\n${BOLD}${CYAN}=== %s ===${NC}\n" "$1"
}

report_pass() {
    printf " [ ${GREEN}PASS${NC} ] %s\n" "$1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

report_fail() {
    printf " [ ${RED}FAIL${NC} ] %s\n" "$1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

report_warn() {
    printf " [ ${YELLOW}WARN${NC} ] %s\n" "$1"
    WARN_COUNT=$((WARN_COUNT + 1))
}

report_info() {
    printf " [ ${BLUE}INFO${NC} ] %s\n" "$1"
}

# Helper function to extract the value byte from an EFI variable
read_efivar_byte() {
    var_path="$1"
    if [ -r "$var_path" ]; then
        od -An -j4 -N1 -tu1 "$var_path" 2>/dev/null | tr -d ' '
    else
        printf ""
    fi
}

# 1. UEFI Secure Boot and Setup Mode
print_header "1. UEFI Secure Boot and Operation Mode (/sys/firmware/efi/efivars/)"

SECURE_BOOT_FILE=$(find /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -n 1)
SETUP_MODE_FILE=$(find /sys/firmware/efi/efivars/SetupMode-* 2>/dev/null | head -n 1)

if [ -n "$SECURE_BOOT_FILE" ] && [ -f "$SECURE_BOOT_FILE" ]; then
    SB_VAL=$(read_efivar_byte "$SECURE_BOOT_FILE")
    if [ "$SB_VAL" = "1" ]; then
        report_pass "Secure Boot enabled in firmware (efivar: 0x01): $(basename "$SECURE_BOOT_FILE")"
    else
        report_fail "Secure Boot disabled in firmware (efivar: $SB_VAL)"
    fi
else
    report_fail "Secure Boot firmware variable not found in /sys/firmware/efi/efivars"
fi

if [ -n "$SETUP_MODE_FILE" ] && [ -f "$SETUP_MODE_FILE" ]; then
    SM_VAL=$(read_efivar_byte "$SETUP_MODE_FILE")
    if [ "$SM_VAL" = "0" ]; then
        report_pass "Setup Mode disabled / User Mode active (efivar: 0x00 - keys enforced)"
    else
        report_warn "Setup Mode is active (efivar: $SM_VAL) - firmware open for writing"
    fi
fi

# 2. TPM 2.0 & Measured Boot
print_header "2. TPM 2.0 & Measured Boot (/sys/class/tpm/, /dev/tpmrm0)"

if [ -d /sys/class/tpm/tpm0 ]; then
    report_pass "TPM hardware interface found at /sys/class/tpm/tpm0"

    if [ -f /sys/class/tpm/tpm0/tpm_version_major ]; then
        TPM_VER=$(cat /sys/class/tpm/tpm0/tpm_version_major)
        if [ "$TPM_VER" = "2" ]; then
            report_pass "TPM version confirmed by the kernel: TPM 2.0"
        else
            report_warn "TPM version reported by the kernel: TPM $TPM_VER"
        fi
    fi
else
    report_fail "No TPM interface registered in /sys/class/tpm/"
fi

if [ -c /dev/tpmrm0 ]; then
    report_pass "Operational /dev/tpmrm0 kernel character device"
else
    report_fail "Device /dev/tpmrm0 missing"
fi

if [ -f /sys/kernel/security/tpm0/binary_bios_measurements ]; then
    MEASURE_SIZE=$(wc -c < /sys/kernel/security/tpm0/binary_bios_measurements)
    if [ "$MEASURE_SIZE" -gt 0 ]; then
        report_pass "Measured Boot active: $MEASURE_SIZE bytes of measured events in /sys/kernel/security/tpm0/binary_bios_measurements"
    else
        report_warn "The measurement log /sys/kernel/security/tpm0/binary_bios_measurements is empty"
    fi
else
    report_info "/sys/kernel/security/tpm0/binary_bios_measurements register not exposed"
fi

# 3. Kernel Lockdown
print_header "3. Kernel Lockdown (/sys/kernel/security/lockdown)"
if [ -f /sys/kernel/security/lockdown ]; then
    LOCKDOWN_RAW=$(cat /sys/kernel/security/lockdown)
    if printf "%s" "$LOCKDOWN_RAW" | grep -q "\[integrity\]"; then
        report_pass "Active mode: [integrity] (Ring-0 locked against tampering)"
    elif printf "%s" "$LOCKDOWN_RAW" | grep -q "\[confidentiality\]"; then
        report_pass "Active mode: [confidentiality]"
    else
        report_fail "Lockdown disabled or incorrect: $LOCKDOWN_RAW"
    fi
else
    report_fail "securityfs: /sys/kernel/security/lockdown does not exist"
fi

# 4. kexec locked
print_header "4. kexec locked (/proc/sys/kernel/kexec_load_disabled)"
if [ -f /proc/sys/kernel/kexec_load_disabled ]; then
    KEXEC_VAL=$(cat /proc/sys/kernel/kexec_load_disabled)
    if [ "$KEXEC_VAL" = "1" ]; then
        report_pass "/proc/sys/kernel/kexec_load_disabled = 1 (Injection of new kernel blocked)"
    else
        report_fail "/proc/sys/kernel/kexec_load_disabled = $KEXEC_VAL (Expected: 1)"
    fi
else
    report_fail "/proc/sys/kernel/kexec_load_disabled does not exist"
fi

# 5. IOMMU Isolation
print_header "5. IOMMU Isolation (/sys/kernel/iommu_groups, /sys/class/iommu)"
if [ -d /sys/kernel/iommu_groups ]; then
    GROUP_COUNT=$(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$GROUP_COUNT" -gt 0 ]; then
        report_pass "$GROUP_COUNT IOMMU isolation groups located in /sys/kernel/iommu_groups/"
    else
        report_fail "/sys/kernel/iommu_groups is empty (IOMMU disabled)"
    fi
else
    report_fail "/sys/kernel/iommu_groups does not exist (IOMMU support missing)"
fi

if [ -d /sys/class/iommu ]; then
    IOMMU_DEVS=$(find /sys/class/iommu 2>/dev/null | tr '\n' ' ' || true)
    report_info "IOMMU controllers registered in sysfs: $IOMMU_DEVS"
fi

# 6. LSM Security Modules
print_header "6. LSM Security Modules (/sys/kernel/security/lsm)"
if [ -f /sys/kernel/security/lsm ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if printf "%s" "$LSM_LIST" | grep -q "bpf"; then
        report_pass "LSM BPF loaded in securityfs: $LSM_LIST"
    else
        report_fail "LSM BPF not present: $LSM_LIST"
    fi
else
    report_fail "/sys/kernel/security/lsm inaccessible"
fi

# 7. Shim Chain and MOK at Runtime
print_header "7. Shim Chain and MOK at Runtime (/sys/firmware/efi/efivars/, /proc/keys)"

MOKLIST_RT_FILE=$(find /sys/firmware/efi/efivars/MokListRT-* 2>/dev/null | head -n 1)
if [ -n "$MOKLIST_RT_FILE" ] && [ -f "$MOKLIST_RT_FILE" ]; then
    MOK_SIZE=$(wc -c < "$MOKLIST_RT_FILE")
    report_pass "Operational shim: Runtime variable MokListRT active ($MOK_SIZE bytes exported to the kernel)"
else
    report_fail "Variable MokListRT not found in /sys/firmware/efi/efivars/ (Shim not initialized or missing keys)"
fi

if [ -f /proc/keys ]; then
    if grep -q "Kernel Modules MOK" /proc/keys; then
        report_pass "MOK key located in the kernel table (/proc/keys)"
        grep -i "Kernel Modules MOK" /proc/keys | sed 's/^/    /'
    else
        report_fail "MOK Certificates ('Kernel Modules MOK') not found in /proc/keys"
    fi

    if grep -q "\.machine" /proc/keys; then
        report_pass "Keyring '.machine' registered and populated in the kernel's security subsystem"
    else
        report_warn "Keyring '.machine' not explicitly identified in /proc/keys"
    fi
else
    report_fail "/proc/keys inaccessible (CONFIG_KEYS disabled in the kernel)"
fi

# 8. Kernel Taint Analysis
print_header "8. Kernel Taint Analysis (/proc/sys/kernel/tainted)"
if [ -f /proc/sys/kernel/tainted ]; then
    TAINT=$(cat /proc/sys/kernel/tainted)
    report_info "Raw value in /proc/sys/kernel/tainted: $TAINT"

    IS_UNSIGNED=$((TAINT / 8192 % 2))
    IS_PROPRIETARY=$((TAINT % 2))
    IS_OOT=$((TAINT / 4096 % 2))

    if [ "$IS_UNSIGNED" -eq 1 ]; then
        report_fail "Bit 13 ACTIVE (8192): Unsigned module in kernel space!"
    else
        report_pass "Bit 13 DISABLED: Zero unsigned modules in the kernel"
    fi

    if [ "$IS_PROPRIETARY" -eq 1 ]; then
        report_warn "Bit 0 ACTIVE (1): Closed-source module present"
    else
        report_pass "Bit 0 DISABLED: Free of closed-source modules that violate the GPL"
    fi

    if [ "$IS_OOT" -eq 1 ]; then
        report_info "Bit 12 ACTIVE (4096): DKMS modules compiled out-of-tree (standard and expected behavior)"
    fi

    if [ "$TAINT" -eq 0 ]; then
        report_pass "100% pure kernel (tainted = 0)"
    elif [ "$TAINT" -eq 4096 ]; then
        report_pass "Kernel tainted solely by an open-source, out-of-tree DKMS module (tainted = 4096). Valid for EAC!"
    fi
fi

# 9. Active Boot Parameters
print_header "9. Active Boot Parameters (/proc/cmdline)"
if [ -f /proc/cmdline ]; then
    CMDLINE_ACTUAL=$(cat /proc/cmdline)
    printf " [ ${BLUE}CMDLINE${NC} ] %s\n" "$CMDLINE_ACTUAL"

    if printf "%s" "$CMDLINE_ACTUAL" | grep -q "lockdown=integrity"; then
        report_pass "'lockdown=integrity' parameter present on the active command line"
    fi

    if printf "%s" "$CMDLINE_ACTUAL" | grep -q "intel_iommu=on"; then
        report_pass "'intel_iommu=on' parameter present in the active command line"
    fi
    if printf "%s" "$CMDLINE_ACTUAL" | grep -q "amd_iommu=on"; then
        report_pass "'amd_iommu=on' parameter present in the active command line"
    fi
fi

# 10. Summary
print_header "EAC Linux v2 Evaluation Summary"
printf "%b" "Successes: ${GREEN}${PASS_COUNT}${NC} | Fails: ${RED}${FAIL_COUNT}${NC} | Notices: ${YELLOW}${WARN_COUNT}${NC}\n"

if [ "$FAIL_COUNT" -eq 0 ]; then
    printf "%b\n" "${GREEN}${BOLD}✔ SYSTEM 100%% COMPLIANT WITH EAC LINUX V2 (Audited directly via /sys and /proc)!${NC}"
    exit 0
else
    printf "%b\n" "${RED}${BOLD}✘ Fails detected during direct kernel auditing.${NC}"
    exit 1
fi
