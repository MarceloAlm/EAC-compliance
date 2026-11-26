#!/bin/sh
# ==============================================================================
# Verificador de Integridade Direta via Kernel (/sys, /proc, /dev, /run)
# Direct Kernel-Level Integrity Checker (/sys, /proc, /dev, /run)
# Compatibilidade / Compatibility: Easy Anti-Cheat (EAC) Linux v2
# ==============================================================================

set -u

# Detecção de idioma (pt_BR/pt -> Português; demais -> English)
LOCALE_CHECK="${LC_ALL:-${LC_MESSAGES:-${LANG:-${LANGUAGE:-}}}}"
case "$LOCALE_CHECK" in
    pt_BR*|pt_PT*|pt*) IS_PT=1 ;;
    *) IS_PT=0 ;;
esac

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

t() {
    if [ "$IS_PT" -eq 1 ] || [ "$#" -lt 2 ]; then
        printf '%s' "$1"
    else
        printf '%s' "$2"
    fi
}

print_header() {
    printf "\n${BOLD}${CYAN}=== %s ===${NC}\n" "$(t "$@")"
}

report_pass() {
    printf " [ ${GREEN}PASS${NC} ] %s\n" "$(t "$@")"
    PASS_COUNT=$((PASS_COUNT + 1))
}

report_fail() {
    printf " [ ${RED}FAIL${NC} ] %s\n" "$(t "$@")"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

report_warn() {
    printf " [ ${YELLOW}WARN${NC} ] %s\n" "$(t "$@")"
    WARN_COUNT=$((WARN_COUNT + 1))
}

report_info() {
    printf " [ ${BLUE}INFO${NC} ] %s\n" "$(t "$@")"
}

# Extrai o byte de valor de uma variável EFI em /sys/firmware/efi/efivars
# As variáveis efivars possuem um cabeçalho de 4 bytes seguido pelo payload.
read_efivar_byte() {
    var_path="$1"
    if [ -r "$var_path" ]; then
        od -An -j4 -N1 -tu1 "$var_path" 2>/dev/null | tr -d ' '
    else
        printf ""
    fi
}

# ------------------------------------------------------------------------------
# 0. Ambiente do Kernel em Execução (uname)
# ------------------------------------------------------------------------------
KERNEL_REL=$(uname -r)
KERNEL_ARCH=$(uname -m)

print_header \
    "0. Ambiente do Kernel em Execução" \
    "0. Running Kernel Environment"

report_info \
    "Kernel em execução: $KERNEL_REL ($KERNEL_ARCH)" \
    "Running kernel: $KERNEL_REL ($KERNEL_ARCH)"

# Identifica a imagem do kernel em execução e verifica sua assinatura EFI
PKGBASE=""
RUNNING_KIMG=""
if [ -r "/usr/lib/modules/${KERNEL_REL}/pkgbase" ]; then
    PKGBASE=$(cat "/usr/lib/modules/${KERNEL_REL}/pkgbase")
    if [ -f "/boot/vmlinuz-${PKGBASE}" ]; then
        RUNNING_KIMG="/boot/vmlinuz-${PKGBASE}"
    fi
fi

if [ -z "$RUNNING_KIMG" ] && [ -f /proc/cmdline ]; then
    BOOT_IMG=$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^BOOT_IMAGE=//p' | head -n 1 || true)
    if [ -n "$BOOT_IMG" ] && [ -f "/boot${BOOT_IMG}" ]; then
        RUNNING_KIMG="/boot${BOOT_IMG}"
    elif [ -n "$BOOT_IMG" ] && [ -f "$BOOT_IMG" ]; then
        RUNNING_KIMG="$BOOT_IMG"
    fi
fi

if command -v sbverify >/dev/null 2>&1; then
    if [ -n "$RUNNING_KIMG" ]; then
        SB_RUN_OUT=$(sbverify --list "$RUNNING_KIMG" 2>/dev/null || true)
        if printf "%s" "$SB_RUN_OUT" | grep -q "^signature "; then
            report_pass \
                "Assinatura EFI do kernel em execução ($RUNNING_KIMG):" \
                "Running kernel EFI signature ($RUNNING_KIMG):"
            printf "%s\n" "$SB_RUN_OUT" | grep -E "subject:|issuer:" | head -n 4 | sed 's/^/    /'
        elif [ "$PKGBASE" = "linux" ] && [ -f /boot/EFI/Linux/arch-linux.efi ]; then
            SB_UKI_OUT=$(sbverify --list /boot/EFI/Linux/arch-linux.efi 2>/dev/null || true)
            if printf "%s" "$SB_UKI_OUT" | grep -q "^signature "; then
                report_info \
                    "Imagem bruta $RUNNING_KIMG sem assinatura; UKI em /boot/EFI/Linux/arch-linux.efi assinada por:" \
                    "Raw image $RUNNING_KIMG unsigned; UKI at /boot/EFI/Linux/arch-linux.efi signed by:"
                printf "%s\n" "$SB_UKI_OUT" | grep -E "subject:|issuer:" | head -n 4 | sed 's/^/    /'
            else
                report_fail \
                    "Kernel em execução ($RUNNING_KIMG) e UKI sem assinatura EFI" \
                    "Running kernel ($RUNNING_KIMG) and UKI have no EFI signature"
            fi
        else
            report_fail \
                "Kernel em execução ($RUNNING_KIMG) sem assinatura EFI" \
                "Running kernel ($RUNNING_KIMG) has no EFI signature"
        fi
    else
        report_info \
            "Imagem do kernel em execução ($KERNEL_REL) não localizada em /boot para checagem de assinatura" \
            "Running kernel image ($KERNEL_REL) not found in /boot for signature check"
    fi
else
    report_warn \
        "Utilitário 'sbverify' (pacote sbsigntools) não encontrado; não foi possível checar assinatura do kernel em execução" \
        "Utility 'sbverify' (sbsigntools package) not found; could not check running kernel signature"
fi

# ------------------------------------------------------------------------------
# 1. UEFI Secure Boot e Setup Mode (/sys/firmware/efi/efivars/)
# ------------------------------------------------------------------------------
print_header \
    "1. UEFI Secure Boot e Modo de Operação (/sys/firmware/efi/efivars/)" \
    "1. UEFI Secure Boot and Operation Mode (/sys/firmware/efi/efivars/)"

SECURE_BOOT_FILE=$(find /sys/firmware/efi/efivars -maxdepth 1 -name 'SecureBoot-*' 2>/dev/null | head -n 1 || true)
SETUP_MODE_FILE=$(find /sys/firmware/efi/efivars -maxdepth 1 -name 'SetupMode-*' 2>/dev/null | head -n 1 || true)

if [ -n "$SECURE_BOOT_FILE" ] && [ -f "$SECURE_BOOT_FILE" ]; then
    SB_VAL=$(read_efivar_byte "$SECURE_BOOT_FILE")
    SB_BASE=$(basename "$SECURE_BOOT_FILE")
    if [ "$SB_VAL" = "1" ]; then
        report_pass \
            "SecureBoot ativo no firmware (efivar: 0x01): $SB_BASE" \
            "Secure Boot enabled in firmware (efivar: 0x01): $SB_BASE"
    else
        report_fail \
            "SecureBoot desativado no firmware (efivar: $SB_VAL)" \
            "Secure Boot disabled in firmware (efivar: $SB_VAL)"
    fi
else
    report_fail \
        "Variável de firmware SecureBoot não encontrada em /sys/firmware/efi/efivars" \
        "Secure Boot firmware variable not found in /sys/firmware/efi/efivars"
fi

if [ -n "$SETUP_MODE_FILE" ] && [ -f "$SETUP_MODE_FILE" ]; then
    SM_VAL=$(read_efivar_byte "$SETUP_MODE_FILE")
    if [ "$SM_VAL" = "0" ]; then
        report_pass \
            "SetupMode desabilitado / Modo Usuário ativo (efivar: 0x00 - chaves em imposição)" \
            "Setup Mode disabled / User Mode active (efivar: 0x00 - keys enforced)"
    else
        report_warn \
            "SetupMode está ativo (efivar: $SM_VAL) - firmware aberto para gravação" \
            "Setup Mode is active (efivar: $SM_VAL) - firmware open for writing"
    fi
fi

# ------------------------------------------------------------------------------
# 2. TPM 2.0 & Measured Boot (/sys/class/tpm/, /dev/tpm*, /sys/kernel/security/tpm*)
# ------------------------------------------------------------------------------
print_header \
    "2. TPM 2.0 & Measured Boot (/sys/class/tpm/, /dev/tpmrm0)" \
    "2. TPM 2.0 & Measured Boot (/sys/class/tpm/, /dev/tpmrm0)"

if [ -d /sys/class/tpm/tpm0 ]; then
    report_pass \
        "Interface de hardware TPM encontrada em /sys/class/tpm/tpm0" \
        "TPM hardware interface found at /sys/class/tpm/tpm0"

    if [ -f /sys/class/tpm/tpm0/tpm_version_major ]; then
        TPM_VER=$(cat /sys/class/tpm/tpm0/tpm_version_major)
        if [ "$TPM_VER" = "2" ]; then
            report_pass \
                "Versão do TPM confirmada pelo kernel: TPM 2.0" \
                "TPM version confirmed by the kernel: TPM 2.0"
        else
            report_warn \
                "Versão do TPM reportada pelo kernel: TPM $TPM_VER" \
                "TPM version reported by the kernel: TPM $TPM_VER"
        fi
    fi
else
    report_fail \
        "Nenhuma interface TPM registrada em /sys/class/tpm/" \
        "No TPM interface registered in /sys/class/tpm/"
fi

if [ -c /dev/tpmrm0 ]; then
    report_pass \
        "Dispositivo de caracteres de kernel /dev/tpmrm0 operacional" \
        "Operational /dev/tpmrm0 kernel character device"
else
    report_fail \
        "Dispositivo /dev/tpmrm0 ausente" \
        "Device /dev/tpmrm0 missing"
fi

if [ -f /sys/kernel/security/tpm0/binary_bios_measurements ]; then
    MEASURE_SIZE=$(wc -c < /sys/kernel/security/tpm0/binary_bios_measurements)
    if [ "$MEASURE_SIZE" -gt 0 ]; then
        report_pass \
            "Measured Boot ativo: $MEASURE_SIZE bytes de eventos medidos em /sys/kernel/security/tpm0/binary_bios_measurements" \
            "Measured Boot active: $MEASURE_SIZE bytes of measured events in /sys/kernel/security/tpm0/binary_bios_measurements"
    else
        report_warn \
            "Log de medições /sys/kernel/security/tpm0/binary_bios_measurements está vazio" \
            "The measurement log /sys/kernel/security/tpm0/binary_bios_measurements is empty"
    fi
else
    report_info \
        "Registro /sys/kernel/security/tpm0/binary_bios_measurements não exposto" \
        "/sys/kernel/security/tpm0/binary_bios_measurements register not exposed"
fi

# ------------------------------------------------------------------------------
# 3. Kernel Lockdown (/sys/kernel/security/lockdown)
# ------------------------------------------------------------------------------
print_header \
    "3. Kernel Lockdown (/sys/kernel/security/lockdown)" \
    "3. Kernel Lockdown (/sys/kernel/security/lockdown)"

if [ -f /sys/kernel/security/lockdown ]; then
    LOCKDOWN_RAW=$(cat /sys/kernel/security/lockdown)
    if printf "%s" "$LOCKDOWN_RAW" | grep -q "\[integrity\]"; then
        report_pass \
            "Modo ativo: [integrity] (Ring-0 trancado contra adulteração)" \
            "Active mode: [integrity] (Ring-0 locked against tampering)"
    elif printf "%s" "$LOCKDOWN_RAW" | grep -q "\[confidentiality\]"; then
        report_pass \
            "Modo ativo: [confidentiality]" \
            "Active mode: [confidentiality]"
    else
        report_fail \
            "Lockdown desabilitado ou incorreto: $LOCKDOWN_RAW" \
            "Lockdown disabled or incorrect: $LOCKDOWN_RAW"
    fi
else
    report_fail \
        "securityfs: /sys/kernel/security/lockdown inexistente" \
        "securityfs: /sys/kernel/security/lockdown does not exist"
fi

# ------------------------------------------------------------------------------
# 4. Bloqueio de kexec (/proc/sys/kernel/kexec_load_disabled)
# ------------------------------------------------------------------------------
print_header \
    "4. Bloqueio de kexec (/proc/sys/kernel/kexec_load_disabled)" \
    "4. kexec Lock (/proc/sys/kernel/kexec_load_disabled)"

if [ -f /proc/sys/kernel/kexec_load_disabled ]; then
    KEXEC_VAL=$(cat /proc/sys/kernel/kexec_load_disabled)
    if [ "$KEXEC_VAL" = "1" ]; then
        report_pass \
            "/proc/sys/kernel/kexec_load_disabled = 1 (Injeção de novo kernel bloqueada)" \
            "/proc/sys/kernel/kexec_load_disabled = 1 (Injection of new kernel blocked)"
    else
        report_fail \
            "/proc/sys/kernel/kexec_load_disabled = $KEXEC_VAL (Esperado: 1)" \
            "/proc/sys/kernel/kexec_load_disabled = $KEXEC_VAL (Expected: 1)"
    fi
else
    report_fail \
        "/proc/sys/kernel/kexec_load_disabled inexistente" \
        "/proc/sys/kernel/kexec_load_disabled does not exist"
fi

# ------------------------------------------------------------------------------
# 5. Isolamento IOMMU (/sys/kernel/iommu_groups, /sys/class/iommu)
# ------------------------------------------------------------------------------
print_header \
    "5. Isolamento IOMMU (/sys/kernel/iommu_groups, /sys/class/iommu)" \
    "5. IOMMU Isolation (/sys/kernel/iommu_groups, /sys/class/iommu)"

if [ -d /sys/kernel/iommu_groups ]; then
    GROUP_COUNT=$(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$GROUP_COUNT" -gt 0 ]; then
        report_pass \
            "$GROUP_COUNT grupos de isolamento IOMMU populados em /sys/kernel/iommu_groups/" \
            "$GROUP_COUNT IOMMU isolation groups populated in /sys/kernel/iommu_groups/"
    else
        report_fail \
            "/sys/kernel/iommu_groups está vazio (IOMMU desativado)" \
            "/sys/kernel/iommu_groups is empty (IOMMU disabled)"
    fi
else
    report_fail \
        "/sys/kernel/iommu_groups inexistente (Suporte IOMMU ausente)" \
        "/sys/kernel/iommu_groups does not exist (IOMMU support missing)"
fi

if [ -d /sys/class/iommu ]; then
    IOMMU_DEVS=$(ls /sys/class/iommu 2>/dev/null | tr '\n' ' ' || true)
    report_info \
        "Controladores IOMMU registrados no sysfs: $IOMMU_DEVS" \
        "IOMMU controllers registered in sysfs: $IOMMU_DEVS"
fi

# ------------------------------------------------------------------------------
# 6. LSM BPF (/sys/kernel/security/lsm)
# ------------------------------------------------------------------------------
print_header \
    "6. Módulos de Segurança LSM (/sys/kernel/security/lsm)" \
    "6. LSM Security Modules (/sys/kernel/security/lsm)"

if [ -f /sys/kernel/security/lsm ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if printf "%s" "$LSM_LIST" | grep -q "bpf"; then
        report_pass \
            "LSM BPF carregado no securityfs: $LSM_LIST" \
            "LSM BPF loaded in securityfs: $LSM_LIST"
    else
        report_fail \
            "LSM BPF não presente: $LSM_LIST" \
            "LSM BPF not present: $LSM_LIST"
    fi
else
    report_fail \
        "/sys/kernel/security/lsm inacessível" \
        "/sys/kernel/security/lsm inaccessible"
fi

# ------------------------------------------------------------------------------
# 7. Assinatura do Kernel, Bootloader e Módulos (sbverify, /proc/keys, modinfo)
# ------------------------------------------------------------------------------
print_header \
    "7. Assinatura do Kernel, Bootloader e Módulos" \
    "7. Kernel, Bootloader, and Module Signatures"

# Verifica assinatura EFI dos kernels/UKIs em /boot/ e do bootloader via sbverify (sbsigntools)
if command -v sbverify >/dev/null 2>&1; then
    FOUND_KERNELS=0
    for k_bin in /boot/vmlinuz-* /boot/EFI/Linux/*.efi; do
        if [ -f "$k_bin" ]; then
            FOUND_KERNELS=1
            SB_OUT=$(sbverify --list "$k_bin" 2>/dev/null || true)
            if printf "%s" "$SB_OUT" | grep -q "^signature "; then
                report_pass \
                    "Assinatura EFI válida em $k_bin:" \
                    "Valid EFI signature on $k_bin:"
                printf "%s\n" "$SB_OUT" | grep -E "subject:|issuer:" | head -n 4 | sed 's/^/    /'
            else
                report_info \
                    "Sem assinatura EFI direta em $k_bin" \
                    "No direct EFI signature on $k_bin"
            fi
        fi
    done
    if [ "$FOUND_KERNELS" -eq 0 ]; then
        report_info \
            "Nenhum kernel (/boot/vmlinuz-*) ou UKI (/boot/EFI/Linux/*.efi) encontrado em /boot/" \
            "No kernel (/boot/vmlinuz-*) or UKI (/boot/EFI/Linux/*.efi) found in /boot/"
    fi

    for efi_bin in /boot/EFI/systemd/systemd-bootx64.efi /boot/EFI/BOOT/BOOTX64.EFI; do
        if [ -f "$efi_bin" ]; then
            SB_OUT=$(sbverify --list "$efi_bin" 2>/dev/null || true)
            if printf "%s" "$SB_OUT" | grep -q "^signature "; then
                report_pass \
                    "Assinatura EFI válida em $efi_bin:" \
                    "Valid EFI signature on $efi_bin:"
                printf "%s\n" "$SB_OUT" | grep -E "subject:|issuer:" | head -n 4 | sed 's/^/    /'
            else
                report_fail \
                    "Nenhuma assinatura EFI detectada em $efi_bin" \
                    "No EFI signature detected on $efi_bin"
            fi
        else
            report_info \
                "Binário não encontrado para verificação: $efi_bin" \
                "Binary not found for verification: $efi_bin"
        fi
    done
else
    report_warn \
        "Utilitário 'sbverify' (pacote sbsigntools) não encontrado; pulando inspeção EFI" \
        "Utility 'sbverify' (sbsigntools package) not found; skipping EFI inspection"
fi

# Verifica imposição de assinatura de módulos pelo kernel em execução
if [ -r /sys/module/module/parameters/sig_enforce ]; then
    SIG_ENFORCE=$(cat /sys/module/module/parameters/sig_enforce)
    if [ "$SIG_ENFORCE" = "Y" ]; then
        report_pass \
            "Imposição de assinatura de módulos ativa (sig_enforce = Y)" \
            "Module signature enforcement active (sig_enforce = Y)"
    else
        report_fail \
            "Imposição de assinatura de módulos desativada (sig_enforce = $SIG_ENFORCE)" \
            "Module signature enforcement disabled (sig_enforce = $SIG_ENFORCE)"
    fi
elif grep -q "module.sig_enforce=1" /proc/cmdline 2>/dev/null; then
    report_pass \
        "Parâmetro 'module.sig_enforce=1' ativo na linha de comando" \
        "Parameter 'module.sig_enforce=1' active on command line"
else
    report_warn \
        "Não foi possível confirmar module.sig_enforce ativo" \
        "Could not confirm module.sig_enforce is active"
fi

# Mostra chaves de confiança embutidas no kernel (/proc/keys)
if [ -f /proc/keys ]; then
    KERNEL_KEYS=$(grep -i "asymmetri" /proc/keys | grep -E "Build time|CachyOS|EAC|Database Key" || true)
    if [ -n "$KERNEL_KEYS" ]; then
        report_pass \
            "Chaves de assinatura de kernel/módulos ativas (/proc/keys):" \
            "Active kernel/module signing keys (/proc/keys):"
        printf "%s\n" "$KERNEL_KEYS" | sed 's/^/    /'
    else
        report_info \
            "Chaves assimétricas registradas em /proc/keys:" \
            "Asymmetric keys registered in /proc/keys:"
        grep -i "asymmetri" /proc/keys | head -n 5 | sed 's/^/    /' || true
    fi
else
    report_fail \
        "/proc/keys inacessível (CONFIG_KEYS desabilitado no kernel)" \
        "/proc/keys inaccessible (CONFIG_KEYS disabled in the kernel)"
fi

# Verifica assinatura dos módulos carregados no kernel atual
if command -v modinfo >/dev/null 2>&1 && [ -r /proc/modules ]; then
    TOTAL_MODS=0
    SIGNED_MODS=0
    UNSIGNED_LIST=""

    while read -r mod_name _; do
        TOTAL_MODS=$((TOTAL_MODS + 1))
        SIGNER=$(modinfo -F signer "$mod_name" 2>/dev/null | head -n 1 || true)
        if [ -n "$SIGNER" ]; then
            SIGNED_MODS=$((SIGNED_MODS + 1))
        else
            UNSIGNED_LIST="${UNSIGNED_LIST}${mod_name} "
        fi
    done < /proc/modules

    if [ "$TOTAL_MODS" -gt 0 ] && [ "$SIGNED_MODS" -eq "$TOTAL_MODS" ]; then
        report_pass \
            "Todos os $SIGNED_MODS/$TOTAL_MODS módulos carregados estão assinados" \
            "All $SIGNED_MODS/$TOTAL_MODS loaded modules are signed"
    elif [ "$TOTAL_MODS" -gt 0 ]; then
        report_fail \
            "$SIGNED_MODS/$TOTAL_MODS módulos assinados (sem assinatura: $UNSIGNED_LIST)" \
            "$SIGNED_MODS/$TOTAL_MODS modules signed (unsigned: $UNSIGNED_LIST)"
    fi

    # Destaca assinatura do driver NVIDIA (se carregado) e de um módulo padrão do kernel
    for sample_mod in nvidia drm; do
        if grep -q "^${sample_mod} " /proc/modules; then
            MOD_SIGNER=$(modinfo -F signer "$sample_mod" 2>/dev/null | head -n 1 || true)
            MOD_HASH=$(modinfo -F sig_hashalgo "$sample_mod" 2>/dev/null | head -n 1 || true)
            NONE_LABEL=$(t "<nenhum>" "<none>")
            report_info \
                "Módulo '$sample_mod' -> signer: ${MOD_SIGNER:-$NONE_LABEL} (hash: ${MOD_HASH:-n/a})" \
                "Module '$sample_mod' -> signer: ${MOD_SIGNER:-$NONE_LABEL} (hash: ${MOD_HASH:-n/a})"
        fi
    done
fi

# ------------------------------------------------------------------------------
# 8. Análise de Taint do Kernel (/proc/sys/kernel/tainted)
# ------------------------------------------------------------------------------
print_header \
    "8. Análise de Taint do Kernel (/proc/sys/kernel/tainted)" \
    "8. Kernel Taint Analysis (/proc/sys/kernel/tainted)"

if [ -f /proc/sys/kernel/tainted ]; then
    TAINT=$(cat /proc/sys/kernel/tainted)
    report_info \
        "Valor bruto em /proc/sys/kernel/tainted: $TAINT" \
        "Raw value in /proc/sys/kernel/tainted: $TAINT"

    IS_UNSIGNED=$((TAINT / 8192 % 2))
    IS_PROPRIETARY=$((TAINT % 2))
    IS_OOT=$((TAINT / 4096 % 2))

    if [ "$IS_UNSIGNED" -eq 1 ]; then
        report_fail \
            "Bit 13 ATIVO (8192): Módulo NÃO assinado no espaço do kernel!" \
            "Bit 13 ACTIVE (8192): Unsigned module in kernel space!"
    else
        report_pass \
            "Bit 13 DESATIVADO: Zero módulos não assinados no kernel" \
            "Bit 13 DISABLED: Zero unsigned modules in the kernel"
    fi

    if [ "$IS_PROPRIETARY" -eq 1 ]; then
        report_warn \
            "Bit 0 ATIVO (1): Módulo de código fechado presente" \
            "Bit 0 ACTIVE (1): Closed-source module present"
    else
        report_pass \
            "Bit 0 DESATIVADO: Livre de módulos fechados que violam GPL" \
            "Bit 0 DISABLED: Free of closed-source modules that violate the GPL"
    fi

    if [ "$IS_OOT" -eq 1 ]; then
        report_info \
            "Bit 12 ATIVO (4096): Módulos fora da árvore (out-of-tree)" \
            "Bit 12 ACTIVE (4096): Out-of-tree modules loaded (expected for NVIDIA open)"
    fi

    if [ "$TAINT" -eq 0 ]; then
        report_pass \
            "Kernel 100% puro (tainted = 0)" \
            "100% pure kernel (tainted = 0)"
    elif [ "$TAINT" -eq 4096 ]; then
        report_pass \
            "Kernel maculado unicamente por módulo aberto out-of-tree (tainted = 4096). Válido para o EAC!" \
            "Kernel tainted solely by an open-source out-of-tree module (tainted = 4096). Valid for EAC!"
    fi
fi

# ------------------------------------------------------------------------------
# 9. Linha de Comando do Kernel em Execução (/proc/cmdline)
# ------------------------------------------------------------------------------
print_header \
    "9. Parâmetros Ativos de Boot (/proc/cmdline)" \
    "9. Active Boot Parameters (/proc/cmdline)"

if [ -f /proc/cmdline ]; then
    CMDLINE_ACTUAL=$(cat /proc/cmdline)
    printf " [ ${BLUE}CMDLINE${NC} ] %s\n" "$CMDLINE_ACTUAL"

    if printf "%s" "$CMDLINE_ACTUAL" | grep -q "lockdown=integrity"; then
        report_pass \
            "Parâmetro 'lockdown=integrity' presente na linha de comando ativa" \
            "'lockdown=integrity' parameter present on the active command line"
    fi

    if printf "%s" "$CMDLINE_ACTUAL" | grep -q "intel_iommu=on"; then
        report_pass \
            "Parâmetro 'intel_iommu=on' presente na linha de comando ativa" \
            "'intel_iommu=on' parameter present on the active command line"
    fi

    if printf "%s" "$CMDLINE_ACTUAL" | grep -q "amd_iommu=on"; then
        report_pass \
            "Parâmetro 'amd_iommu=on' presente na linha de comando ativa" \
            "'amd_iommu=on' parameter present on the active command line"
    fi
fi

# ------------------------------------------------------------------------------
# 10. Resumo Final
# ------------------------------------------------------------------------------
print_header \
    "Resumo da Avaliação EAC Linux v2" \
    "EAC Linux v2 Evaluation Summary"

if [ "$IS_PT" -eq 1 ]; then
    printf "Sucessos: ${GREEN}%s${NC} | Falhas: ${RED}%s${NC} | Avisos: ${YELLOW}%s${NC}\n" "$PASS_COUNT" "$FAIL_COUNT" "$WARN_COUNT"
else
    printf "Successes: ${GREEN}%s${NC} | Fails: ${RED}%s${NC} | Warnings: ${YELLOW}%s${NC}\n" "$PASS_COUNT" "$FAIL_COUNT" "$WARN_COUNT"
fi

if [ "$FAIL_COUNT" -eq 0 ]; then
    printf "\n${GREEN}${BOLD}%s${NC}\n\n" "$(t \
        "✔ SISTEMA 100% CONFORME COM EAC LINUX V2 (Auditado diretamente via /sys e /proc)!" \
        "✔ SYSTEM 100% COMPLIANT WITH EAC LINUX V2 (Audited directly via /sys and /proc)!")"
    exit 0
else
    printf "\n${RED}${BOLD}%s${NC}\n\n" "$(t \
        "✘ Falhas detectadas na auditoria direta do kernel." \
        "✘ Failures detected during direct kernel auditing.")"
    exit 1
fi
