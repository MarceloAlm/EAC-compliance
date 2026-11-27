#!/bin/sh
# ==============================================================================
# Verificador de Integridade Direta via Kernel (/sys, /proc, /dev, /run)
# Direct Kernel-Level Integrity Checker (/sys, /proc, /dev, /run)
# Compatibilidade / Compatibility: Easy Anti-Cheat (EAC) Linux v2
# ==============================================================================

set -u

LANG_OVERRIDE=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --pt) LANG_OVERRIDE="pt" ;;
        --en) LANG_OVERRIDE="en" ;;
        -h|--help)
            printf "Usage: sudo %s [--pt | --en]\n" "$0"
            exit 0
            ;;
        *)
            printf "Unknown option: %s\nUsage: sudo %s [--pt | --en]\n" "$1" "$0" >&2
            exit 1
            ;;
    esac
    shift
done

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

# Detecção de idioma (flag --pt/--en ou pt_BR/pt -> Português; demais -> English)
LOCALE_CHECK="${LANG_OVERRIDE:-${LC_ALL:-${LC_MESSAGES:-${LANG:-${LANGUAGE:-}}}}}"
case "$LOCALE_CHECK" in
    pt_BR*|pt_PT*|pt*)
        MSG_HDR_0="0. Ambiente do Kernel em Execução"
        MSG_KERNEL_RUNNING="Kernel em execução: %s (%s)"
        MSG_KIMG_SIGNED="Assinatura EFI do kernel em execução (%s):"
        MSG_UKI_SIGNED="Imagem bruta %s sem assinatura; UKI em /boot/EFI/Linux/arch-linux.efi assinada por:"
        MSG_KIMG_UKI_NOSIG="Kernel em execução (%s) e UKI sem assinatura EFI"
        MSG_KIMG_NOSIG="Kernel em execução (%s) sem assinatura EFI"
        MSG_KIMG_NOT_FOUND="Imagem do kernel em execução (%s) não localizada em /boot para checagem de assinatura"
        MSG_NO_SBVERIFY_KIMG="Utilitário 'sbverify' (pacote sbsigntools) não encontrado; não foi possível checar assinatura do kernel em execução"

        MSG_HDR_1="1. UEFI Secure Boot e Modo de Operação (/sys/firmware/efi/efivars/)"
        MSG_SB_ON="SecureBoot ativo no firmware (efivar: 0x01): %s"
        MSG_SB_OFF="SecureBoot desativado no firmware (efivar: %s)"
        MSG_SB_MISSING="Variável de firmware SecureBoot não encontrada em /sys/firmware/efi/efivars"
        MSG_SM_USER="SetupMode desabilitado / Modo Usuário ativo (efivar: 0x00 - chaves em imposição)"
        MSG_SM_ACTIVE="SetupMode está ativo (efivar: %s) - firmware aberto para gravação"

        MSG_HDR_2="2. TPM 2.0 & Measured Boot (/sys/class/tpm/, /dev/tpmrm0)"
        MSG_TPM_FOUND="Interface de hardware TPM encontrada em /sys/class/tpm/tpm0"
        MSG_TPM_VER_2="Versão do TPM confirmada pelo kernel: TPM 2.0"
        MSG_TPM_VER_OTHER="Versão do TPM reportada pelo kernel: TPM %s"
        MSG_TPM_MISSING="Nenhuma interface TPM registrada em /sys/class/tpm/"
        MSG_TPMRM0_OK="Dispositivo de caracteres de kernel /dev/tpmrm0 operacional"
        MSG_TPMRM0_MISSING="Dispositivo /dev/tpmrm0 ausente"
        MSG_MEASURED_OK="Measured Boot ativo: %s bytes de eventos medidos em /sys/kernel/security/tpm0/binary_bios_measurements"
        MSG_MEASURED_EMPTY="Log de medições /sys/kernel/security/tpm0/binary_bios_measurements está vazio"
        MSG_MEASURED_MISSING="Registro /sys/kernel/security/tpm0/binary_bios_measurements não exposto"

        MSG_HDR_3="3. Kernel Lockdown (/sys/kernel/security/lockdown)"
        MSG_LOCKDOWN_INT="Modo ativo: [integrity] (Ring-0 trancado contra adulteração)"
        MSG_LOCKDOWN_CONF="Modo ativo: [confidentiality]"
        MSG_LOCKDOWN_FAIL="Lockdown desabilitado ou incorreto: %s"
        MSG_LOCKDOWN_MISSING="securityfs: /sys/kernel/security/lockdown inexistente"

        MSG_HDR_4="4. Bloqueio de kexec (/proc/sys/kernel/kexec_load_disabled)"
        MSG_KEXEC_OK="/proc/sys/kernel/kexec_load_disabled = 1 (Injeção de novo kernel bloqueada)"
        MSG_KEXEC_FAIL="/proc/sys/kernel/kexec_load_disabled = %s (Esperado: 1)"
        MSG_KEXEC_MISSING="/proc/sys/kernel/kexec_load_disabled inexistente"

        MSG_HDR_5="5. Isolamento IOMMU (/sys/kernel/iommu_groups, /sys/class/iommu)"
        MSG_IOMMU_OK="%s grupos de isolamento IOMMU populados em /sys/kernel/iommu_groups/"
        MSG_IOMMU_EMPTY="/sys/kernel/iommu_groups está vazio (IOMMU desativado)"
        MSG_IOMMU_MISSING="/sys/kernel/iommu_groups inexistente (Suporte IOMMU ausente)"
        MSG_IOMMU_DEVS="Controladores IOMMU registrados no sysfs: %s"

        MSG_HDR_6="6. Módulos de Segurança LSM (/sys/kernel/security/lsm)"
        MSG_LSM_OK="LSM BPF carregado no securityfs: %s"
        MSG_LSM_FAIL="LSM BPF não presente: %s"
        MSG_LSM_MISSING="/sys/kernel/security/lsm inacessível"

        MSG_HDR_7="7. Assinatura do Kernel, Bootloader e Módulos"
        MSG_EFI_SIG_OK="Assinatura EFI válida em %s:"
        MSG_EFI_SIG_NONE="Sem assinatura EFI direta em %s"
        MSG_EFI_NO_KERNELS="Nenhum kernel (/boot/vmlinuz-*) ou UKI (/boot/EFI/Linux/*.efi) encontrado em /boot/"
        MSG_EFI_BIN_FAIL="Nenhuma assinatura EFI detectada em %s"
        MSG_EFI_BIN_MISSING="Binário não encontrado para verificação: %s"
        MSG_NO_SBVERIFY_EFI="Utilitário 'sbverify' (pacote sbsigntools) não encontrado; pulando inspeção EFI"
        MSG_SIG_ENFORCE_OK="Imposição de assinatura de módulos ativa (sig_enforce = Y)"
        MSG_SIG_ENFORCE_FAIL="Imposição de assinatura de módulos desativada (sig_enforce = %s)"
        MSG_SIG_ENFORCE_CMDLINE="Parâmetro 'module.sig_enforce=1' ativo na linha de comando"
        MSG_SIG_ENFORCE_WARN="Não foi possível confirmar module.sig_enforce ativo"
        MSG_KEYS_ACTIVE="Chaves de assinatura de kernel/módulos ativas (/proc/keys):"
        MSG_KEYS_ASYM="Chaves assimétricas registradas em /proc/keys:"
        MSG_KEYS_MISSING="/proc/keys inacessível (CONFIG_KEYS desabilitado no kernel)"
        MSG_MODS_ALL_SIGNED="Todos os %s/%s módulos carregados estão assinados"
        MSG_MODS_UNSIGNED="%s/%s módulos assinados (sem assinatura: %s)"
        MSG_NONE_LABEL="<nenhum>"
        MSG_MOD_SAMPLE="Módulo '%s' -> signer: %s (hash: %s)"

        MSG_HDR_8="8. Análise de Taint do Kernel (/proc/sys/kernel/tainted)"
        MSG_TAINT_RAW="Valor bruto em /proc/sys/kernel/tainted: %s"
        MSG_TAINT_BIT13_FAIL="Bit 13 ATIVO (8192): Módulo NÃO assinado no espaço do kernel!"
        MSG_TAINT_BIT13_OK="Bit 13 DESATIVADO: Zero módulos não assinados no kernel"
        MSG_TAINT_BIT0_WARN="Bit 0 ATIVO (1): Módulo de código fechado presente"
        MSG_TAINT_BIT0_OK="Bit 0 DESATIVADO: Livre de módulos fechados que violam GPL"
        MSG_TAINT_BIT12_INFO="Bit 12 ATIVO (4096): Módulos fora da árvore (out-of-tree)"
        MSG_TAINT_PURE="Kernel 100%% puro (tainted = 0)"
        MSG_TAINT_OOT_VALID="Kernel maculado unicamente por módulo aberto out-of-tree (tainted = 4096). Válido para o EAC!"

        MSG_HDR_9="9. Parâmetros Ativos de Boot (/proc/cmdline)"
        MSG_CMDLINE_PARAM="Parâmetro '%s' presente na linha de comando ativa"

        MSG_HDR_10="Resumo da Avaliação EAC Linux v2"
        MSG_LBL_PASS="Sucessos"
        MSG_LBL_FAIL="Falhas"
        MSG_LBL_WARN="Avisos"
        MSG_SUMMARY_PASS="✔ SISTEMA 100%% CONFORME COM EAC LINUX V2 (Auditado diretamente via /sys e /proc)!"
        MSG_SUMMARY_FAIL="✘ Falhas detectadas na auditoria direta do kernel."
        MSG_ROOT_REQUIRED="Este script precisa ser executado como root (use: sudo %s)."
        ;;
    *)
        MSG_HDR_0="0. Running Kernel Environment"
        MSG_KERNEL_RUNNING="Running kernel: %s (%s)"
        MSG_KIMG_SIGNED="Running kernel EFI signature (%s):"
        MSG_UKI_SIGNED="Raw image %s unsigned; UKI at /boot/EFI/Linux/arch-linux.efi signed by:"
        MSG_KIMG_UKI_NOSIG="Running kernel (%s) and UKI have no EFI signature"
        MSG_KIMG_NOSIG="Running kernel (%s) has no EFI signature"
        MSG_KIMG_NOT_FOUND="Running kernel image (%s) not found in /boot for signature check"
        MSG_NO_SBVERIFY_KIMG="Utility 'sbverify' (sbsigntools package) not found; could not check running kernel signature"

        MSG_HDR_1="1. UEFI Secure Boot and Operation Mode (/sys/firmware/efi/efivars/)"
        MSG_SB_ON="Secure Boot enabled in firmware (efivar: 0x01): %s"
        MSG_SB_OFF="Secure Boot disabled in firmware (efivar: %s)"
        MSG_SB_MISSING="Secure Boot firmware variable not found in /sys/firmware/efi/efivars"
        MSG_SM_USER="Setup Mode disabled / User Mode active (efivar: 0x00 - keys enforced)"
        MSG_SM_ACTIVE="Setup Mode is active (efivar: %s) - firmware open for writing"

        MSG_HDR_2="2. TPM 2.0 & Measured Boot (/sys/class/tpm/, /dev/tpmrm0)"
        MSG_TPM_FOUND="TPM hardware interface found at /sys/class/tpm/tpm0"
        MSG_TPM_VER_2="TPM version confirmed by the kernel: TPM 2.0"
        MSG_TPM_VER_OTHER="TPM version reported by the kernel: TPM %s"
        MSG_TPM_MISSING="No TPM interface registered in /sys/class/tpm/"
        MSG_TPMRM0_OK="Operational /dev/tpmrm0 kernel character device"
        MSG_TPMRM0_MISSING="Device /dev/tpmrm0 missing"
        MSG_MEASURED_OK="Measured Boot active: %s bytes of measured events in /sys/kernel/security/tpm0/binary_bios_measurements"
        MSG_MEASURED_EMPTY="The measurement log /sys/kernel/security/tpm0/binary_bios_measurements is empty"
        MSG_MEASURED_MISSING="/sys/kernel/security/tpm0/binary_bios_measurements register not exposed"

        MSG_HDR_3="3. Kernel Lockdown (/sys/kernel/security/lockdown)"
        MSG_LOCKDOWN_INT="Active mode: [integrity] (Ring-0 locked against tampering)"
        MSG_LOCKDOWN_CONF="Active mode: [confidentiality]"
        MSG_LOCKDOWN_FAIL="Lockdown disabled or incorrect: %s"
        MSG_LOCKDOWN_MISSING="securityfs: /sys/kernel/security/lockdown does not exist"

        MSG_HDR_4="4. kexec Lock (/proc/sys/kernel/kexec_load_disabled)"
        MSG_KEXEC_OK="/proc/sys/kernel/kexec_load_disabled = 1 (Injection of new kernel blocked)"
        MSG_KEXEC_FAIL="/proc/sys/kernel/kexec_load_disabled = %s (Expected: 1)"
        MSG_KEXEC_MISSING="/proc/sys/kernel/kexec_load_disabled does not exist"

        MSG_HDR_5="5. IOMMU Isolation (/sys/kernel/iommu_groups, /sys/class/iommu)"
        MSG_IOMMU_OK="%s IOMMU isolation groups populated in /sys/kernel/iommu_groups/"
        MSG_IOMMU_EMPTY="/sys/kernel/iommu_groups is empty (IOMMU disabled)"
        MSG_IOMMU_MISSING="/sys/kernel/iommu_groups does not exist (IOMMU support missing)"
        MSG_IOMMU_DEVS="IOMMU controllers registered in sysfs: %s"

        MSG_HDR_6="6. LSM Security Modules (/sys/kernel/security/lsm)"
        MSG_LSM_OK="LSM BPF loaded in securityfs: %s"
        MSG_LSM_FAIL="LSM BPF not present: %s"
        MSG_LSM_MISSING="/sys/kernel/security/lsm inaccessible"

        MSG_HDR_7="7. Kernel, Bootloader, and Module Signatures"
        MSG_EFI_SIG_OK="Valid EFI signature on %s:"
        MSG_EFI_SIG_NONE="No direct EFI signature on %s"
        MSG_EFI_NO_KERNELS="No kernel (/boot/vmlinuz-*) or UKI (/boot/EFI/Linux/*.efi) found in /boot/"
        MSG_EFI_BIN_FAIL="No EFI signature detected on %s"
        MSG_EFI_BIN_MISSING="Binary not found for verification: %s"
        MSG_NO_SBVERIFY_EFI="Utility 'sbverify' (sbsigntools package) not found; skipping EFI inspection"
        MSG_SIG_ENFORCE_OK="Module signature enforcement active (sig_enforce = Y)"
        MSG_SIG_ENFORCE_FAIL="Module signature enforcement disabled (sig_enforce = %s)"
        MSG_SIG_ENFORCE_CMDLINE="Parameter 'module.sig_enforce=1' active on command line"
        MSG_SIG_ENFORCE_WARN="Could not confirm module.sig_enforce is active"
        MSG_KEYS_ACTIVE="Active kernel/module signing keys (/proc/keys):"
        MSG_KEYS_ASYM="Asymmetric keys registered in /proc/keys:"
        MSG_KEYS_MISSING="/proc/keys inaccessible (CONFIG_KEYS disabled in the kernel)"
        MSG_MODS_ALL_SIGNED="All %s/%s loaded modules are signed"
        MSG_MODS_UNSIGNED="%s/%s modules signed (unsigned: %s)"
        MSG_NONE_LABEL="<none>"
        MSG_MOD_SAMPLE="Module '%s' -> signer: %s (hash: %s)"

        MSG_HDR_8="8. Kernel Taint Analysis (/proc/sys/kernel/tainted)"
        MSG_TAINT_RAW="Raw value in /proc/sys/kernel/tainted: %s"
        MSG_TAINT_BIT13_FAIL="Bit 13 ACTIVE (8192): Unsigned module in kernel space!"
        MSG_TAINT_BIT13_OK="Bit 13 DISABLED: Zero unsigned modules in the kernel"
        MSG_TAINT_BIT0_WARN="Bit 0 ACTIVE (1): Closed-source module present"
        MSG_TAINT_BIT0_OK="Bit 0 DISABLED: Free of closed-source modules that violate the GPL"
        MSG_TAINT_BIT12_INFO="Bit 12 ACTIVE (4096): Out-of-tree modules loaded (expected for NVIDIA open)"
        MSG_TAINT_PURE="100%% pure kernel (tainted = 0)"
        MSG_TAINT_OOT_VALID="Kernel tainted solely by an open-source out-of-tree module (tainted = 4096). Valid for EAC!"

        MSG_HDR_9="9. Active Boot Parameters (/proc/cmdline)"
        MSG_CMDLINE_PARAM="'%s' parameter present on the active command line"

        MSG_HDR_10="EAC Linux v2 Evaluation Summary"
        MSG_LBL_PASS="Successes"
        MSG_LBL_FAIL="Fails"
        MSG_LBL_WARN="Warnings"
        MSG_SUMMARY_PASS="✔ SYSTEM 100%% COMPLIANT WITH EAC LINUX V2 (Audited directly via /sys and /proc)!"
        MSG_SUMMARY_FAIL="✘ Failures detected during direct kernel auditing."
        MSG_ROOT_REQUIRED="This script must be run as root (use: sudo %s)."
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    printf "\n [ ${RED}FAIL${NC} ] ${MSG_ROOT_REQUIRED}\n\n" "$0" >&2
    exit 1
fi

print_header() {
    _fmt="$1"; shift
    printf "\n${BOLD}${CYAN}=== ${_fmt} ===${NC}\n" "$@"
}

report_pass() {
    _fmt="$1"; shift
    printf " [ ${GREEN}PASS${NC} ] ${_fmt}\n" "$@"
    PASS_COUNT=$((PASS_COUNT + 1))
}

report_fail() {
    _fmt="$1"; shift
    printf " [ ${RED}FAIL${NC} ] ${_fmt}\n" "$@"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

report_warn() {
    _fmt="$1"; shift
    printf " [ ${YELLOW}WARN${NC} ] ${_fmt}\n" "$@"
    WARN_COUNT=$((WARN_COUNT + 1))
}

report_info() {
    _fmt="$1"; shift
    printf " [ ${BLUE}INFO${NC} ] ${_fmt}\n" "$@"
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

print_header "$MSG_HDR_0"
report_info "$MSG_KERNEL_RUNNING" "$KERNEL_REL" "$KERNEL_ARCH"

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
            report_pass "$MSG_KIMG_SIGNED" "$RUNNING_KIMG"
            printf "%s\n" "$SB_RUN_OUT" | grep -E "subject:|issuer:" | head -n 4 | sed 's/^/    /'
        elif [ "$PKGBASE" = "linux" ] && [ -f /boot/EFI/Linux/arch-linux.efi ]; then
            SB_UKI_OUT=$(sbverify --list /boot/EFI/Linux/arch-linux.efi 2>/dev/null || true)
            if printf "%s" "$SB_UKI_OUT" | grep -q "^signature "; then
                report_info "$MSG_UKI_SIGNED" "$RUNNING_KIMG"
                printf "%s\n" "$SB_UKI_OUT" | grep -E "subject:|issuer:" | head -n 4 | sed 's/^/    /'
            else
                report_fail "$MSG_KIMG_UKI_NOSIG" "$RUNNING_KIMG"
            fi
        else
            report_fail "$MSG_KIMG_NOSIG" "$RUNNING_KIMG"
        fi
    else
        report_info "$MSG_KIMG_NOT_FOUND" "$KERNEL_REL"
    fi
else
    report_warn "$MSG_NO_SBVERIFY_KIMG"
fi

# ------------------------------------------------------------------------------
# 1. UEFI Secure Boot e Setup Mode (/sys/firmware/efi/efivars/)
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_1"

SECURE_BOOT_FILE=$(find /sys/firmware/efi/efivars -maxdepth 1 -name 'SecureBoot-*' 2>/dev/null | head -n 1 || true)
SETUP_MODE_FILE=$(find /sys/firmware/efi/efivars -maxdepth 1 -name 'SetupMode-*' 2>/dev/null | head -n 1 || true)

if [ -n "$SECURE_BOOT_FILE" ] && [ -f "$SECURE_BOOT_FILE" ]; then
    SB_VAL=$(read_efivar_byte "$SECURE_BOOT_FILE")
    SB_BASE=$(basename "$SECURE_BOOT_FILE")
    if [ "$SB_VAL" = "1" ]; then
        report_pass "$MSG_SB_ON" "$SB_BASE"
    else
        report_fail "$MSG_SB_OFF" "$SB_VAL"
    fi
else
    report_fail "$MSG_SB_MISSING"
fi

if [ -n "$SETUP_MODE_FILE" ] && [ -f "$SETUP_MODE_FILE" ]; then
    SM_VAL=$(read_efivar_byte "$SETUP_MODE_FILE")
    if [ "$SM_VAL" = "0" ]; then
        report_pass "$MSG_SM_USER"
    else
        report_warn "$MSG_SM_ACTIVE" "$SM_VAL"
    fi
fi

# ------------------------------------------------------------------------------
# 2. TPM 2.0 & Measured Boot (/sys/class/tpm/, /dev/tpm*, /sys/kernel/security/tpm*)
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_2"

if [ -d /sys/class/tpm/tpm0 ]; then
    report_pass "$MSG_TPM_FOUND"

    if [ -f /sys/class/tpm/tpm0/tpm_version_major ]; then
        TPM_VER=$(cat /sys/class/tpm/tpm0/tpm_version_major)
        if [ "$TPM_VER" = "2" ]; then
            report_pass "$MSG_TPM_VER_2"
        else
            report_warn "$MSG_TPM_VER_OTHER" "$TPM_VER"
        fi
    fi
else
    report_fail "$MSG_TPM_MISSING"
fi

if [ -c /dev/tpmrm0 ]; then
    report_pass "$MSG_TPMRM0_OK"
else
    report_fail "$MSG_TPMRM0_MISSING"
fi

if [ -f /sys/kernel/security/tpm0/binary_bios_measurements ]; then
    MEASURE_SIZE=$(wc -c < /sys/kernel/security/tpm0/binary_bios_measurements)
    if [ "$MEASURE_SIZE" -gt 0 ]; then
        report_pass "$MSG_MEASURED_OK" "$MEASURE_SIZE"
    else
        report_warn "$MSG_MEASURED_EMPTY"
    fi
else
    report_info "$MSG_MEASURED_MISSING"
fi

# ------------------------------------------------------------------------------
# 3. Kernel Lockdown (/sys/kernel/security/lockdown)
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_3"

if [ -f /sys/kernel/security/lockdown ]; then
    LOCKDOWN_RAW=$(cat /sys/kernel/security/lockdown)
    if printf "%s" "$LOCKDOWN_RAW" | grep -q "\[integrity\]"; then
        report_pass "$MSG_LOCKDOWN_INT"
    elif printf "%s" "$LOCKDOWN_RAW" | grep -q "\[confidentiality\]"; then
        report_pass "$MSG_LOCKDOWN_CONF"
    else
        report_fail "$MSG_LOCKDOWN_FAIL" "$LOCKDOWN_RAW"
    fi
else
    report_fail "$MSG_LOCKDOWN_MISSING"
fi

# ------------------------------------------------------------------------------
# 4. Bloqueio de kexec (/proc/sys/kernel/kexec_load_disabled)
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_4"

if [ -f /proc/sys/kernel/kexec_load_disabled ]; then
    KEXEC_VAL=$(cat /proc/sys/kernel/kexec_load_disabled)
    if [ "$KEXEC_VAL" = "1" ]; then
        report_pass "$MSG_KEXEC_OK"
    else
        report_fail "$MSG_KEXEC_FAIL" "$KEXEC_VAL"
    fi
else
    report_fail "$MSG_KEXEC_MISSING"
fi

# ------------------------------------------------------------------------------
# 5. Isolamento IOMMU (/sys/kernel/iommu_groups, /sys/class/iommu)
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_5"

if [ -d /sys/kernel/iommu_groups ]; then
    GROUP_COUNT=$(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$GROUP_COUNT" -gt 0 ]; then
        report_pass "$MSG_IOMMU_OK" "$GROUP_COUNT"
    else
        report_fail "$MSG_IOMMU_EMPTY"
    fi
else
    report_fail "$MSG_IOMMU_MISSING"
fi

if [ -d /sys/class/iommu ]; then
    IOMMU_DEVS=$(ls /sys/class/iommu 2>/dev/null | tr '\n' ' ' || true)
    report_info "$MSG_IOMMU_DEVS" "$IOMMU_DEVS"
fi

# ------------------------------------------------------------------------------
# 6. LSM BPF (/sys/kernel/security/lsm)
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_6"

if [ -f /sys/kernel/security/lsm ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if printf "%s" "$LSM_LIST" | grep -q "bpf"; then
        report_pass "$MSG_LSM_OK" "$LSM_LIST"
    else
        report_fail "$MSG_LSM_FAIL" "$LSM_LIST"
    fi
else
    report_fail "$MSG_LSM_MISSING"
fi

# ------------------------------------------------------------------------------
# 7. Assinatura do Kernel, Bootloader e Módulos (sbverify, /proc/keys, modinfo)
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_7"

# Verifica assinatura EFI dos kernels/UKIs em /boot/ e do bootloader via sbverify (sbsigntools)
if command -v sbverify >/dev/null 2>&1; then
    FOUND_KERNELS=0
    for k_bin in /boot/vmlinuz-* /boot/EFI/Linux/*.efi; do
        if [ -f "$k_bin" ]; then
            FOUND_KERNELS=1
            SB_OUT=$(sbverify --list "$k_bin" 2>/dev/null || true)
            if printf "%s" "$SB_OUT" | grep -q "^signature "; then
                report_pass "$MSG_EFI_SIG_OK" "$k_bin"
                printf "%s\n" "$SB_OUT" | grep -E "subject:|issuer:" | head -n 4 | sed 's/^/    /'
            else
                report_info "$MSG_EFI_SIG_NONE" "$k_bin"
            fi
        fi
    done
    if [ "$FOUND_KERNELS" -eq 0 ]; then
        report_info "$MSG_EFI_NO_KERNELS"
    fi

    for efi_bin in /boot/EFI/systemd/systemd-bootx64.efi /boot/EFI/BOOT/BOOTX64.EFI; do
        if [ -f "$efi_bin" ]; then
            SB_OUT=$(sbverify --list "$efi_bin" 2>/dev/null || true)
            if printf "%s" "$SB_OUT" | grep -q "^signature "; then
                report_pass "$MSG_EFI_SIG_OK" "$efi_bin"
                printf "%s\n" "$SB_OUT" | grep -E "subject:|issuer:" | head -n 4 | sed 's/^/    /'
            else
                report_fail "$MSG_EFI_BIN_FAIL" "$efi_bin"
            fi
        else
            report_info "$MSG_EFI_BIN_MISSING" "$efi_bin"
        fi
    done
else
    report_warn "$MSG_NO_SBVERIFY_EFI"
fi

# Verifica imposição de assinatura de módulos pelo kernel em execução
if [ -r /sys/module/module/parameters/sig_enforce ]; then
    SIG_ENFORCE=$(cat /sys/module/module/parameters/sig_enforce)
    if [ "$SIG_ENFORCE" = "Y" ]; then
        report_pass "$MSG_SIG_ENFORCE_OK"
    else
        report_fail "$MSG_SIG_ENFORCE_FAIL" "$SIG_ENFORCE"
    fi
elif grep -q "module.sig_enforce=1" /proc/cmdline 2>/dev/null; then
    report_pass "$MSG_SIG_ENFORCE_CMDLINE"
else
    report_warn "$MSG_SIG_ENFORCE_WARN"
fi

# Mostra chaves de confiança embutidas no kernel (/proc/keys)
if [ -f /proc/keys ]; then
    KERNEL_KEYS=$(grep -i "asymmetri" /proc/keys | grep -E "Build time|CachyOS|EAC|Database Key" || true)
    if [ -n "$KERNEL_KEYS" ]; then
        report_pass "$MSG_KEYS_ACTIVE"
        printf "%s\n" "$KERNEL_KEYS" | sed 's/^/    /'
    else
        report_info "$MSG_KEYS_ASYM"
        grep -i "asymmetri" /proc/keys | head -n 5 | sed 's/^/    /' || true
    fi
else
    report_fail "$MSG_KEYS_MISSING"
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
        report_pass "$MSG_MODS_ALL_SIGNED" "$SIGNED_MODS" "$TOTAL_MODS"
    elif [ "$TOTAL_MODS" -gt 0 ]; then
        report_fail "$MSG_MODS_UNSIGNED" "$SIGNED_MODS" "$TOTAL_MODS" "$UNSIGNED_LIST"
    fi

    # Destaca assinatura do driver NVIDIA (se carregado) e de um módulo padrão do kernel
    for sample_mod in nvidia drm; do
        if grep -q "^${sample_mod} " /proc/modules; then
            MOD_SIGNER=$(modinfo -F signer "$sample_mod" 2>/dev/null | head -n 1 || true)
            MOD_HASH=$(modinfo -F sig_hashalgo "$sample_mod" 2>/dev/null | head -n 1 || true)
            report_info "$MSG_MOD_SAMPLE" "$sample_mod" "${MOD_SIGNER:-$MSG_NONE_LABEL}" "${MOD_HASH:-n/a}"
        fi
    done
fi

# ------------------------------------------------------------------------------
# 8. Análise de Taint do Kernel (/proc/sys/kernel/tainted)
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_8"

if [ -f /proc/sys/kernel/tainted ]; then
    TAINT=$(cat /proc/sys/kernel/tainted)
    report_info "$MSG_TAINT_RAW" "$TAINT"

    IS_UNSIGNED=$((TAINT / 8192 % 2))
    IS_PROPRIETARY=$((TAINT % 2))
    IS_OOT=$((TAINT / 4096 % 2))

    if [ "$IS_UNSIGNED" -eq 1 ]; then
        report_fail "$MSG_TAINT_BIT13_FAIL"
    else
        report_pass "$MSG_TAINT_BIT13_OK"
    fi

    if [ "$IS_PROPRIETARY" -eq 1 ]; then
        report_warn "$MSG_TAINT_BIT0_WARN"
    else
        report_pass "$MSG_TAINT_BIT0_OK"
    fi

    if [ "$IS_OOT" -eq 1 ]; then
        report_info "$MSG_TAINT_BIT12_INFO"
    fi

    if [ "$TAINT" -eq 0 ]; then
        report_pass "$MSG_TAINT_PURE"
    elif [ "$TAINT" -eq 4096 ]; then
        report_pass "$MSG_TAINT_OOT_VALID"
    fi
fi

# ------------------------------------------------------------------------------
# 9. Linha de Comando do Kernel em Execução (/proc/cmdline)
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_9"

if [ -f /proc/cmdline ]; then
    CMDLINE_ACTUAL=$(cat /proc/cmdline)
    printf " [ ${BLUE}CMDLINE${NC} ] %s\n" "$CMDLINE_ACTUAL"

    if printf "%s" "$CMDLINE_ACTUAL" | grep -q "lockdown=integrity"; then
        report_pass "$MSG_CMDLINE_PARAM" "lockdown=integrity"
    fi

    if printf "%s" "$CMDLINE_ACTUAL" | grep -q "intel_iommu=on"; then
        report_pass "$MSG_CMDLINE_PARAM" "intel_iommu=on"
    fi

    if printf "%s" "$CMDLINE_ACTUAL" | grep -q "amd_iommu=on"; then
        report_pass "$MSG_CMDLINE_PARAM" "amd_iommu=on"
    fi
fi

# ------------------------------------------------------------------------------
# 10. Resumo Final
# ------------------------------------------------------------------------------
print_header "$MSG_HDR_10"

printf "%s: ${GREEN}%s${NC} | %s: ${RED}%s${NC} | %s: ${YELLOW}%s${NC}\n" \
    "$MSG_LBL_PASS" "$PASS_COUNT" "$MSG_LBL_FAIL" "$FAIL_COUNT" "$MSG_LBL_WARN" "$WARN_COUNT"

if [ "$FAIL_COUNT" -eq 0 ]; then
    printf "\n${GREEN}${BOLD}${MSG_SUMMARY_PASS}${NC}\n\n"
    exit 0
else
    printf "\n${RED}${BOLD}${MSG_SUMMARY_FAIL}${NC}\n\n"
    exit 1
fi
