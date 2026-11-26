#!/usr/bin/env bash
# ==============================================================================
# Verificador de Integridade Direta via Kernel (/sys, /proc, /dev, /run)
# Compatibilidade com Easy Anti-Cheat (EAC) Linux v2
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
    echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}"
}

report_pass() {
    echo -e " [ ${GREEN}PASS${NC} ] $1"
    ((PASS_COUNT++))
}

report_fail() {
    echo -e " [ ${RED}FAIL${NC} ] $1"
    ((FAIL_COUNT++))
}

report_warn() {
    echo -e " [ ${YELLOW}WARN${NC} ] $1"
    ((WARN_COUNT++))
}

report_info() {
    echo -e " [ ${BLUE}INFO${NC} ] $1"
}

# Função auxiliar para extrair o byte de valor de uma variável EFI no /sys/firmware/efi/efivars
# As variáveis efivars possuem um cabeçalho de 4 bytes de atributos EFI seguidos pelo payload de dados.
read_efivar_byte() {
    local var_path="$1"
    if [[ -r "$var_path" ]]; then
        # Extrai o 5º byte (1 byte a partir do offset 4) em valor decimal
        od -An -j4 -N1 -tu1 "$var_path" 2>/dev/null | tr -d ' '
    else
        echo ""
    fi
}

# ------------------------------------------------------------------------------
# 1. UEFI Secure Boot e Setup Mode (/sys/firmware/efi/efivars/)
# ------------------------------------------------------------------------------
print_header "1. UEFI Secure Boot e Modo de Operação (/sys/firmware/efi/efivars/)"

# SecureBoot: GUID padrão global da UEFI 8be4df61-93ca-11d2-aa0d-00e098032b8c
SECURE_BOOT_FILE=$(compgen -G "/sys/firmware/efi/efivars/SecureBoot-*" | head -n 1 || true)
SETUP_MODE_FILE=$(compgen -G "/sys/firmware/efi/efivars/SetupMode-*" | head -n 1 || true)

if [[ -n "$SECURE_BOOT_FILE" && -f "$SECURE_BOOT_FILE" ]]; then
    SB_VAL=$(read_efivar_byte "$SECURE_BOOT_FILE")
    if [[ "$SB_VAL" == "1" ]]; then
        report_pass "SecureBoot ativo no firmware (efivar: 0x01): $(basename "$SECURE_BOOT_FILE")"
    else
        report_fail "SecureBoot desativado no firmware (efivar: $SB_VAL)"
    fi
else
    report_fail "Variável de firmware SecureBoot não encontrada em /sys/firmware/efi/efivars"
fi

if [[ -n "$SETUP_MODE_FILE" && -f "$SETUP_MODE_FILE" ]]; then
    SM_VAL=$(read_efivar_byte "$SETUP_MODE_FILE")
    if [[ "$SM_VAL" == "0" ]]; then
        report_pass "SetupMode desabilitado / Modo Usuário ativo (efivar: 0x00 - chaves em imposição)"
    else
        report_warn "SetupMode está ativo (efivar: $SM_VAL) - firmware aberto para gravação"
    fi
fi

# ------------------------------------------------------------------------------
# 2. TPM 2.0 & Measured Boot (/sys/class/tpm/, /dev/tpm*, /sys/kernel/security/tpm*)
# ------------------------------------------------------------------------------
print_header "2. TPM 2.0 & Measured Boot (/sys/class/tpm/, /dev/tpmrm0)"

if [[ -d /sys/class/tpm/tpm0 ]]; then
    report_pass "Interface de hardware TPM encontrada em /sys/class/tpm/tpm0"

    # Checa versão principal do TPM
    if [[ -f /sys/class/tpm/tpm0/tpm_version_major ]]; then
        TPM_VER=$(cat /sys/class/tpm/tpm0/tpm_version_major)
        if [[ "$TPM_VER" == "2" ]]; then
            report_pass "Versão do TPM confirmada pelo kernel: TPM 2.0"
        else
            report_warn "Versão do TPM reportada pelo kernel: TPM $TPM_VER"
        fi
    fi
else
    report_fail "Nenhuma interface TPM registrada em /sys/class/tpm/"
fi

# Checa se o Resource Manager do TPM está presente (necessário para multiplexação)
if [[ -c /dev/tpmrm0 ]]; then
    report_pass "Dispositivo de caracteres de kernel /dev/tpmrm0 operacional"
else
    report_fail "Dispositivo /dev/tpmrm0 ausente"
fi

# Checa medições do BIOS/Bootloader exportadas via securityfs
if [[ -f /sys/kernel/security/tpm0/binary_bios_measurements ]]; then
    MEASURE_SIZE=$(wc -c < /sys/kernel/security/tpm0/binary_bios_measurements)
    if [[ $MEASURE_SIZE -gt 0 ]]; then
        report_pass "Measured Boot ativo: $MEASURE_SIZE bytes de eventos medidos em /sys/kernel/security/tpm0/binary_bios_measurements"
    else
        report_warn "Log de medições /sys/kernel/security/tpm0/binary_bios_measurements está vazio"
    fi
else
    report_info "Registro /sys/kernel/security/tpm0/binary_bios_measurements não exposto"
fi

# ------------------------------------------------------------------------------
# 3. Kernel Lockdown (/sys/kernel/security/lockdown)
# ------------------------------------------------------------------------------
print_header "3. Kernel Lockdown (/sys/kernel/security/lockdown)"
if [[ -f /sys/kernel/security/lockdown ]]; then
    LOCKDOWN_RAW=$(cat /sys/kernel/security/lockdown)
    if echo "$LOCKDOWN_RAW" | grep -q "\[integrity\]"; then
        report_pass "Modo ativo: [integrity] (Ring-0 trancado contra adulteração)"
    elif echo "$LOCKDOWN_RAW" | grep -q "\[confidentiality\]"; then
        report_pass "Modo ativo: [confidentiality]"
    else
        report_fail "Lockdown desabilitado ou incorreto: $LOCKDOWN_RAW"
    fi
else
    report_fail "securityfs: /sys/kernel/security/lockdown inexistente"
fi

# ------------------------------------------------------------------------------
# 4. Bloqueio de kexec (/proc/sys/kernel/kexec_load_disabled)
# ------------------------------------------------------------------------------
print_header "4. Bloqueio de kexec (/proc/sys/kernel/kexec_load_disabled)"
if [[ -f /proc/sys/kernel/kexec_load_disabled ]]; then
    KEXEC_VAL=$(cat /proc/sys/kernel/kexec_load_disabled)
    if [[ "$KEXEC_VAL" == "1" ]]; then
        report_pass "/proc/sys/kernel/kexec_load_disabled = 1 (Injeção de novo kernel bloqueada)"
    else
        report_fail "/proc/sys/kernel/kexec_load_disabled = $KEXEC_VAL (Esperado: 1)"
    fi
else
    report_fail "/proc/sys/kernel/kexec_load_disabled inexistente"
fi

# ------------------------------------------------------------------------------
# 5. Isolamento IOMMU (/sys/kernel/iommu_groups, /sys/class/iommu)
# ------------------------------------------------------------------------------
print_header "5. Isolamento IOMMU (/sys/kernel/iommu_groups, /sys/class/iommu)"
if [[ -d /sys/kernel/iommu_groups ]]; then
    GROUP_COUNT=$(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d | wc -l)
    if [[ $GROUP_COUNT -gt 0 ]]; then
        report_pass "$GROUP_COUNT grupos de isolamento IOMMU populados em /sys/kernel/iommu_groups/"
    else
        report_fail "/sys/kernel/iommu_groups está vazio (IOMMU desativado)"
    fi
else
    report_fail "/sys/kernel/iommu_groups inexistente (Suporte IOMMU ausente)"
fi

if [[ -d /sys/class/iommu ]]; then
    IOMMU_DEVS=$(ls /sys/class/iommu 2>/dev/null | tr '\n' ' ' || true)
    report_info "Controladores IOMMU registrados no sysfs: $IOMMU_DEVS"
fi

# ------------------------------------------------------------------------------
# 6. LSM BPF (/sys/kernel/security/lsm)
# ------------------------------------------------------------------------------
print_header "6. Módulos de Segurança LSM (/sys/kernel/security/lsm)"
if [[ -f /sys/kernel/security/lsm ]]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if echo "$LSM_LIST" | grep -q "bpf"; then
        report_pass "LSM BPF carregado no securityfs: $LSM_LIST"
    else
        report_fail "LSM BPF não presente: $LSM_LIST"
    fi
else
    report_fail "/sys/kernel/security/lsm inacessível"
fi

# ------------------------------------------------------------------------------
# 7. Assinatura do Kernel, Bootloader e Módulos (sbverify, /proc/keys, modinfo)
# ------------------------------------------------------------------------------
print_header "7. Assinatura do Kernel, Bootloader e Módulos"

# Verifica assinatura EFI do kernel EAC e do systemd-boot via sbverify (sbsigntools)
if command -v sbverify >/dev/null 2>&1; then
    for efi_bin in /boot/vmlinuz-linux-cachyos-eac /boot/EFI/systemd/systemd-bootx64.efi; do
        if [[ -f "$efi_bin" ]]; then
            SB_OUT=$(sbverify --list "$efi_bin" 2>/dev/null || true)
            if echo "$SB_OUT" | grep -q "^signature "; then
                report_pass "Assinatura EFI válida em $efi_bin:"
                echo "$SB_OUT" | grep -E "subject:|issuer:| - /" | head -n 4 | sed 's/^/    /'
            else
                report_fail "Nenhuma assinatura EFI detectada em $efi_bin"
            fi
        else
            report_info "Binário não encontrado para verificação: $efi_bin"
        fi
    done
else
    report_warn "Utilitário 'sbverify' (pacote sbsigntools) não encontrado; pulando inspeção EFI"
fi

# Verifica imposição de assinatura de módulos pelo kernel em execução
if [[ -r /sys/module/module/parameters/sig_enforce ]]; then
    SIG_ENFORCE=$(cat /sys/module/module/parameters/sig_enforce)
    if [[ "$SIG_ENFORCE" == "Y" ]]; then
        report_pass "Imposição de assinatura de módulos ativa (sig_enforce = Y)"
    else
        report_fail "Imposição de assinatura de módulos desativada (sig_enforce = $SIG_ENFORCE)"
    fi
elif grep -q "module.sig_enforce=1" /proc/cmdline 2>/dev/null; then
    report_pass "Parâmetro 'module.sig_enforce=1' ativo na linha de comando"
else
    report_warn "Não foi possível confirmar module.sig_enforce ativo"
fi

# Mostra chaves de confiança embutidas no kernel (/proc/keys)
if [[ -f /proc/keys ]]; then
    KERNEL_KEYS=$(grep -i "asymmetric" /proc/keys | grep -E "Build time|CachyOS|EAC" || true)
    if [[ -n "$KERNEL_KEYS" ]]; then
        report_pass "Chaves de assinatura de kernel/módulos ativas (/proc/keys):"
        echo "$KERNEL_KEYS" | sed 's/^/    /'
    else
        report_info "Chaves assimétricas registradas em /proc/keys:"
        grep -i "asymmetric" /proc/keys | head -n 5 | sed 's/^/    /' || true
    fi
else
    report_fail "/proc/keys inacessível (CONFIG_KEYS desabilitado no kernel)"
fi

# Verifica assinatura dos módulos carregados no kernel atual
if command -v modinfo >/dev/null 2>&1 && [[ -r /proc/modules ]]; then
    TOTAL_MODS=0
    SIGNED_MODS=0
    UNSIGNED_LIST=""

    while read -r mod_name _; do
        ((TOTAL_MODS++))
        SIGNER=$(modinfo -F signer "$mod_name" 2>/dev/null | head -n 1 || true)
        if [[ -n "$SIGNER" ]]; then
            ((SIGNED_MODS++))
        else
            UNSIGNED_LIST+="$mod_name "
        fi
    done < /proc/modules

    if [[ $TOTAL_MODS -gt 0 && $SIGNED_MODS -eq $TOTAL_MODS ]]; then
        report_pass "Todos os $SIGNED_MODS/$TOTAL_MODS módulos carregados estão assinados"
    elif [[ $TOTAL_MODS -gt 0 ]]; then
        report_fail "$SIGNED_MODS/$TOTAL_MODS módulos assinados (sem assinatura: $UNSIGNED_LIST)"
    fi

    # Destaca assinatura do driver NVIDIA (se carregado) e de um módulo padrão do kernel
    for sample_mod in nvidia drm; do
        if grep -q "^${sample_mod} " /proc/modules; then
            MOD_SIGNER=$(modinfo -F signer "$sample_mod" 2>/dev/null | head -n 1 || true)
            MOD_HASH=$(modinfo -F sig_hashalgo "$sample_mod" 2>/dev/null | head -n 1 || true)
            report_info "Módulo '$sample_mod' -> signer: ${MOD_SIGNER:-<nenhum>} (hash: ${MOD_HASH:-n/a})"
        fi
    done
fi

# ------------------------------------------------------------------------------
# 8. Análise de Taint do Kernel (/proc/sys/kernel/tainted)
# ------------------------------------------------------------------------------
print_header "8. Análise de Taint do Kernel (/proc/sys/kernel/tainted)"
if [[ -f /proc/sys/kernel/tainted ]]; then
    TAINT=$(cat /proc/sys/kernel/tainted)
    report_info "Valor bruto em /proc/sys/kernel/tainted: $TAINT"

    # Bit 13: 8192 (TAINT_UNSIGNED_MODULE)
    IS_UNSIGNED=$(( (TAINT & 8192) != 0 ))
    # Bit 0: 1 (TAINT_PROPRIETARY_MODULE)
    IS_PROPRIETARY=$(( (TAINT & 1) != 0 ))
    # Bit 12: 4096 (TAINT_OOT_MODULE) -> DKMS Out-of-tree
    IS_OOT=$(( (TAINT & 4096) != 0 ))

    if [[ $IS_UNSIGNED -eq 1 ]]; then
        report_fail "Bit 13 ATIVO (8192): Módulo NÃO assinado no espaço do kernel!"
    else
        report_pass "Bit 13 DESATIVADO: Zero módulos não assinados no kernel"
    fi

    if [[ $IS_PROPRIETARY -eq 1 ]]; then
        report_warn "Bit 0 ATIVO (1): Módulo de código fechado presente"
    else
        report_pass "Bit 0 DESATIVADO: Livre de módulos fechados que violam GPL"
    fi

    if [[ $IS_OOT -eq 1 ]]; then
        report_info "Bit 12 ATIVO (4096): Módulos DKMS compilados fora da árvore (comportamento padrão e esperado)"
    fi

    if [[ $TAINT -eq 0 ]]; then
        report_pass "Kernel 100% puro (tainted = 0)"
    elif [[ $TAINT -eq 4096 ]]; then
        report_pass "Kernel maculado unicamente pelo DKMS aberto out-of-tree (tainted = 4096). Válido para o EAC!"
    fi
fi

# ------------------------------------------------------------------------------
# 9. Linha de Comando do Kernel em Execução (/proc/cmdline)
# ------------------------------------------------------------------------------
print_header "9. Parâmetros Ativos de Boot (/proc/cmdline)"
if [[ -f /proc/cmdline ]]; then
    CMDLINE_ACTUAL=$(cat /proc/cmdline)
    echo -e " [ ${BLUE}CMDLINE${NC} ] $CMDLINE_ACTUAL"

    if echo "$CMDLINE_ACTUAL" | grep -q "lockdown=integrity"; then
        report_pass "Parâmetro 'lockdown=integrity' presente na linha de comando ativa"
    fi

    if echo "$CMDLINE_ACTUAL" | grep -q "intel_iommu=on"; then
        report_pass "Parâmetro 'intel_iommu=on' presente na linha de comando ativa"
    fi
fi

# ------------------------------------------------------------------------------
# 10. Resumo Final
# ------------------------------------------------------------------------------
print_header "Resumo da Avaliação EAC Linux v2"
echo -e "Sucessos: ${GREEN}${PASS_COUNT}${NC} | Falhas: ${RED}${FAIL_COUNT}${NC} | Avisos: ${YELLOW}${WARN_COUNT}${NC}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "\n${GREEN}${BOLD}✔ SISTEMA 100% CONFORME COM EAC LINUX V2 (Auditado diretamente via /sys e /proc)!${NC}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}✘ Falhas detectadas na auditoria direta do kernel.${NC}\n"
    exit 1
fi
