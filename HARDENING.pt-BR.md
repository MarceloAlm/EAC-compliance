# Guia de Hardening Arch Linux: Alinhamento CIS Benchmark e Defesa em Profundidade

[![Arch Linux](https://img.shields.io/badge/Arch%20Linux-Hardened-1793d1?logo=arch-linux&logoColor=white)](https://archlinux.org/)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-Level%201%20%26%202-success)](https://www.cisecurity.org/cis-benchmarks/)
[![Secure Boot](https://img.shields.io/badge/UEFI-Secure%20Boot%20Ativo-blue?logo=linux&logoColor=white)](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> Read this guide in English: **[English](HARDENING.md)**  
> Este guia é o complemento de segurança e hardening do repositório, aproveitando as fundações de boot e kernel do **[Guia EAC Linux v2](README.pt-BR.md)**.

Este documento consolida as diretrizes técnicas para transformar uma instalação do **Arch Linux** em um ambiente de alta segurança operacional. O alinhamento segue as melhores práticas do **CIS Linux Benchmark** (*Center for Internet Security*), cobrindo desde a integridade do firmware até o espaço do usuário, sem comprometer a estabilidade do sistema nem o desempenho gráfico para trabalho ou jogos.

---

## Índice

- [1. Princípios de Defesa em Profundidade e Níveis CIS](#1-princípios-de-defesa-em-profundidade-e-níveis-cis)
- [2. Camada 1: Firmware, Boot e Integridade de Ring-0 (A Base Consolidada)](#2-camada-1-firmware-boot-e-integridade-de-ring-0-a-base-consolidada)
- [3. Camada 2: Hardening de Kernel e Memória via Sysctl (CIS 1.5 & 3.x)](#3-camada-2-hardening-de-kernel-e-memória-via-sysctl-cis-15--3x)
- [4. Camada 3: Proteção do Sistema de Arquivos e Módulos Obsoletos (CIS 1.1)](#4-camada-3-proteção-do-sistema-de-arquivos-e-módulos-obsoletos-cis-11)
- [5. Camada 4: Blindagem da Pilha de Rede TCP/IP (CIS 3.1 & 3.2)](#5-camada-4-blindagem-da-pilha-de-rede-tcpip-cis-31--32)
- [6. Camada 5: Controle de Privilégios, PAM e Sudo Seguro (CIS 5.x)](#6-camada-5-controle-de-privilégios-pam-e-sudo-seguro-cis-5x)
- [7. Camada 6: Auditoria de Eventos e Rastreamento com `auditd` (CIS 4.x)](#7-camada-6-auditoria-de-eventos-e-rastreamento-com-auditd-cis-4x)
- [8. Checklist de Verificação e Manutenção Contínua](#8-checklist-de-verificação-e-manutenção-contínua)
- [Referências Oficiais](#referências-oficiais)

---

## 1. Princípios de Defesa em Profundidade e Níveis CIS

A metodologia de **Defesa em Profundidade** pressupõe que nenhuma camada de segurança é infalível de forma isolada. O sistema é estruturado em barreiras concêntricas:

```
[ Usuário / Aplicação ]
        │
        ▼ (Sudo Seguro, PAM, umask 027, Core Dumps desativados)
[ Sistema Operacional ]
        │
        ▼ (Proteção de fs, montagens noexec/nosuid, desativação de fs legados)
[ Rede & Transporte ]
        │
        ▼ (SYN Cookies, rp_filter estrito, ICMP redirects desativados)
[ Kernel & Memória ]
        │
        ▼ (Sysctl Hardening, ASLR 2, Yama ptrace_scope 2, BPF JIT harden)
[ Firmware & Hardware ]
          (UEFI Secure Boot, TPM 2.0 PCRs, IOMMU DMA pt, Kernel Lockdown)
```

### Perfis do CIS Benchmark:
* **Nível 1 (Workstation / Produtividade):** Conjunto prático de configurações que oferece uma postura defensiva rígida sem interromper a usabilidade de estações de trabalho, navegadores, jogos ou ferramentas de desenvolvimento.
* **Nível 2 (Ambientes Críticos / Hardened):** Postura estrita com restrição de depuradores, auditoria integral de chamadas de sistema e isolamento absoluto de memória.

---

## 2. Camada 1: Firmware, Boot e Integridade de Ring-0 (A Base Consolidada)

A fundação de integridade aplica as proteções de forma permanente diretamente sobre o **kernel único padrão do Arch Linux (`linux`)**, sem perfil de duplo boot:

1. **UEFI Secure Boot em Modo Usuário (`SetupMode = 0`):**
   * Garante que apenas binários validados pela sua `Database Key` no banco `db` da UEFI possam ser executados.
   * Assinatura automática de kernels e UKIs nativos do Arch Linux via `sbctl` (sem dependência de repositórios externos).
2. **TPM 2.0 & Measured Boot:**
   * Medição estrita de PCRs (0 a 11) registrando cada transição de firmware, bootloader e initramfs.
3. **Alinhamento ao Host Security ID Level 1 (HSI-1 via `fwupd`):**
   * Valida travas de hardware e firmware: proteção de escrita na SPI Flash da BIOS (`BIOSWE`/`BLE`/`SMM_BWP`), **Intel BootGuard** (ou *AMD Hardware Verified Boot*), `PK` UEFI válida, **TPM 2.0**, **UEFI Secure Boot** ativo e modo de fábrica do ME/CSME travado.
   * Instalação e auditoria com ferramentas nativas do Arch:
     ```bash
     sudo pacman -S fwupd
     fwupdmgr security
     ```
   * Para corrigir eventuais avisos de firmware desatualizado: `fwupdmgr refresh && fwupdmgr update`.
4. **Bloqueio de `kexec`:**
   * Impede a sobreposição de kernels na memória RAM (`kernel.kexec_load_disabled = 1`, aplicado permanentemente via `/etc/sysctl.d/50-security-hardening.conf` na Camada 2).
5. **Isolamento de Barramento IOMMU (`intel_iommu=on iommu=pt`):**
   * Proteção ativa das tabelas DMAR contra ataques de hardware via DMA (*Direct Memory Access*) em portas PCIe ou Thunderbolt/USB4 (em CPUs AMD, use `amd_iommu=on`).
6. **Kernel Lockdown (`lockdown=integrity`):**
   * Isolamento inviolável do Ring-0, bloqueando `/dev/mem`, escrita em MSRs, hibernação e o carregamento de módulos sem assinatura confiável.
   * **Drivers *in-tree* (Intel/AMD):** funcionam nativamente apenas com `sbctl` + UKI.
   * **Módulos DKMS / *out-of-tree* (ex.: NVIDIA, VirtualBox):** no Arch Linux puro, exigem a cadeia **Shim (`shimx64.efi`) + MOK** (chaveiro `.machine`) para que os módulos assinados carreguem sob `lockdown=integrity` — consulte [SHIM-MOK-REFERENCIA.pt-BR.md](SHIM-MOK-REFERENCIA.pt-BR.md).
   * **Aplicação permanente na `cmdline` única (`/etc/cmdline.d/90-security.conf`):**
     ```bash
     cat << 'EOF' | sudo tee /etc/cmdline.d/90-security.conf
     intel_iommu=on iommu=pt lockdown=integrity
     EOF
     sudo mkinitcpio -P
     ```

---

## 3. Camada 2: Hardening de Kernel e Memória via Sysctl (CIS 1.5 & 3.x)

Os parâmetros abaixo configuram proteções em tempo de execução para dificultar a exploração de vulnerabilidades de corrupção de memória e vazamento de ponteiros.

### Configuração: `/etc/sysctl.d/50-security-hardening.conf`

Crie o arquivo com as seguintes diretivas comentadas:

```ini
# ==============================================================================
# Hardening de Kernel e Subsistema de Memória (CIS Benchmark Level 1 & 2)
# ==============================================================================

# 1. Randomização Total do Espaço de Endereçamento (ASLR)
# 2 = Randomização completa de posições de pilha, heap e bibliotecas compartilhadas (CIS 1.5.3)
kernel.randomize_va_space = 2

# 2. Restrição do Buffer de Logs do Kernel (dmesg)
# Impede usuários sem privilégios de inspecionar dmesg e coletar endereços de ponteiros (CIS 1.5.2)
kernel.dmesg_restrict = 1

# 3. Ocultação de Ponteiros de Kernel (/proc/kallsyms)
# 2 = Oculta todos os ponteiros do kernel de todos os usuários (inclusive root), exceto com CAP_SYSLOG
kernel.kptr_restrict = 2

# 4. Escopo do Mecanismo ptrace (LSM Yama)
# 1 = Apenas processos ancestrais imediatos podem anexar (evita injeção de processos alheios)
# 2 = Apenas processos com CAP_SYS_PTRACE (administrador) podem rastrear processos
kernel.yama.ptrace_scope = 2

# 5. Restrição do Compilador JIT do eBPF
# 1 = Desabilita o uso de eBPF por usuários sem privilégios
# 2 = Aplica blindagem contra ataques de Spectre no código compilado JIT
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# 6. Proteção contra Race Conditions no Sistema de Arquivos (Symlinks e Hardlinks)
# Impede a criação de links maliciosos em diretórios públicos como /tmp (CIS 1.5.1)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# 7. Desativação do Magic SysRq para Segurança Local
# Permite apenas o controle mínimo de emergência ou desativa completamente (0 = desativado, 176 = sync/unmount/reboot)
kernel.sysrq = 176

# 8. Desativação de Core Dumps via Kernel
# Evita gravação de senhas ou chaves na memória em caso de falha de processos
fs.suid_dumpable = 0

# 9. Bloqueio Permanente de kexec
# Impede carregamento em RAM de kernels não verificados sem passar pela UEFI
kernel.kexec_load_disabled = 1
```

Aplique imediatamente com:
```bash
sudo sysctl --system
```

---

## 4. Camada 3: Proteção do Sistema de Arquivos e Módulos Obsoletos (CIS 1.1)

### 4.1. Opções de Montagem Restritivas em Partições Temporárias

Diretórios onde qualquer usuário tem permissão de escrita (`/tmp`, `/dev/shm`, `/var/tmp`) devem ter execução de binários e elevação de privilégios revogadas.

#### 1. Montagem Segura do `/tmp` (via systemd `tmp.mount`):
O Arch Linux monta o `/tmp` como `tmpfs` automaticamente. Habilite o serviço nativo com flags restritas:

```bash
sudo cp /usr/share/systemd/tmp.mount /etc/systemd/system/tmp.mount
sudo vim /etc/systemd/system/tmp.mount
```
Certifique-se de que a linha `Options` contenha:
```ini
Options=mode=1777,strictatime,nosuid,nodev,noexec
```
Recarregue e ative:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tmp.mount
```
> [!NOTE]
> `noexec` em `/tmp` pode impedir scripts de build que executam binários a partir de `/tmp` (ex.: `makepkg` se `BUILDDIR=/tmp`). Em estações de desenvolvimento, defina `BUILDDIR` fora de `/tmp` (ex.: em `/etc/makepkg.conf`) ou remova `noexec` se necessário.

#### 2. Montagem Segura de `/dev/shm`:
Adicione ao `/etc/fstab` para restringir a memória compartilhada POSIX:
```text
tmpfs   /dev/shm    tmpfs   defaults,nosuid,nodev,noexec    0   0
```

---

### 4.2. Desativação de Módulos de Sistemas de Arquivos Obsoletos (CIS 1.1.1)

Formatos legados ou exóticos não auditados representam superfície de ataque para injeção via pendrives maliciosos.

Crie `/etc/modprobe.d/blacklist-filesystems.conf`:
```ini
# Desativação de sistemas de arquivos legados ou vulneráveis
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
```

---

## 5. Camada 4: Blindagem da Pilha de Rede TCP/IP (CIS 3.1 & 3.2)

Em estações de trabalho e servidores, o tráfego de rede deve ser estritamente defensivo, descartando pacotes malformados e impedindo técnicas de spoofing e personificação de rota.

### Configuração: `/etc/sysctl.d/60-network-hardening.conf`

```ini
# ==============================================================================
# Hardening da Pilha de Rede TCP/IP (CIS Benchmark 3.1, 3.2 & 3.3)
# ==============================================================================

# 1. Desativação de Roteamento de Pacotes (A estação não atua como roteador)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 2. Proteção contra IP Spoofing (Reverse Path Filtering Estrito - CIS 3.2.7)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 3. Bloqueio de ICMP Redirects (Impede ataques Man-in-the-Middle de rota - CIS 3.2.2)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 4. Bloqueio de Source Routing (Impede o emissor de ditar a rota dos pacotes - CIS 3.2.1)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 5. Mitigação contra Ataques de Negação de Serviço (DoS / SYN Flood - CIS 3.2.8)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# 6. Proteção contra Smurf Attacks e Broadcasts Falsos (CIS 3.2.4 & 3.2.5)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 7. Log de Pacotes Suspeitos com Endereços Impossíveis (Martians - CIS 3.2.3)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 8. Desativação de Router Advertisements IPv6 não solicitados
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
```

> [!NOTE]
> **Impacto em Workstation:**
> - `accept_ra = 0` desativa IPv6 automático via SLAAC; em redes com IPv6 via SLAAC, mantenha `1` ou configure IPv6 estático/DHCPv6.
> - `ip_forward = 0` e `rp_filter = 1` (estrito) bloqueiam roteamento de **Docker/Podman** (*bridge*), **KVM/libvirt** (NAT) e podem afetar VPNs assimétricas (use `rp_filter = 2` se necessário).

### 5.2. Desativação de Protocolos de Rede Pouco Comuns (CIS 3.4)

Crie `/etc/modprobe.d/blacklist-protocols.conf`:
```ini
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
```

---

## 6. Camada 5: Controle de Privilégios, PAM e Sudo Seguro (CIS 5.x)

### 6.1. Configuração do `sudo` Seguro (CIS 5.3)

O `sudo` deve operar isolado em seu próprio terminal virtual e registrar todas as execuções.

Crie o arquivo `/etc/sudoers.d/01-security-hardening` com validação de sintaxe:

```bash
sudo visudo -f /etc/sudoers.d/01-security-hardening
```

Insira as seguintes regras:
```text
# Exige que o sudo rode dentro de um PTY dedicado, prevenindo ataques de hijacking de terminal (CIS 5.3.2)
Defaults use_pty

# Registra todas as execuções em arquivo de log dedicado (CIS 5.3.3)
Defaults logfile="/var/log/sudo.log"

# Define timeout de autenticação em 5 minutos (CIS 5.3.4)
Defaults timestamp_timeout=5

# Limita o número de tentativas de senha incorreta
Defaults passwd_tries=3
```

### 6.2. Desativação de Core Dumps no Espaço do Usuário (CIS 1.5.1)

Core dumps podem conter dados sensíveis (tokens, senhas e fragmentos de chaves privadas em memória).

1. No `/etc/security/limits.d/10-coredump.conf`:
   ```text
   * hard core 0
   * soft core 0
   ```
2. No `/etc/systemd/coredump.conf`:
   ```ini
   [Coredump]
   Storage=none
   ProcessSizeMax=0
   ```

---

## 7. Camada 6: Auditoria de Eventos e Rastreamento com `auditd` (CIS 4.x)

O daemon de auditoria do Linux (`auditd`) monitora e gera registros à prova de adulteração sobre chamadas de sistema, execução de privilégios e alterações de autorização.

### 1. Instalação e Habilitação do Serviço:
```bash
sudo pacman -S audit
sudo systemctl enable --now auditd
```

### 2. Regras Essenciais de Auditoria (`/etc/audit/rules.d/50-security.rules`):

```ini
# Remove regras anteriores
-D

# Define o tamanho do buffer de eventos
-b 8192

# Falha silenciosa em caso de sobrecarga (evita travar o boot)
-f 1

# Monitorar alterações no relógio do sistema (CIS 4.1.3)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change

# Monitorar modificações em usuários e grupos (CIS 4.1.4)
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitorar alterações de configuração de rede (CIS 4.1.5)
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system_locale
-w /etc/issue -p wa -k system_locale
-w /etc/hosts -p wa -k system_locale

# Monitorar regras do Sudoers (CIS 4.1.10)
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Tornar as regras imutáveis até o próximo reboot (CIS 4.1.17)
-e 2
```

Recarregue as regras:
```bash
sudo augenrules --load
```

---

## 8. Checklist de Verificação e Manutenção Contínua

Execute estes comandos rápidos para auditar o status das defesas aplicadas:

| Componente | Comando de Verificação | Saída Esperada |
| :--- | :--- | :--- |
| **Secure Boot** | `sbctl status` | `Secure Boot: ✓ Enabled` |
| **Host Security ID** | `fwupdmgr security` | `HSI:1` (ou superior), BootGuard/TPM ativos |
| **Kernel Lockdown** | `cat /sys/kernel/security/lockdown` | `none [integrity] confidentiality` |
| **kexec Bloqueado** | `cat /proc/sys/kernel/kexec_load_disabled` | `1` |
| **ASLR** | `sysctl kernel.randomize_va_space` | `kernel.randomize_va_space = 2` |
| **Yama ptrace** | `sysctl kernel.yama.ptrace_scope` | `kernel.yama.ptrace_scope = 2` |
| **Reverse Path** | `sysctl net.ipv4.conf.all.rp_filter` | `net.ipv4.conf.all.rp_filter = 1` |
| **SYN Cookies** | `sysctl net.ipv4.tcp_syncookies` | `net.ipv4.tcp_syncookies = 1` |
| **Auditd** | `auditctl -s` | `enabled 2, pid ...` |
| **Core Dumps** | `ulimit -c` | `0` |

---

## Referências Oficiais

* [CIS Center for Internet Security: Distribution-Independent Linux Benchmark](https://www.cisecurity.org/benchmark/distribution_independent_linux)
* [ArchWiki: Security Hardening](https://wiki.archlinux.org/title/Security)
* [ArchWiki: Sysctl Hardening](https://wiki.archlinux.org/title/Sysctl#Security)
* [Kernel.org: Admin Guide - Linux Security Hardening](https://docs.kernel.org/admin-guide/index.html)
* [Kernel.org: Yama LSM Documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
