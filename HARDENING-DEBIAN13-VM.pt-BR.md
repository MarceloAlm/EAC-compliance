# Guia de Hardening Debian 13 (Trixie) para Máquinas Virtuais: CIS Benchmark & Defesa em Profundidade

[![Debian](https://img.shields.io/badge/Debian%2013-Trixie%20(Testing%2FStable)-d70a53?logo=debian&logoColor=white)](https://www.debian.org/)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-Debian%20Level%201%20Server-success)](https://www.cisecurity.org/cis-benchmarks/)
[![Virtualization](https://img.shields.io/badge/Virtualization-KVM%20%7C%20Proxmox%20%7C%20VMware-blue)](https://wiki.debian.org/KVM)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> Read this guide in English: **[English](HARDENING-DEBIAN13-VM.md)**  
> Este guia é dedicado a servidores e estações virtualizadas executando **Debian 13 (Trixie)** sobre hypervisors modernos (KVM/QEMU, Proxmox VE, VMware ESXi, Hyper-V e VirtualBox). Para o guia focado em bare-metal Arch Linux, consulte **[HARDENING.pt-BR.md](HARDENING.pt-BR.md)**.

Este documento estabelece o padrão de segurança operacional e endurecimento defensivo (*hardening*) para instâncias virtuais rodando **Debian 13**. O modelo adota os controles estritos do **CIS Debian Linux Benchmark** (Nível 1 - Server) e introduz salvaguardas específicas para o ecossistema virtualizado, minimizando a superfície de ataque e garantindo o isolamento entre o convidado (*guest*) e o hospedeiro (*hypervisor*).

---

## Índice

- [1. Princípios de Segurança em Ambientes Virtualizados](#1-princípios-de-segurança-em-ambientes-virtualizados)
- [2. Camada 1: Hardware Virtual e Firmware (OVMF & Hypervisor)](#2-camada-1-hardware-virtual-e-firmware-ovmf--hypervisor)
- [3. Camada 2: Kernel, Memória e Sysctl no Debian 13 (CIS 1.5 & 3.x)](#3-camada-2-kernel-memória-e-sysctl-no-debian-13-cis-15--3x)
- [4. Camada 3: Particionamento e Sistema de Arquivos em VMs (CIS 1.1)](#4-camada-3-particionamento-e-sistema-de-arquivos-em-vms-cis-11)
- [5. Camada 4: Blindagem da Pilha de Rede TCP/IP e Firewall com `nftables`](#5-camada-4-blindagem-da-pilha-de-rede-tcpip-e-firewall-com-nftables)
- [6. Camada 5: Hardening do Servidor OpenSSH e Controle de Privilégios (CIS 5.x)](#6-camada-5-hardening-do-servidor-openssh-e-controle-de-privilégios-cis-5x)
- [7. Camada 6: Mandatory Access Control com AppArmor (O Padrão Debian)](#7-camada-6-mandatory-access-control-com-apparmor-o-padrão-debian)
- [8. Camada 7: Auditoria Contínua com `auditd` e Atualizações Automáticas](#8-camada-7-auditoria-contínua-com-auditd-e-atualizações-automáticas)
- [9. Checklist de Auditoria e Conformidade para a VM](#9-checklist-de-auditoria-e-conformidade-para-a-vm)
- [Referências Oficiais](#referências-oficiais)

---

## 1. Princípios de Segurança em Ambientes Virtualizados

Uma Máquina Virtual (VM) possui uma dinâmica de ameaça distinta de um computador físico:
1. **Compartilhamento de Recursos Físicos:** Ataques de canal lateral (ex.: *Spectre*, *Meltdown*, *L1TF*) podem tentar vazar dados entre VMs vizinhas ou para o hypervisor.
2. **Interfaces Paravirtualizadas:** Dispositivos `virtio` oferecem alta performance, mas exigem que barramentos virtuais não utilizados sejam eliminados.
3. **Agentes de Convidado (*Guest Agents*):** Ferramentas como o `qemu-guest-agent` permitem ao hypervisor executar comandos como `root` no convidado se não forem devidamente restringidas.
4. **Ausência de Periféricos Físicos Supérfluos:** Uma VM não necessita de Bluetooth, som, interfaces Wi-Fi ou leitor de disquetes. Toda redução na emulação é uma vitória defensiva.

---

## 2. Camada 1: Hardware Virtual e Firmware (OVMF & Hypervisor)

Antes de instalar ou configurar o Debian 13, configure as opções da máquina virtual no hypervisor:

### 2.1. Configuração Recomendada no Hypervisor (Proxmox / KVM / QEMU)
* **BIOS / Firmware:** Selecione **OVMF (UEFI)** em vez de SeaBIOS legada.
* **Secure Boot:** Ative o suporte a Secure Boot com chaves pré-matriculadas (Debian assina nativamente seu kernel e GRUB via certificado Microsoft UEFI CA).
* **vTPM (TPM 2.0 Virtual):** Ative a emulação de TPM 2.0 (via `swtpm` no Proxmox/KVM ou vTPM no ESXi).
* **Remoção de Dispositivos Inúteis:**
  * Remova controladoras de áudio (*Audio Device*).
  * Desative portas seriais/paralelas desnecessárias.
  * Remova controladoras de disquete (*Floppy*).
  * Use barramento **VirtIO SCSI** ou **VirtIO Block** para discos e **VirtIO Network** com multiqueue.

### 2.2. Hardening do Agente do Hypervisor (`qemu-guest-agent`)

Se você usa KVM/Proxmox, o `qemu-guest-agent` é essencial para sincronização de clock, snapshots consistentes de disco e visualização de IPs. Porém, por padrão, o hypervisor pode injetar comandos arbitrários no convidado via `guest-exec`.

1. **Instalação do Agente:**
   ```bash
   sudo apt update
   sudo apt install -y qemu-guest-agent
   ```
2. **Restringir Execução de Comandos Arbitrários via Hypervisor:**
   Edite o `/etc/default/qemu-guest-agent` para desabilitar comandos de execução externa remota (`guest-exec` e `guest-file-write`):
   ```ini
   DAEMON_ARGS="--blacklist=guest-exec,guest-exec-status"
   ```
   Reinicie o serviço:
   ```bash
   sudo systemctl restart qemu-guest-agent
   ```

---

## 3. Camada 2: Kernel, Memória e Sysctl no Debian 13 (CIS 1.5 & 3.x)

Crie o arquivo `/etc/sysctl.d/50-security-hardening.conf` para aplicar o baseline de memória do CIS Benchmark no Debian 13:

```ini
# ==============================================================================
# Hardening de Kernel, Memória e Processos - Debian 13 (CIS Level 1 Server)
# ==============================================================================

# 1. Randomização Total do Espaço de Endereçamento (ASLR - CIS 1.5.3)
kernel.randomize_va_space = 2

# 2. Restrição do Buffer de Logs do Kernel (dmesg - CIS 1.5.2)
kernel.dmesg_restrict = 1

# 3. Ocultação de Ponteiros de Kernel (/proc/kallsyms)
kernel.kptr_restrict = 2

# 4. Restrição de Process Tracing (LSM Yama - CIS 1.5.4)
# Permite anexar ptrace apenas com CAP_SYS_PTRACE (root)
kernel.yama.ptrace_scope = 2

# 5. Restrição de eBPF sem privilégios e JIT Hardening
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# 6. Proteção contra Symlinks/Hardlinks em Diretórios Públicos (CIS 1.5.1)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# 7. Desativação de Core Dumps no Kernel
fs.suid_dumpable = 0

# 8. Desativação do Magic SysRq (ou restrito a sincronização/reboot de emergência)
kernel.sysrq = 176

# 9. Otimização de Memória e Troca para VMs (Swappiness)
# Em VMs, evitar paginação agressiva melhora a segurança e estabilidade do host
vm.swappiness = 10
```

Aplique as regras imediatamente:
```bash
sudo sysctl --system
```

---

## 4. Camada 3: Particionamento e Sistema de Arquivos em VMs (CIS 1.1)

O CIS Benchmark recomenda particionamento dedicado para isolar diretórios temporários e de logs, prevenindo ataques de esgotamento de disco (*DoS*) e elevação de privilégios.

### 4.1. Esquema de Montagens Seguras em `/etc/fstab`

Em uma VM particionada com LVM ou subvolumes dedicados, aplique as flags restritivas:

```text
# Montagem do /tmp em memória volátil com execução bloqueada (CIS 1.1.2 - 1.1.5)
tmpfs   /tmp        tmpfs   defaults,nosuid,nodev,noexec,mode=1777  0   0

# Montagem de memória compartilhada POSIX (CIS 1.1.6 - 1.1.8)
tmpfs   /dev/shm    tmpfs   defaults,nosuid,nodev,noexec            0   0

# Partições de Logs e Auditoria (se criadas separadamente)
# /var/log          ext4    defaults,nosuid,nodev,noexec            0   2
# /var/log/audit    ext4    defaults,nosuid,nodev,noexec            0   2
```

Se o seu Debian 13 utiliza o serviço nativo do systemd para gerenciar o `/tmp`:
```bash
sudo systemctl enable --now tmp.mount
```

### 4.2. Desativação de Módulos de Sistemas de Arquivos Obsoletos (CIS 1.1.1)

Como a VM se comunica estritamente via rede e discos virtuais, nenhum formato de arquivo arcaico deve estar disponível para montagem.

Crie `/etc/modprobe.d/blacklist-filesystems.conf`:
```ini
# CIS Benchmark 1.1.1 - Desativação de drivers de sistemas de arquivos não utilizados
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
```

---

## 5. Camada 4: Blindagem da Pilha de Rede TCP/IP e Firewall com `nftables`

Em ambientes virtualizados, pacotes frequentemente transitam por pontes (*bridges*) virtuais compartilhadas. O tráfego precisa ser estritamente filtrado.

### 5.1. Hardening de Rede via Sysctl: `/etc/sysctl.d/60-network-hardening.conf`

```ini
# ==============================================================================
# Hardening de Rede para VM Debian 13 (CIS 3.1 & 3.2)
# ==============================================================================

# 1. Desativação de Roteamento de Pacotes (A VM não é gateway)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 2. Reverse Path Filtering Estrito (Anti-Spoofing em Redes Virtuais - CIS 3.2.7)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 3. Bloqueio Total de ICMP Redirects (CIS 3.2.2)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 4. Bloqueio de Source Routing (CIS 3.2.1)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 5. Mitigação de SYN Flood (CIS 3.2.8)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# 6. Ignorar Mensagens ICMP Broadcast e Erros Forjados (CIS 3.2.4 & 3.2.5)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 7. Log de Pacotes com Roteamento Impossível (Martians - CIS 3.2.3)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 8. Ignorar Router Advertisements IPv6 não solicitados
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
```

### 5.2. Firewall Nativo com `nftables` (Padrão Oficial do Debian)

O Debian substituiu integralmente o `iptables` legado pelo **`nftables`**. Configure uma política padrão de descarte (*default drop*):

1. **Instalar e Ativar o Serviço:**
   ```bash
   sudo apt install -y nftables
   sudo systemctl enable --now nftables
   ```
2. **Definir as Regras em `/etc/nftables.conf`:**
   ```text
   #!/usr/sbin/nft -f

   flush ruleset

   table inet filter {
       chain input {
           type filter hook input priority filter; policy drop;

           # Aceita tráfego da interface local (loopback)
           iif "lo" accept

           # Aceita conexões já estabelecidas e relacionadas
           ct state established,related accept

           # Descarta pacotes em estado inválido
           ct state invalid drop

           # Aceita ICMP (Ping) com limite de taxa (rate limiting)
           ip protocol icmp icmp type echo-request limit rate 5/second accept
           ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 5/second accept

           # Acesso SSH Seguro (ajuste a porta se usar porta customizada)
           tcp dport 22 ct state new limit rate 10/minute accept

           # Adicione aqui portas de serviços da VM (ex.: 80, 443 para web)
           # tcp dport { 80, 443 } ct state new accept
       }

       chain forward {
           type filter hook forward priority filter; policy drop;
       }

       chain output {
           type filter hook output priority filter; policy accept;
       }
   }
   ```
3. **Aplicar e Validar:**
   ```bash
   sudo nft -f /etc/nftables.conf
   sudo systemctl restart nftables
   sudo nft list ruleset
   ```

---

## 6. Camada 5: Hardening do Servidor OpenSSH e Controle de Privilégios (CIS 5.x)

Para uma VM gerenciada remotamente, o **OpenSSH** é a porta de entrada principal e exige proteção intransigente.

### 6.1. Configuração do SSH: `/etc/ssh/sshd_config.d/01-hardening.conf`

No Debian 13, utilize o diretório modular de configuração do SSH:

```ini
# ==============================================================================
# Hardening do Servidor OpenSSH - Debian 13 (CIS Benchmark 5.2)
# ==============================================================================

# 1. Proibir Login Direto como Root (CIS 5.2.8)
PermitRootLogin no

# 2. Desabilitar Autenticação por Senha (Exigir Chaves Criptográficas - CIS 5.2.9)
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no

# 3. Forçar Autenticação por Chave Pública
PubkeyAuthentication yes

# 4. Limitar Tentativas de Autenticação por Conexão (CIS 5.2.5)
MaxAuthTries 3

# 5. Criptografia Moderna (Apenas Ciphers e KEX Seguros - CIS 5.2.11)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# 6. Desativar Encaminhamentos Inseguros (CIS 5.2.6)
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no

# 7. Timeouts de Sessão Inativa (CIS 5.2.13)
# Desconecta após 10 minutos de inatividade (300s x 2)
ClientAliveInterval 300
ClientAliveCountMax 2

# 8. Isolamento de Privilégios e Logs Detalhados (CIS 5.2.3)
LogLevel VERBOSE
```

Valide e recarregue o SSH com segurança:
```bash
sudo sshd -t
sudo systemctl reload ssh
```

---

### 6.2. Configuração do `sudo` Seguro (CIS 5.3)

Crie `/etc/sudoers.d/01-security-hardening`:

```bash
sudo visudo -f /etc/sudoers.d/01-security-hardening
```

Adicione as regras:
```text
# Exige PTY dedicado para prevenir hijacking de terminal (CIS 5.3.2)
Defaults use_pty

# Registro em log dedicado (CIS 5.3.3)
Defaults logfile="/var/log/sudo.log"

# Timeout de expiração de credenciais em 5 minutos (CIS 5.3.4)
Defaults timestamp_timeout=5

# Limite de tentativas de senha incorreta
Defaults passwd_tries=3
```

---

## 7. Camada 6: Mandatory Access Control com AppArmor (O Padrão Debian)

Ao contrário de distribuições que deixam o LSM a critério do usuário, o **Debian instala e ativa o AppArmor nativamente**. O objetivo do hardening no Debian 13 é garantir que os perfis estejam em modo estrito de imposição (*enforcing*).

### 1. Verificar o Status do AppArmor:
```bash
sudo aa-status
```
*Certifique-se de que o AppArmor está carregado e que os perfis padrão estão em `enforce mode`.*

### 2. Instalar Perfis Adicionais e Utilitários:
```bash
sudo apt install -y apparmor-profiles apparmor-utils
```

### 3. Colocar Perfis em Modo Enforce:
Se algum perfil estiver em modo reclamante (*complain*), coloque-o em imposição:
```bash
sudo aa-enforce /etc/apparmor.d/*
```

---

## 8. Camada 7: Auditoria Contínua com `auditd` e Atualizações Automáticas

### 8.1. Auditoria do Sistema com `auditd` (CIS 4.x)

1. **Instalação:**
   ```bash
   sudo apt install -y auditd
   sudo systemctl enable --now auditd
   ```
2. **Regras de Auditoria para Debian (`/etc/audit/rules.d/50-security.rules`):**
   ```ini
   # Remove regras anteriores
   -D
   -b 8192
   -f 1

   # Monitorar alterações em contas, grupos e senhas (CIS 4.1.4)
   -w /etc/group -p wa -k identity
   -w /etc/passwd -p wa -k identity
   -w /etc/gshadow -p wa -k identity
   -w /etc/shadow -p wa -k identity
   -w /etc/security/opasswd -p wa -k identity

   # Monitorar configurações de rede (CIS 4.1.5)
   -a always,exit -F arch=b64 -S sethostname,setdomainname -k system_locale
   -w /etc/issue -p wa -k system_locale
   -w /etc/hosts -p wa -k system_locale

   # Monitorar sudo e privilégios (CIS 4.1.10)
   -w /etc/sudoers -p wa -k scope
   -w /etc/sudoers.d/ -p wa -k scope

   # Monitorar chamadas de montagem de arquivos (CIS 4.1.13)
   -a always,exit -F arch=b64 -S mount,umount2 -k mounts

   # Tornar as regras imutáveis até o próximo reboot (CIS 4.1.17)
   -e 2
   ```
3. **Aplicar as Regras:**
   ```bash
   sudo augenrules --load
   sudo auditctl -s
   ```

---

### 8.2. Atualizações de Segurança Automáticas com `unattended-upgrades`

Uma VM exposta precisa de correções de segurança imediatas sem depender de intervenções manuais.

1. **Instalação:**
   ```bash
   sudo apt install -y unattended-upgrades apt-listchanges
   ```
2. **Ativar o Serviço:**
   ```bash
   sudo dpkg-reconfigure -plow unattended-upgrades
   ```
3. **Garantir Atualizações Estritas de Segurança em `/etc/apt/apt.conf.d/50unattended-upgrades`:**
   Certifique-se de que a origem de segurança do Debian 13 (Trixie) está habilitada:
   ```text
   Unattended-Upgrade::Origins-Pattern {
       "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
   };
   Unattended-Upgrade::AutoFixInterruptedDpkg "true";
   Unattended-Upgrade::MinimalSteps "true";
   Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
   Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
   ```

---

### 8.3. Verificação de Integridade de Pacotes com `debsums`

O Debian possui uma ferramenta nativa excepcional para verificar se arquivos do sistema foram alterados ou corrompidos em relação aos pacotes originais dos repositórios:

```bash
sudo apt install -y debsums

# Verifica apenas arquivos alterados ou corrompidos (omitindo arquivos de configuração esperados):
sudo debsums -c
```

---

## 9. Checklist de Auditoria e Conformidade para a VM

Execute estes comandos rápidos na VM Debian 13 para validar o cumprimento dos controles:

| Controle CIS | Comando de Auditoria | Resultado Esperado |
| :--- | :--- | :--- |
| **AppArmor** | `aa-status` | `apparmor module is loaded; ... profiles in enforce mode` |
| **Firewall** | `nft list ruleset` | `chain input { type filter ... policy drop; }` |
| **SSH Root** | `sshd -T \| grep permitrootlogin` | `permitrootlogin no` |
| **SSH Senhas** | `sshd -T \| grep passwordauthentication` | `passwordauthentication no` |
| **ASLR** | `sysctl kernel.randomize_va_space` | `kernel.randomize_va_space = 2` |
| **Yama ptrace** | `sysctl kernel.yama.ptrace_scope` | `kernel.yama.ptrace_scope = 2` |
| **Auditd** | `auditctl -s` | `enabled 2` (imutável) |
| **Reverse Path** | `sysctl net.ipv4.conf.all.rp_filter` | `net.ipv4.conf.all.rp_filter = 1` |
| **SYN Cookies** | `sysctl net.ipv4.tcp_syncookies` | `net.ipv4.tcp_syncookies = 1` |
| **Integridade** | `debsums -c` | Sem saídas (zero arquivos corrompidos/adulterados) |

---

## Referências Oficiais

* [CIS Center for Internet Security: Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux)
* [Debian Wiki: Securing Debian Manual](https://www.debian.org/doc/manuals/securing-debian-manual/)
* [Debian Wiki: AppArmor](https://wiki.debian.org/AppArmor)
* [Debian Wiki: nftables](https://wiki.debian.org/nftables)
* [Debian Wiki: UnattendedUpgrades](https://wiki.debian.org/UnattendedUpgrades)
* [QEMU Documentation: Guest Agent Security Considerations](https://www.qemu.org/docs/master/interop/qemu-ga.html)
