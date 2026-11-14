# Blueprint de Segurança e Hardening CIS para Ansible: Debian 13 em Máquinas Virtuais

[![Ansible](https://img.shields.io/badge/Ansible-Ready-EE0000?logo=ansible&logoColor=white)](https://www.ansible.com/)
[![Debian](https://img.shields.io/badge/Debian%2013-Trixie-d70a53?logo=debian&logoColor=white)](https://www.debian.org/)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-Level%201%20Server-success)](https://www.cisecurity.org/cis-benchmarks/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Documento de Especificação Técnica e Arquitetura de Automação**  
> Este arquivo foi estruturado para servir de especificação de engenharia direta para a criação de **Playbooks e Roles do Ansible**, automatizando o provisionamento e o endurecimento defensivo de Máquinas Virtuais Debian 13 em conformidade com o **CIS Benchmark Level 1 Server**.

---

## Índice

- [1. Visão Geral da Arquitetura e Matriz de Roles Ansible](#1-visão-geral-da-arquitetura-e-matriz-de-roles-ansible)
- [2. Role 1: `vm_firmware_agent` (Hypervisor & QEMU Guest Agent)](#2-role-1-vm_firmware_agent-hypervisor--qemu-guest-agent)
- [3. Role 2: `kernel_sysctl` (Memória, ASLR, Yama e Processos)](#3-role-2-kernel_sysctl-memória-aslr-yama-e-processos)
- [4. Role 3: `filesystem_security` (Montagens e Blacklist de Drivers)](#4-role-3-filesystem_security-montagens-e-blacklist-de-drivers)
- [5. Role 4: `network_hardening` (Stack TCP/IP e Anti-Spoofing)](#5-role-4-network_hardening-stack-tcpip-e-anti-spoofing)
- [6. Role 5: `nftables_firewall` (Filtragem Nativa de Pacotes)](#6-role-5-nftables_firewall-filtragem-nativa-de-pacotes)
- [7. Role 6: `openssh_server` (Acesso Remoto Seguro e Criptografia)](#7-role-6-openssh_server-acesso-remoto-seguro-e-criptografia)
- [8. Role 7: `access_privilege` (Sudo Seguro, PAM e Core Dumps)](#8-role-7-access_privilege-sudo-seguro-pam-e-core-dumps)
- [9. Role 8: `apparmor_enforce` (Mandatory Access Control)](#9-role-8-apparmor_enforce-mandatory-access-control)
- [10. Role 9: `auditd_logging` (Auditoria Contínua Imutável)](#10-role-9-auditd_logging-auditoria-contínua-imutável)
- [11. Role 10: `auto_updates_integrity` (Unattended Upgrades & Debsums)](#11-role-10-auto_updates_integrity-unattended-upgrades--debsums)
- [12. Playbook Integrador e Tarefas de Validação (`verify.yml`)](#12-playbook-integrador-e-tarefas-de-validação-verifyyml)

---

## 1. Visão Geral da Arquitetura e Matriz de Roles Ansible

A automação deve ser dividida em roles independentes, idempotentes e orientadas a handlers.

```
site.yml
├── roles/
│   ├── vm_firmware_agent/       # Restrições de QEMU Guest Agent
│   ├── kernel_sysctl/           # Sysctl de memória, ASLR, Yama, eBPF
│   ├── filesystem_security/     # Montagens fstab, tmpfs, blacklist fs
│   ├── network_hardening/       # Sysctl de rede, rp_filter, ICMP
│   ├── nftables_firewall/       # Firewall padrão drop, rate limiting
│   ├── openssh_server/          # sshd_config.d, chaves públicas, ciphers
│   ├── access_privilege/        # Sudo use_pty, limits coredump
│   ├── apparmor_enforce/        # Perfis do AppArmor em enforce
│   ├── auditd_logging/          # Regras CIS auditd imutáveis
│   └── auto_updates_integrity/  # Unattended-upgrades e debsums
```

---

## 2. Role 1: `vm_firmware_agent` (Hypervisor & QEMU Guest Agent)

### Objetivo
Garantir o isolamento entre convidado e hypervisor, desabilitando o vetor de injeção de comandos arbitrários no agente de virtualização.

### Variáveis (`defaults/main.yml`)
```yaml
vm_agent_package: "qemu-guest-agent"
vm_agent_blacklist_commands:
  - "guest-exec"
  - "guest-exec-status"
```

### Tarefas (`tasks/main.yml`)
```yaml
- name: Instalar o pacote do agente do hypervisor
  ansible.builtin.apt:
    name: "{{ vm_agent_package }}"
    state: present
    update_cache: yes

- name: Restringir execuções remotas arbitrárias via QEMU Guest Agent
  ansible.builtin.lineinfile:
    path: /etc/default/qemu-guest-agent
    regexp: '^DAEMON_ARGS='
    line: 'DAEMON_ARGS="--blacklist={{ vm_agent_blacklist_commands | join(",") }}"'
    create: yes
    mode: '0644'
  notify: Reiniciar QEMU Guest Agent
```

### Handlers (`handlers/main.yml`)
```yaml
- name: Reiniciar QEMU Guest Agent
  ansible.builtin.systemd:
    name: qemu-guest-agent
    state: restarted
```

---

## 3. Role 2: `kernel_sysctl` (Memória, ASLR, Yama e Processos)

### Objetivo
Aplicar parâmetros de memória em tempo de execução para mitigar ataques de corrupção de memória e exploração de ponteiros (CIS 1.5).

### Variáveis (`defaults/main.yml`)
```yaml
kernel_sysctl_settings:
  kernel.randomize_va_space: 2
  kernel.dmesg_restrict: 1
  kernel.kptr_restrict: 2
  kernel.yama.ptrace_scope: 2
  kernel.unprivileged_bpf_disabled: 1
  net.core.bpf_jit_harden: 2
  fs.protected_symlinks: 1
  fs.protected_hardlinks: 1
  fs.protected_fifos: 2
  fs.protected_regular: 2
  fs.suid_dumpable: 0
  kernel.sysrq: 176
  vm.swappiness: 10
```

### Tarefas (`tasks/main.yml`)
```yaml
- name: Implantar configuração de sysctl de hardening
  ansible.builtin.template:
    src: 50-security-hardening.conf.j2
    dest: /etc/sysctl.d/50-security-hardening.conf
    owner: root
    group: root
    mode: '0644'
  notify: Aplicar Sysctl
```

### Template (`templates/50-security-hardening.conf.j2`)
```ini
# Gerado via Ansible - CIS Benchmark Level 1
{% for key, value in kernel_sysctl_settings.items() %}
{{ key }} = {{ value }}
{% endfor %}
```

### Handlers (`handlers/main.yml`)
```yaml
- name: Aplicar Sysctl
  ansible.builtin.command:
    cmd: sysctl --system
  changed_when: true
```

---

## 4. Role 3: `filesystem_security` (Montagens e Blacklist de Drivers)

### Objetivo
Impedir a execução de binários não autorizados em áreas públicas e desabilitar drivers de sistemas de arquivos legados (CIS 1.1).

### Tarefas (`tasks/main.yml`)
```yaml
- name: Desabilitar drivers de sistemas de arquivos legados e obsoletos
  ansible.builtin.copy:
    dest: /etc/modprobe.d/blacklist-filesystems.conf
    content: |
      # CIS Benchmark 1.1.1
      install cramfs /bin/true
      install freevxfs /bin/true
      install jffs2 /bin/true
      install hfs /bin/true
      install hfsplus /bin/true
      install squashfs /bin/true
      install udf /bin/true
    owner: root
    group: root
    mode: '0644'

- name: Garantir opções seguras de montagem para /dev/shm no fstab
  ansible.posix.mount:
    path: /dev/shm
    src: tmpfs
    fstype: tmpfs
    opts: "defaults,nosuid,nodev,noexec"
    state: present

- name: Habilitar unidade tmp.mount do systemd para o /tmp seguro
  ansible.builtin.systemd:
    name: tmp.mount
    enabled: yes
    state: started
```

---

## 5. Role 4: `network_hardening` (Stack TCP/IP e Anti-Spoofing)

### Objetivo
Descartar pacotes forjados, bloquear ICMP redirects e proteger a VM contra DoS e spoofing em redes virtuais (CIS 3.1 & 3.2).

### Variáveis (`defaults/main.yml`)
```yaml
network_sysctl_settings:
  net.ipv4.ip_forward: 0
  net.ipv6.conf.all.forwarding: 0
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.conf.default.rp_filter: 1
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.conf.default.accept_redirects: 0
  net.ipv4.conf.all.secure_redirects: 0
  net.ipv4.conf.default.secure_redirects: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.default.send_redirects: 0
  net.ipv6.conf.all.accept_redirects: 0
  net.ipv6.conf.default.accept_redirects: 0
  net.ipv4.conf.all.accept_source_route: 0
  net.ipv4.conf.default.accept_source_route: 0
  net.ipv6.conf.all.accept_source_route: 0
  net.ipv6.conf.default.accept_source_route: 0
  net.ipv4.tcp_syncookies: 1
  net.ipv4.tcp_rfc1337: 1
  net.ipv4.icmp_echo_ignore_broadcasts: 1
  net.ipv4.icmp_ignore_bogus_error_responses: 1
  net.ipv4.conf.all.log_martians: 1
  net.ipv4.conf.default.log_martians: 1
  net.ipv6.conf.all.accept_ra: 0
  net.ipv6.conf.default.accept_ra: 0
```

### Tarefas (`tasks/main.yml`)
```yaml
- name: Implantar sysctl de hardening de rede TCP/IP
  ansible.builtin.template:
    src: 60-network-hardening.conf.j2
    dest: /etc/sysctl.d/60-network-hardening.conf
    owner: root
    group: root
    mode: '0644'
  notify: Aplicar Sysctl

- name: Desabilitar protocolos de rede obsoletos
  ansible.builtin.copy:
    dest: /etc/modprobe.d/blacklist-protocols.conf
    content: |
      # CIS Benchmark 3.4
      install dccp /bin/true
      install sctp /bin/true
      install rds /bin/true
      install tipc /bin/true
    owner: root
    group: root
    mode: '0644'
```

---

## 6. Role 5: `nftables_firewall` (Filtragem Nativa de Pacotes)

### Objetivo
Impor uma política restritiva de descarte (*default drop*) em nível de kernel utilizando o framework nativo do Debian.

### Variáveis (`defaults/main.yml`)
```yaml
firewall_allowed_tcp_ports:
  - 22
firewall_rate_limit_ssh: "10/minute"
firewall_rate_limit_icmp: "5/second"
```

### Template (`templates/nftables.conf.j2`)
```text
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        iif "lo" accept
        ct state established,related accept
        ct state invalid drop

        ip protocol icmp icmp type echo-request limit rate {{ firewall_rate_limit_icmp }} accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate {{ firewall_rate_limit_icmp }} accept

        {% for port in firewall_allowed_tcp_ports %}
        tcp dport {{ port }} ct state new limit rate {{ firewall_rate_limit_ssh }} accept
        {% endfor %}
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```

### Tarefas (`tasks/main.yml`)
```yaml
- name: Instalar nftables
  ansible.builtin.apt:
    name: nftables
    state: present

- name: Implantar configuração de firewall nftables
  ansible.builtin.template:
    src: nftables.conf.j2
    dest: /etc/nftables.conf
    owner: root
    group: root
    mode: '0755'
  notify: Recarregar Nftables

- name: Habilitar e iniciar serviço nftables
  ansible.builtin.systemd:
    name: nftables
    enabled: yes
    state: started
```

### Handlers (`handlers/main.yml`)
```yaml
- name: Recarregar Nftables
  ansible.builtin.systemd:
    name: nftables
    state: reloaded
```

---

## 7. Role 6: `openssh_server` (Acesso Remoto Seguro e Criptografia)

### Objetivo
Desativar senhas em texto puro, proibir login de root e limitar tentativas de conexão remota (CIS 5.2).

### Variáveis (`defaults/main.yml`)
```yaml
sshd_permit_root_login: "no"
sshd_password_authentication: "no"
sshd_pubkey_authentication: "yes"
sshd_max_auth_tries: 3
sshd_client_alive_interval: 300
sshd_client_alive_count_max: 2
sshd_ciphers: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
sshd_kex_algorithms: "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512"
sshd_macs: "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
```

### Tarefas (`tasks/main.yml`)
```yaml
- name: Configurar arquivo modular de hardening do OpenSSH
  ansible.builtin.template:
    src: 01-hardening.conf.j2
    dest: /etc/ssh/sshd_config.d/01-hardening.conf
    owner: root
    group: root
    mode: '0600'
    validate: '/usr/sbin/sshd -t -f %s'
  notify: Recarregar SSH
```

### Template (`templates/01-hardening.conf.j2`)
```ini
# CIS Benchmark 5.2 - Gerado via Ansible
PermitRootLogin {{ sshd_permit_root_login }}
PasswordAuthentication {{ sshd_password_authentication }}
PermitEmptyPasswords no
KbdInteractiveAuthentication no
PubkeyAuthentication {{ sshd_pubkey_authentication }}
MaxAuthTries {{ sshd_max_auth_tries }}
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval {{ sshd_client_alive_interval }}
ClientAliveCountMax {{ sshd_client_alive_count_max }}
LogLevel VERBOSE
Ciphers {{ sshd_ciphers }}
KexAlgorithms {{ sshd_kex_algorithms }}
MACs {{ sshd_macs }}
```

### Handlers (`handlers/main.yml`)
```yaml
- name: Recarregar SSH
  ansible.builtin.systemd:
    name: ssh
    state: reloaded
```

---

## 8. Role 7: `access_privilege` (Sudo Seguro, PAM e Core Dumps)

### Objetivo
Isolar o terminal do `sudo`, registrar execuções administrativas e impedir despejo de memória sensível (CIS 5.3 & 1.5).

### Tarefas (`tasks/main.yml`)
```yaml
- name: Configurar regras restritivas do Sudo
  ansible.builtin.copy:
    dest: /etc/sudoers.d/01-security-hardening
    content: |
      # CIS Benchmark 5.3
      Defaults use_pty
      Defaults logfile="/var/log/sudo.log"
      Defaults timestamp_timeout=5
      Defaults passwd_tries=3
    owner: root
    group: root
    mode: '0440'
    validate: '/usr/sbin/visudo -cf %s'

- name: Desabilitar core dumps em limits.conf
  ansible.builtin.copy:
    dest: /etc/security/limits.d/10-coredump.conf
    content: |
      # CIS Benchmark 1.5.1
      * hard core 0
      * soft core 0
    owner: root
    group: root
    mode: '0644'

- name: Desabilitar armazenamento de core dumps no systemd
  ansible.builtin.ini_file:
    path: /etc/systemd/coredump.conf
    section: Coredump
    option: "{{ item.option }}"
    value: "{{ item.value }}"
    mode: '0644'
  loop:
    - { option: 'Storage', value: 'none' }
    - { option: 'ProcessSizeMax', value: '0' }
```

---

## 9. Role 8: `apparmor_enforce` (Mandatory Access Control)

### Objetivo
Garantir que o LSM padrão do Debian 13 esteja operacional com todos os perfis em modo estrito de imposição (*enforcing*).

### Tarefas (`tasks/main.yml`)
```yaml
- name: Instalar pacotes de perfis e utilitários do AppArmor
  ansible.builtin.apt:
    name:
      - apparmor
      - apparmor-profiles
      - apparmor-utils
    state: present

- name: Garantir que o serviço do AppArmor esteja habilitado e ativo
  ansible.builtin.systemd:
    name: apparmor
    enabled: yes
    state: started

- name: Impor modo enforce em todos os perfis carregados
  ansible.builtin.command:
    cmd: aa-enforce /etc/apparmor.d/*
  changed_when: false
```

---

## 10. Role 9: `auditd_logging` (Auditoria Contínua Imutável)

### Objetivo
Rastrear chamadas de sistema, escalonamento de privilégios e alterações de credenciais, travando as regras até o reboot (CIS 4.x).

### Tarefas (`tasks/main.yml`)
```yaml
- name: Instalar auditd
  ansible.builtin.apt:
    name: auditd
    state: present

- name: Implantar regras CIS de auditoria
  ansible.builtin.copy:
    dest: /etc/audit/rules.d/50-security.rules
    content: |
      -D
      -b 8192
      -f 1

      # Identidade e Usuários (CIS 4.1.4)
      -w /etc/group -p wa -k identity
      -w /etc/passwd -p wa -k identity
      -w /etc/gshadow -p wa -k identity
      -w /etc/shadow -p wa -k identity
      -w /etc/security/opasswd -p wa -k identity

      # Ambiente de Rede (CIS 4.1.5)
      -a always,exit -F arch=b64 -S sethostname,setdomainname -k system_locale
      -w /etc/issue -p wa -k system_locale
      -w /etc/hosts -p wa -k system_locale

      # Privilégios e Sudoers (CIS 4.1.10)
      -w /etc/sudoers -p wa -k scope
      -w /etc/sudoers.d/ -p wa -k scope

      # Chamadas de Montagem (CIS 4.1.13)
      -a always,exit -F arch=b64 -S mount,umount2 -k mounts

      # Regras Imutáveis (CIS 4.1.17)
      -e 2
    owner: root
    group: root
    mode: '0640'
  notify: Recarregar Audit Rules

- name: Habilitar serviço auditd
  ansible.builtin.systemd:
    name: auditd
    enabled: yes
    state: started
```

### Handlers (`handlers/main.yml`)
```yaml
- name: Recarregar Audit Rules
  ansible.builtin.command:
    cmd: augenrules --load
  changed_when: true
```

---

## 11. Role 10: `auto_updates_integrity` (Unattended Upgrades & Debsums)

### Objetivo
Automatizar a aplicação de patches de segurança e auditar alterações em binários oficiais do sistema operacional.

### Tarefas (`tasks/main.yml`)
```yaml
- name: Instalar unattended-upgrades e debsums
  ansible.builtin.apt:
    name:
      - unattended-upgrades
      - apt-listchanges
      - debsums
    state: present

- name: Configurar origens de segurança automáticas no Debian
  ansible.builtin.copy:
    dest: /etc/apt/apt.conf.d/50unattended-upgrades
    content: |
      Unattended-Upgrade::Origins-Pattern {
          "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
      };
      Unattended-Upgrade::AutoFixInterruptedDpkg "true";
      Unattended-Upgrade::MinimalSteps "true";
      Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
      Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
    owner: root
    group: root
    mode: '0644'

- name: Habilitar execução diária do unattended-upgrades
  ansible.builtin.copy:
    dest: /etc/apt/apt.conf.d/20auto-upgrades
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";
    owner: root
    group: root
    mode: '0644'
```

---

## 12. Playbook Integrador e Tarefas de Validação (`verify.yml`)

### Playbook Principal (`site.yml`)
```yaml
---
- name: Hardening Completo Debian 13 para Máquinas Virtuais (CIS Level 1)
  hosts: debian_vms
  become: yes
  roles:
    - vm_firmware_agent
    - kernel_sysctl
    - filesystem_security
    - network_hardening
    - nftables_firewall
    - openssh_server
    - access_privilege
    - apparmor_enforce
    - auditd_logging
    - auto_updates_integrity
```

### Tarefas de Validação e Asserção (`verify.yml`)
Execute após o playbook para atestar que o estado desejado foi alcançado:

```yaml
---
- name: Validar Controles de Segurança Aplicados
  hosts: debian_vms
  become: yes
  tasks:
    - name: Verificar ASLR ativo em nível 2
      ansible.builtin.assert:
        that: ansible_kernel_randomize_va_space == "2"
      vars:
        ansible_kernel_randomize_va_space: "{{ lookup('pipe', 'sysctl -n kernel.randomize_va_space') }}"

    - name: Verificar política padrão de descarte do nftables
      ansible.builtin.command:
        cmd: nft list ruleset
      register: nft_output
      changed_when: false
      failed_when: "'policy drop' not in nft_output.stdout"

    - name: Verificar AppArmor em execução
      ansible.builtin.command:
        cmd: aa-status
      register: apparmor_output
      changed_when: false
      failed_when: "'apparmor module is loaded' not in apparmor_output.stdout"

    - name: Verificar bloqueio de login root no SSH
      ansible.builtin.command:
        cmd: sshd -T
      register: sshd_output
      changed_when: false
      failed_when: "'permitrootlogin no' not in sshd_output.stdout"

    - name: Relatório de Integridade de Pacotes com Debsums
      ansible.builtin.command:
        cmd: debsums -c
      register: debsums_result
      changed_when: false
      failed_when: debsums_result.rc != 0
```
