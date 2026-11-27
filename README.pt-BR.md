# Guia Arch Linux: Secure Boot, TPM 2.0 e Kernel Assinado CachyOS para EAC Linux v2

[![Arch Linux](https://img.shields.io/badge/Arch%20Linux-Kernel%206.x%2F7.x-1793d1?logo=arch-linux&logoColor=white)](https://archlinux.org/)
[![CachyOS EAC](https://img.shields.io/badge/CachyOS-linux--cachyos--eac-00a896?logo=linux&logoColor=white)](https://wiki.cachyos.org/configuration/easy_anti_cheat/)
[![Secure Boot](https://img.shields.io/badge/UEFI-Secure%20Boot%20Ativo-success?logo=linux&logoColor=white)](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
[![Lockdown](https://img.shields.io/badge/Kernel%20Lockdown-integrity-blue)](https://docs.kernel.org/admin-guide/module-signing.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> Leia este documento em inglês: **[English](README.md)**  
> Consulte também o guia complementar de segurança: **[Guia de Hardening e CIS Benchmark](HARDENING.pt-BR.md)**

Este documento registra as configurações, referências oficiais e o passo a passo completo para implantar e manter um sistema **Arch Linux** em total conformidade com os requisitos estritos do **Easy Anti-Cheat (EAC) Linux v2** utilizando o kernel oficial pré-assinado do CachyOS (**`linux-cachyos-eac`**) e o **`systemd-boot`** assinado, mantendo o kernel padrão do Arch (`linux`) intacto para uso diário (hibernação, VirtualBox/DKMS e produtividade).

> [!IMPORTANT]
> **Por que `linux-cachyos-eac` em vez de chaves MOK locais?**
> Para impedir que trapaças assinem módulos maliciosos com chaves próprias, a Epic Games mantém uma **lista fechada de chaves públicas reconhecidas** (*Well-Known Key List*) e **não aceita chaves MOK geradas localmente pelo usuário**. O CachyOS mantém uma autoridade certificadora oficial (`CachyOS EAC CA`) reconhecida pelo EAC Linux v2 e distribui o kernel `linux-cachyos-eac` + módulos pré-compilados (`linux-cachyos-eac-nvidia-open`) + `systemd-boot-cachyos-signed` diretamente em seu repositório `[cachyos]`.

---

## Índice

- [1. Requisitos Técnicos do Easy Anti-Cheat Linux v2](#1-requisitos-técnicos-do-easy-anti-cheat-linux-v2)
  - [1.1. Matriz de Vetores de Defesa e Restrições Práticas no Sistema](#11-matriz-de-vetores-de-defesa-e-restrições-práticas-no-sistema)
- [2. Arquitetura de Duplo Boot no Arch Linux (Uso Diário vs. EAC v2)](#2-arquitetura-de-duplo-boot-no-arch-linux-uso-diário-vs-eac-v2)
- [3. Passo a Passo de Implementação Manual (Sem `eac-setup`)](#3-passo-a-passo-de-implementação-manual-sem-eac-setup)
  - [Fase 1: Secure Boot Base com `sbctl` (Apenas Kernel Padrão)](#fase-1-secure-boot-base-com-sbctl-apenas-kernel-padrão)
  - [Fase 2: Adicionar Apenas o Repositório `[cachyos]` no Arch Linux](#fase-2-adicionar-apenas-o-repositório-cachyos-no-arch-linux)
  - [Fase 3: Instalar Kernel EAC, Bootloader Assinado e Driver NVIDIA](#fase-3-instalar-kernel-eac-bootloader-assinado-e-driver-nvidia)
  - [Fase 4: Configurar Manualmente a Entrada EAC e Proteger Assinaturas](#fase-4-configurar-manualmente-a-entrada-eac-e-proteger-assinaturas)
  - [Fase 5: Matricular Chaves na UEFI (`--microsoft --custom`) e Ativar Secure Boot](#fase-5-matricular-chaves-na-uefi---microsoft---custom-e-ativar-secure-boot)
  - [Alternativa Opcional: Automação com `cachyos-settings` (`eac-setup`)](#alternativa-opcional-automação-com-cachyos-settings-eac-setup)
- [4. Auditor Automatizado de Kernel Direto (`check-eac-compliance.sh`)](#4-auditor-automatizado-de-kernel-direto-check-eac-compliancesh)
- [5. Guia de Verificação Pós-Boot](#5-guia-de-verificação-pós-boot)
- [6. Manutenção e Atualizações](#6-manutenção-e-atualizações)
- [7. Referências Oficiais](#7-referências-oficiais)
- [Licença](#licença)

---

## 1. Requisitos Técnicos do Easy Anti-Cheat Linux v2

O EAC Linux v2 abandona drivers de ring-0 invasivos em favor de um serviço sob demanda do **`systemd`** acoplado a programas **`eBPF`**, exigindo uma cadeia estrita de confiança no sistema operacional:

1. **UEFI [Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) Ativo** em modo usuário (`SetupMode = 0`) com chaves reconhecidas (`CachyOS EAC CA` + Microsoft).
2. **TPM 2.0 & Measured Boot** operacional com banco SHA-256 ativo.
3. **Kernel, Bootloader e Módulos Assinados** criptograficamente (`module.sig_enforce=1`).
4. **Kernel Lockdown em Modo `integrity`** (`/sys/kernel/security/lockdown` definido como `[integrity]`), bloqueando modificações no espaço de kernel mesmo pelo usuário `root`.
5. **`kexec` Desabilitado** (`kernel.kexec_load_disabled = 1`), impedindo injeção de kernels não verificados via memória RAM.
6. **IOMMU Habilitado** (Intel VT-d com `intel_iommu=on iommu=pt iommu.passthrough=0`, ou equivalente AMD-Vi), impedindo ataques DMA de periféricos físicos.
7. **LSM BPF Habilitado** (`lsm=landlock,lockdown,yama,integrity,bpf`), permitindo auditoria das sondas de integridade do anti-cheat via Security Module.

### 1.1. Matriz de Vetores de Defesa e Restrições Práticas no Sistema

| # | Requisito Técnico | Vetor de Defesa EAC | Consequência Prática no Sistema |
| :--- | :--- | :--- | :--- |
| **1** | **UEFI Secure Boot** (`SetupMode = 0`) | Impede carregamento de bootloaders, kernels ou binários EFI adulterados antes do SO. | **Binários não assinados não inicializam.** Pendrives sem assinatura reconhecida sofrem `Security Violation`. |
| **2** | **TPM 2.0 & Measured Boot** (PCRs) | Audita alterações em firmware, BIOS, bootloader e `cmdline`. | **LUKS via TPM fica sensível:** updates de BIOS ou mudanças de `cmdline` alteram PCRs. |
| **3** | **Assinatura de Módulos** (`module.sig_enforce=1`) | Bloqueia injeção de drivers não assinados no Ring-0. | **DKMS não funciona no kernel EAC.** Use os pacotes pré-compilados (`linux-cachyos-eac-nvidia-open`); mantenha VirtualBox/DKMS no kernel padrão `linux`. |
| **4** | **Kernel Lockdown** (`[integrity]`) | Isola a memória do kernel contra o espaço do usuário (mesmo com `root`). | **Hibernação bloqueada** no boot EAC; escrita em MSRs bloqueada (impede undervolt via software); `debugfs` restrito. |
| **5** | **Bloqueio de `kexec`** (`kexec_load_disabled = 1`) | Impede salto direto entre kernels na RAM sem passar pela UEFI. | **`systemctl kexec` desativado.** Trocas de kernel passam pelo boot completo. |
| **6** | **Isolamento IOMMU** (`intel_iommu=on iommu.passthrough=0`) | Mitiga ataques DMA via hardware PCIe / Thunderbolt. | Tráfego DMA filtrado pelo hardware IOMMU. |
| **7** | **LSM BPF Habilitado** (`bpf`) | Permite ao EAC inspecionar e vetar syscalls via eBPF. | Depuradores de memória (GDB, Cheat Engine via Proton) são vetados ao inspecionar o jogo. |

---

## 2. Arquitetura de Duplo Boot no Arch Linux (Uso Diário vs. EAC v2)

Ao manter os dois kernels em paralelo, você evita todas as restrições do Lockdown no dia a dia:

| Perfil | Entrada de Boot | Kernel | Driver NVIDIA | Recursos |
| :--- | :--- | :--- | :--- | :--- |
| **Desktop / Trabalho (Padrão)** | `/boot/EFI/Linux/arch-linux.efi` (UKI assinada pelo `sbctl`) | `linux` (Arch oficial) | `nvidia-open` | Hibernação (`resume=`), VirtualBox (`virtualbox-host-dkms`), undervolt |
| **Gaming / EAC Linux v2** | `/boot/loader/entries/cachyos-eac.conf` | `linux-cachyos-eac` (assinado pelo CachyOS) | `linux-cachyos-eac-nvidia-open` | `lockdown=integrity`, `module.sig_enforce=1`, `CachyOS EAC CA`, 100% conforme EAC v2 |

---

## 3. Passo a Passo de Implementação Manual (Sem `eac-setup`)

### Fase 1: Secure Boot Base com `sbctl` (Apenas Kernel Padrão)

Consulte o guia oficial do [ArchWiki: sbctl](https://wiki.archlinux.org/title/Sbctl):

1. **Instale o `sbctl` e crie suas chaves locais** (caso ainda não tenha criado):
   ```bash
   sudo pacman -S sbctl
   sudo sbctl create-keys
   ```

2. **Assine apenas a sua UKI padrão (e/ou kernel padrão) com o `sbctl`:**
   ```bash
   sudo sbctl sign -s /boot/EFI/Linux/arch-linux.efi
   ```
   > [!IMPORTANT]
   > **Não** adicione `/boot/EFI/systemd/systemd-bootx64.efi`, `/boot/EFI/BOOT/BOOTX64.EFI` nem `/boot/vmlinuz-linux-cachyos-eac` ao banco do `sbctl`. Esses arquivos usarão a assinatura oficial da **CachyOS EAC CA** (instalada na Fase 3). Se o `sbctl` re-assiná-los com sua chave local, a verificação do EAC falhará.

---

### Fase 2: Adicionar Apenas o Repositório `[cachyos]` no Arch Linux

Para manter o seu sistema **Arch Linux puro** (sem adicionar repositórios `*-v3`/`*-v4` e sem substituir pacotes base do Arch pelas compilações do CachyOS), faça a instalação **manual** da chave GPG, do mirrorlist e do bloco `[cachyos]` no final do `/etc/pacman.conf`:

1. **Importar e assinar localmente a chave GPG oficial do CachyOS:**
   ```bash
   sudo pacman-key --recv-keys F3B607488DB35A47 --keyserver keyserver.ubuntu.com
   sudo pacman-key --lsign-key F3B607488DB35A47
   ```

2. **Instalar somente `cachyos-keyring` e `cachyos-mirrorlist`:**
   ```bash
   sudo pacman -U \
     'https://mirror.cachyos.org/repo/x86_64/cachyos/cachyos-keyring-any.pkg.tar.zst' \
     'https://mirror.cachyos.org/repo/x86_64/cachyos/cachyos-mirrorlist-any.pkg.tar.zst'
   ```

3. **Adicionar apenas `[cachyos]` no final do `/etc/pacman.conf` (`sudo vim /etc/pacman.conf`), abaixo de `[core]`, `[extra]` e `[multilib]`:**
   ```ini
   [cachyos]
   Include = /etc/pacman.d/cachyos-mirrorlist
   ```

4. **Sincronizar e atualizar a base de pacotes:**
   ```bash
   sudo pacman -Syu
   ```

---

### Fase 3: Instalar Kernel EAC, Bootloader Assinado e Driver NVIDIA

**Instale os pacotes necessários do Arch e do `[cachyos]`:**
```bash
sudo pacman -S sbsigntools tpm2-tools efibootmgr \
  cachyos-eac-signing-key linux-cachyos-eac systemd-boot-cachyos-signed \
  linux-cachyos-eac-nvidia-open nvidia-open
```
*(Para GPUs NVIDIA Turing ou mais novas — GTX 16xx / RTX 20xx+ — use `linux-cachyos-eac-nvidia-open` + `nvidia-open`. Para Maxwell/Pascal/Volta, use `linux-cachyos-eac-nvidia-580xx`. Em GPUs **AMD ou Intel**, omita os pacotes NVIDIA).*

---

### Fase 4: Configurar Manualmente a Entrada EAC e Proteger Assinaturas

1. **Garantir que `sbctl` não gerencia os binários assinados pelo CachyOS:**
   Caso você já tivesse registrado o `systemd-boot` ou `BOOTX64.EFI` anteriormente no `sbctl`, remova-os do banco local e restaure a assinatura oficial do CachyOS:
   ```bash
   sudo sbctl remove-file /boot/EFI/BOOT/BOOTX64.EFI 2>/dev/null || true
   sudo sbctl remove-file /boot/EFI/systemd/systemd-bootx64.efi 2>/dev/null || true
   sudo sbctl remove-file /boot/vmlinuz-linux-cachyos-eac 2>/dev/null || true

   sudo cp -f /usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed /boot/EFI/systemd/systemd-bootx64.efi
   sudo cp -f /usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed /boot/EFI/BOOT/BOOTX64.EFI
   ```

2. **Consultar o `cmdline` atual, o `PARTUUID` da partição raiz e criar `/boot/loader/entries/cachyos-eac.conf`:**
   Antes de montar a entrada EAC, consulte os parâmetros já usados pelo seu kernel padrão (como `root=`, `rootfstype=`, `rootflags=` para Btrfs, etc.) e o identificador GPT da partição raiz (`/`):
   ```bash
   cat /proc/cmdline
   cat /etc/kernel/cmdline 2>/dev/null || true
   lsblk -o NAME,FSTYPE,LABEL,PARTUUID,MOUNTPOINTS
   ```
   > [!TIP]
   > Use a saída acima para confirmar seu `PARTUUID`, sistema de arquivos (`ext4`, `btrfs`, etc.) e eventuais flags de subvolume/criptografia. **Não** copie parâmetros de hibernação (`resume=`, `resume_offset=`) para a entrada EAC, pois a hibernação é bloqueada pelo `lockdown=integrity`.

   Crie o arquivo `/boot/loader/entries/cachyos-eac.conf` conforme sua GPU/CPU (substituindo `<SEU-ROOT-PARTUUID>` pelo valor real e ajustando `rootfstype=` se usar `btrfs`/outro):

   - **NVIDIA** *(CPU Intel; em CPUs AMD, substitua `intel_iommu=on` por `amd_iommu=on`)*:
     ```bash
     cat << 'EOF' | sudo tee /boot/loader/entries/cachyos-eac.conf
     title   CachyOS (EAC)
     linux   /vmlinuz-linux-cachyos-eac
     initrd  /initramfs-linux-cachyos-eac.img
     options root=PARTUUID=<SEU-ROOT-PARTUUID> rw rootfstype=ext4 zswap.enabled=0 quiet splash nvidia_drm.modeset=1 iommu=pt lockdown=integrity lsm=landlock,lockdown,yama,integrity,bpf iommu.passthrough=0 intel_iommu=on module.sig_enforce=1 sysctl.kernel.kexec_load_disabled=1
     EOF
     ```

   - **AMD** *(CPU/GPU AMD; em CPUs Intel, substitua `amd_iommu=on` por `intel_iommu=on`)*:
     ```bash
     cat << 'EOF' | sudo tee /boot/loader/entries/cachyos-eac.conf
     title   CachyOS (EAC)
     linux   /vmlinuz-linux-cachyos-eac
     initrd  /initramfs-linux-cachyos-eac.img
     options root=PARTUUID=<SEU-ROOT-PARTUUID> rw rootfstype=ext4 zswap.enabled=0 quiet splash iommu=pt lockdown=integrity lsm=landlock,lockdown,yama,integrity,bpf iommu.passthrough=0 amd_iommu=on module.sig_enforce=1 sysctl.kernel.kexec_load_disabled=1
     EOF
     ```

3. **Confirmar que o `systemd-boot` assinado está na NVRAM e verificar assinaturas:**
   ```bash
   sudo bootctl install
   sudo sbverify --list /boot/vmlinuz-linux-cachyos-eac
   sudo sbverify --list /boot/EFI/systemd/systemd-bootx64.efi
   ```
   *(Ambos devem exibir `subject: /CN=CachyOS EAC Signing ...` emitido por `issuer: /CN=CachyOS EAC CA/O=CachyOS`).*

---

### Fase 5: Matricular Chaves na UEFI (`--microsoft --custom`) e Ativar Secure Boot

1. **Colocar a BIOS/UEFI em *Setup Mode*:**
   Reinicie entrando direto no firmware:
   ```bash
   systemctl reboot --firmware-setup
   ```
   Na BIOS/UEFI, acesse **Security → Secure Boot**, selecione a opção para limpar/resetar as chaves (*Reset to Setup Mode* / *Clear Secure Boot Keys*), salve e inicie no Arch Linux.

2. **Confirmar `Setup Mode` e matricular as chaves:**
   ```bash
   sudo sbctl status
   sudo sbctl enroll-keys --microsoft --custom
   ```
   - `--microsoft`: **obrigatório** para Option ROMs de vídeo (NVIDIA/laptops) e dual-boot Windows.
   - `--custom`: matricula automaticamente o certificado `CachyOS EAC CA` instalado pelo pacote `cachyos-eac-signing-key` junto com suas chaves do `sbctl`.

3. **Ativar o Secure Boot na BIOS/UEFI:**
   Reinicie novamente na BIOS/UEFI (`systemctl reboot --firmware-setup`), ative **Secure Boot → Enabled**, salve e saia.

---

### Alternativa Opcional: Automação com `cachyos-settings` (`eac-setup`)

Se preferir automatizar as Fases 4 e 5 em vez de criar `/boot/loader/entries/cachyos-eac.conf` manualmente, o CachyOS fornece os utilitários `eac-setup` e `eac-status` no pacote **opcional** `cachyos-settings`:

```bash
sudo pacman -S cachyos-settings
sudo eac-setup
```

> [!NOTE]
> O pacote `cachyos-settings` instala e habilita serviços adicionais (`ananicy-cpp`, `systemd-oomd`, `cachyos-iw-set-regdomain`) e sysctls próprios do CachyOS. Após concluir a configuração, você pode desabilitar esses serviços ou até mesmo remover `cachyos-settings` (`sudo pacman -Rns cachyos-settings`) mantendo `/boot/loader/entries/cachyos-eac.conf` funcionando normalmente.

---

## 4. Auditor Automatizado de Kernel Direto (`check-eac-compliance.sh`)

Após iniciar na entrada **`CachyOS (EAC)`**, execute o script auditor fornecido neste repositório ([`check-eac-compliance.sh`](check-eac-compliance.sh)) para verificar diretamente as interfaces do kernel e assinaturas:

```bash
chmod +x check-eac-compliance.sh
sudo ./check-eac-compliance.sh
```

### Interfaces e Assinaturas Auditadas:

| Alvo | Fonte / Interface | Critério de Sucesso |
|---|---|---|
| **Secure Boot** | `/sys/firmware/efi/efivars/SecureBoot-*` | 5º byte == `0x01` |
| **Setup Mode** | `/sys/firmware/efi/efivars/SetupMode-*` | 5º byte == `0x00` (Modo Usuário ativo) |
| **TPM 2.0** | `/sys/class/tpm/tpm0/tpm_version_major` | Reporta versão `2` |
| **Measured Boot** | `/sys/kernel/security/tpm0/binary_bios_measurements` | Log de eventos > 0 bytes |
| **Kernel Lockdown** | `/sys/kernel/security/lockdown` | Contém `[integrity]` |
| **kexec Bloqueado** | `/proc/sys/kernel/kexec_load_disabled` | Igual a `1` |
| **Grupos IOMMU** | `/sys/kernel/iommu_groups` | Contagem de grupos > 0 |
| **LSM BPF** | `/sys/kernel/security/lsm` | Contém `bpf` |
| **Assinatura EFI** | `sbverify --list` (`/boot/vmlinuz-linux-cachyos-eac` e `systemd-bootx64.efi`) | Assinados pela `CachyOS EAC CA` |
| **module.sig_enforce** | `/sys/module/module/parameters/sig_enforce` | Igual a `Y` |
| **Chaves do Kernel** | `/proc/keys` | Chaves assimétricas ativas no kernel |
| **Módulos Carregados** | `/proc/modules` + `modinfo` | 100% dos módulos carregados assinados |
| **Taint do Kernel** | `/proc/sys/kernel/tainted` | Bit 13 (`8192` - Não assinado) em `0`; Bit 12 (`4096` - OOT) permitido |
| **Cmdline Ativo** | `/proc/cmdline` | Contém `lockdown=integrity` e `intel_iommu=on` |

---

## 5. Guia de Verificação Pós-Boot

Para reiniciar diretamente na entrada EAC pelo terminal (sem precisar segurar **Espaço** no boot):

```bash
sudo bootctl set-oneshot cachyos-eac.conf && systemctl reboot
```

Dentro da sessão EAC, você pode fazer checagens pontuais:

| Métrica | Comando de Auditoria Direta | Saída Esperada |
|---|---|---|
| **Auditor Completo** | `sudo ./check-eac-compliance.sh` | `100% PASS` (`0 FAIL`, `0 WARN`) |
| **Validador Opcional CachyOS** | `sudo eac-status` *(se `cachyos-settings` instalado)* | Todos `[ OK ]` |
| **Status do Lockdown** | `cat /sys/kernel/security/lockdown` | `none [integrity] confidentiality` |
| **kexec Desativado** | `cat /proc/sys/kernel/kexec_load_disabled` | `1` |
| **Assinatura de Módulos** | `modinfo -F signer nvidia` *(ou `drm`)* | `Build time autogenerated kernel key` |
| **Assinaturas EFI** | `sbverify --list /boot/vmlinuz-linux-cachyos-eac` | Assinado por `CachyOS EAC Signing ...` / `CachyOS EAC CA` |
| **Taint do Kernel** | `cat /proc/sys/kernel/tainted` | `4096` (módulo aberto out-of-tree) ou `0` (limpo) |
| **Driver 3D NVIDIA** | `nvidia-smi` | GPU funcional em Wayland/X11 |

---

## 6. Manutenção e Atualizações

1. **Atualizações normais (`sudo pacman -Syu`):**
   - Quando `linux` ou `mkinitcpio` atualizam, a UKI padrão `/boot/EFI/Linux/arch-linux.efi` é recompilada e assinada automaticamente pelo hook do `sbctl`.
   - Quando `linux-cachyos-eac` ou `systemd-boot-cachyos-signed` atualizam, os hooks próprios dos pacotes atualizam o `initramfs-linux-cachyos-eac.img` e o `systemd-boot` assinado sem intervenção manual.
2. **Sincronização do driver NVIDIA (`nvidia-open` vs. `linux-cachyos-eac-nvidia-open`):**
   Ambos os módulos compartilham o mesmo `nvidia-utils` em userspace. Caso um dos repositórios (`extra` do Arch vs. `cachyos`) publique uma nova versão do driver antes do outro, aguarde a sincronização antes de aplicar o `pacman -Syu` (ou atualize quando ambos estiverem na mesma versão de `nvidia-utils`).
3. **Nunca rodar `sbctl sign-all` incluindo os binários do EAC:**
   Como `/boot/vmlinuz-linux-cachyos-eac`, `/boot/EFI/systemd/systemd-bootx64.efi` e `/boot/EFI/BOOT/BOOTX64.EFI` **não** estão cadastrados no `/var/lib/sbctl/files.json`, o hook `zz-sbctl.hook` os preserva intactos.

---

## 7. Referências Oficiais

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

## Licença

Distribuído sob a [Licença MIT](LICENSE).
