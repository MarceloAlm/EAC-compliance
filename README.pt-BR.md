# Guia Arch Linux: Secure Boot, TPM 2.0 e Kernel Lockdown atendendo requisitos EAC Linux v2

[![Arch Linux](https://img.shields.io/badge/Arch%20Linux-Kernel%206.x%2F7.x-1793d1?logo=arch-linux&logoColor=white)](https://archlinux.org/)
[![Secure Boot](https://img.shields.io/badge/UEFI-Secure%20Boot%20Ativo-success?logo=linux&logoColor=white)](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
[![Lockdown](https://img.shields.io/badge/Kernel%20Lockdown-integrity-blue)](https://docs.kernel.org/admin-guide/module-signing.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> Leia este documento em inglês: **[English](README.md)**

Este documento registra todas as configurações, referências oficiais, descobertas arquiteturais e o passo a passo integral para implantar e manter um sistema **Arch Linux** em total conformidade com os requisitos estritos do **Easy Anti-Cheat (EAC) Linux v2** (anunciado pela Epic Games em outubro de 2026), garantindo a integridade do sistema operacional com suporte completo a **placas de vídeo NVIDIA** e a qualquer módulo [DKMS](https://wiki.archlinux.org/title/Dynamic_Kernel_Module_Support#Secure_Boot) de terceiros (VirtualBox, v4l2loopback, drivers Wi-Fi/NICs proprietários, etc.).

> [!IMPORTANT]
> **Esclarecimento Técnico: A "Well-Known Key List" da Epic Games vs. Chaves MOK Locais:**
> Conforme detalhado no anúncio oficial da Epic Games:
> 1. **Parâmetros de Sistema (100% Conformes):** Todas as configurações deste guia (UEFI Secure Boot, TPM 2.0 & Measured Boot, Kernel Lockdown `[integrity]`, bloqueio de `kexec`, isolamento IOMMU e LSM BPF) cumprem rigorosamente e sem restrições todas as exigências do EAC Linux v2.
> 2. **A "Well-Known List" de Chaves:** Para prevenir que desenvolvedores de trapaças assinem módulos maliciosos com suas próprias chaves privadas, a Epic Games mantém uma **lista fechada de chaves públicas reconhecidas** (*Well-Known Key List*), que inicialmente contempla apenas distribuições com infraestrutura corporativa de assinatura centralizada (Ubuntu/Canonical, Fedora, Debian, openSUSE, Universal Blue/Bazzite).
> 3. **O Papel dos Mantenedores do Arch Linux:** A Epic Games **não aceita chaves MOK geradas localmente pelo próprio usuário** para fins de liberação no anti-cheat. A Epic declarou oficialmente que distribuições comunitárias dependem de uma coordenação direta de seus **mantenedores oficiais** para estabelecer uma autoridade certificadora (CA) oficial da distribuição que possa ser auditada e incluída na lista confiável do EAC. Este guia deixa o sistema pronto em nível de arquitetura para quando esse canal for consolidado.

---

## Índice

- [1. Requisitos Técnicos do Easy Anti-Cheat Linux v2](#1-requisitos-técnicos-do-easy-anti-cheat-linux-v2)
- [2. A Arquitetura de Confiança de Duplo Chaveiro (O Problema e a Solução)](#2-a-arquitetura-de-confiança-de-duplo-chaveiro-o-problema-e-a-solução)
- [3. Passo a Passo de Implementação Completa](#3-passo-a-passo-de-implementação-completa)
  - [Fase 1: Secure Boot Base com `sbctl`](#fase-1-secure-boot-base-com-sbctl)
  - [Fase 2: Sysctl e Linha de Comando Modular do Kernel (`/etc/cmdline.d/`)](#fase-2-sysctl-e-linha-de-comando-modular-do-kernel-etccmdlined)
  - [Fase 3: Cadeia de Boot do Shim e Infraestrutura MOK](#fase-3-cadeia-de-boot-do-shim-e-infraestrutura-mok)
  - [Fase 4: Instalação e Validação dos Módulos DKMS (NVIDIA e Jogos)](#fase-4-instalação-e-validação-dos-módulos-dkms-nvidia-e-jogos)
  - [Fase 5: Ativação Definitiva do Kernel Lockdown](#fase-5-ativação-definitiva-do-kernel-lockdown)
  - [Opção Alternativa: Perfil de Duplo Boot UKI (Desktop/Hibernação vs. Gaming/Lockdown)](#opção-alternativa-perfil-de-duplo-boot-uki-desktophibernação-vs-gaminglockdown)
- [4. Auditor Automatizado de Kernel Direto (`check-eac-compliance.sh`)](#4-auditor-automatizado-de-kernel-direto-check-eac-compliancesh)
- [5. Guia de Verificação Pós-Boot](#5-guia-de-verificação-pós-boot)
- [6. Manutenção: Como Reassinar e Reconstruir Módulos DKMS](#6-manutenção-como-reassinar-e-reconstruir-módulos-dkms)
- [7. Referências Oficiais](#7-referências-oficiais)
- [Licença](#licença)

---

## 1. Requisitos Técnicos do Easy Anti-Cheat Linux v2

O EAC Linux v2 abandona drivers de ring-0 invasivos (estilo Windows) em favor de um serviço sob demanda do **`systemd`** acoplado a programas **`eBPF`**, exigindo uma cadeia estrita de confiança no sistema operacional:

1. **UEFI [Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) Ativo** em modo usuário (`SetupMode = 0`) com chaves reconhecidas.
2. **TPM 2.0 & Measured Boot** operacional e medindo PCRs no boot.
3. **Kernel e Módulos Assinados** criptograficamente (`CONFIG_MODULE_SIG=y`).
4. **Kernel Lockdown em Modo `integrity`** (`/sys/kernel/security/lockdown` definido como `[integrity]`), bloqueando modificações no espaço de kernel mesmo pelo usuário `root`.
5. **`kexec` Desabilitado** (`kernel.kexec_load_disabled = 1`), impedindo injeção de kernels não verificados via memória RAM.
6. **IOMMU Habilitado** (Intel VT-d ou AMD-Vi com `iommu=pt`), impedindo ataques DMA de periféricos físicos.
7. **LSM BPF Habilitado** (`CONFIG_BPF_LSM=y`), permitindo auditoria das sondas de integridade do anti-cheat via Security Module.

---

## 2. A Arquitetura de Confiança de Duplo Chaveiro (O Problema e a Solução)

### O Problema do Kernel Upstream com o `sbctl` e o Lockdown
No Arch Linux ao utilizar o [sbctl](https://wiki.archlinux.org/title/Sbctl), a chave mestre (`Database Key`) é gravada diretamente na memória NVRAM do firmware UEFI no banco `db`.

Quando o Linux inicializa:
* O kernel lê o banco `db` da UEFI e o adiciona ao chaveiro **`.platform`**.
* **Trava de Segurança Upstream:** O kernel Linux proíbe que o chaveiro `.platform` valide módulos de kernel (`.ko`), pois quase todas as placas-mãe possuem certificados da Microsoft no `db`. Se o `.platform` validasse módulos, qualquer binário assinado com certificado Microsoft ou OEM poderia rodar no ring-0.
* **Consequência sob Lockdown:** Ao ativar `lockdown=integrity`, o kernel do Arch ignora a `Database Key` no `.platform`, trata o driver NVIDIA e qualquer outro módulo DKMS como **não assinados** e bloqueia o carregamento com `Operation not permitted`.

### A Solução: Arquitetura Shim + MOK + `sbctl`
Para contornar esse isolamento mantendo a máxima segurança, adotamos uma arquitetura de papéis separados:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Firmware UEFI (NVRAM)                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                         Chama shimx64.efi (Assinado MS / sbctl)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                              Shim Bootloader                           │
│  - Lê a lista MOK (MokList) na NVRAM                                   │
│  - Cria a variável de runtime EFI 'MokListRT'                          │
│  - Executa 'grubx64.efi' (cópia assinada do systemd-boot)              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 systemd-bootx64.efi -> arch-linux.efi (UKI)            │
│  - Executa o Kernel Linux com parâmetros de boot                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                             Kernel Linux                               │
│                                                                        │
│  [Keyring .platform] (via db UEFI)   │ [Keyring .machine] (via MokList)│
│  - Valida binários de boot e UKI     │ - Valida Módulos de Kernel      │
│  - Chave: Database Key (sbctl)       │ - Chave: Arch Linux Kernel MOK  │
│                                      │   (NVIDIA + Qualquer DKMS OK!)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Passo a Passo de Implementação Completa

### Fase 1: Secure Boot Base com `sbctl`

Consulte o guia oficial do [ArchWiki sbctl](https://wiki.archlinux.org/title/Sbctl) para o provisionamento base:

1. **Acessar o Firmware UEFI e Ativar o Modo de Instalação (Setup Mode):**
   Antes de permitir que o Linux matricule as chaves no chip NVRAM da placa-mãe, o firmware precisa ser colocado em **Setup Mode** (modo de configuração aberta onde as variáveis PK, KEK e db aceitam gravação). O caminho e o nome dessa opção variam dependendo da marca da placa-mãe ou do laptop:
   * **Lenovo (Insyde / ThinkPad / Legion):** Vá em `Security` -> `Secure Boot` -> selecione `Reset to Setup Mode` ou `Clear All Secure Boot Keys`.
   * **ASUS:** Acesse `Boot` -> `Secure Boot` -> `Key Management` -> selecione `Clear Secure Boot Keys` (o firmware entra em Setup Mode automaticamente).
   * **MSI:** Vá em `Settings` -> `Security` -> `Secure Boot` -> altere o modo de `Standard` para `Custom` -> selecione `Delete all Secure Boot variables`.
   * **Gigabyte / AORUS:** Navegue até `BIOS` -> `Secure Boot` -> mude para `Custom` -> selecione `Delete PK` ou `Clear Keys`.
   * **Dell:** Vá em `Secure Boot` -> `Expert Key Management` -> selecione `Enable Custom Mode` -> `Delete All Keys`.
   * **HP:** Acesse `Security` -> `Secure Boot Configuration` -> marque `Clear Secure Boot keys`.

   Salve as alterações e reinicie no Arch Linux. Confirme executando `sudo sbctl status` (deve constar `Setup Mode: ✓ Enabled` e `Secure Boot: ✗ Disabled`).

2. **Instalar o `sbctl` e Gerar as Chaves do Sistema:**
   ```bash
   sudo pacman -S sbctl
   sudo sbctl create-keys
   ```

3. **Matricular as Chaves com Suporte a Vendor Keys (Microsoft):**
   > [!IMPORTANT]
   > Conforme documentado no [ArchWiki: Secure Boot - Microsoft keys](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot#Microsoft_keys), a flag `-m` (`--microsoft`) é **obrigatória** em máquinas com GPU dedicada NVIDIA. Ela inclui as chaves Microsoft UEFI CA necessárias para carregar os Option ROMs de firmware de vídeo durante a inicialização, evitando telas pretas na BIOS/POST.
   ```bash
   sudo sbctl enroll-keys -m
   ```

4. **Assinar os Binários de Boot e a UKI:**
   ```bash
   sudo sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI
   sudo sbctl sign -s /boot/EFI/systemd/systemd-bootx64.efi
   sudo sbctl sign -s /boot/EFI/Linux/arch-linux.efi
   ```

---

### Fase 2: Sysctl e Linha de Comando Modular do Kernel (`/etc/cmdline.d/`)

1. **Desabilitar o `kexec` via Sysctl:**
   ```bash
   cat << 'EOF' | sudo tee /etc/sysctl.d/99-eac-security.conf
   kernel.kexec_load_disabled = 1
   EOF
   ```
   Aplique em tempo de execução:
   ```bash
   sudo sysctl -p /etc/sysctl.d/99-eac-security.conf
   ```

2. **Modularizar a Linha de Comando do Kernel:**
   O `mkinitcpio` moderno monta a [Imagem Unificada de Kernel (UKI)](https://wiki.archlinux.org/title/Unified_kernel_image) lendo drop-ins em `/etc/cmdline.d/*.conf` em ordem alfanumérica:

   #### 2.1. Identificar o PARTUUID da Partição Raiz
   Antes de criar ou editar as configurações de boot, consulte o identificador GPT da sua partição raiz:
   ```bash
   lsblk -o NAME,FSTYPE,LABEL,PARTUUID,MOUNTPOINTS
   ```
   * **`PARTUUID` (UUID da Partição):** Gravado no cabeçalho GPT da partição (localize a linha montada em `/`). Permanece idêntico mesmo se o sistema de arquivos for formatado, sendo o identificador ideal para `root=PARTUUID=...`.

   > [!NOTE]
   > **Nota sobre Hibernação (Suspend-to-Disk):**
   > Sob o Kernel Lockdown (`[integrity]`), a hibernação tradicional em disco é estritamente bloqueada por design do kernel upstream para prevenir adulteração de memória através do swap. A suspensão na memória RAM (`suspend`) permanece 100% operacional. Desta forma, não configuramos parâmetros de `resume=`.

   #### 2.2. Fazer Backup e Criar os Arquivos Modulares
   Em vez de apagar sua configuração anterior, faça uma cópia de segurança e use-a como base para os arquivos modulares:

   ```bash
   # 1. Criar o diretório de drop-ins:
   sudo mkdir -p /etc/cmdline.d

   # 2. Copiar a linha atual para 10-root.conf como base:
   sudo cp /etc/kernel/cmdline /etc/cmdline.d/10-root.conf

   # 3. Mover o arquivo monolítico original para backup:
   sudo mv /etc/kernel/cmdline /etc/kernel/cmdline.backup
   ```

   * **Inspecionar e Limpar os Parâmetros da Raiz (`/etc/cmdline.d/10-root.conf`):**
     Exiba o conteúdo herdado:
     ```bash
     cat /etc/cmdline.d/10-root.conf
     ```
     Abra o arquivo com o **Vim** (`sudo vim /etc/cmdline.d/10-root.conf`) e ajuste as opções seguindo estas diretrizes:
     * **O que MANTER:**
       * Referência da partição raiz: Certifique-se de que `root=PARTUUID=<SEU-ROOT-PARTUUID>` reflete a partição correta. Caso o original usasse `root=/dev/...` ou `root=UUID=...`, prefira o `PARTUUID` para imunidade contra alterações de formatação.
       * Tipo de sistema de arquivos e modo de escrita: `rootfstype=ext4` (ou `btrfs`), `rw`.
       * Parâmetros do sistema: `quiet`, `splash`, `zswap.enabled=...`, flags de processador, etc.
     * **O que REMOVER deste arquivo:**
       * **Parâmetros de hibernação:** Remova quaisquer opções de `resume=UUID=...` e `resume_offset=...` (visto que a hibernação é bloqueada sob Lockdown).
       * **Parâmetros de segurança e IOMMU:** Remova opções como `intel_iommu=...`, `iommu=...` ou `lockdown=...` (essas opções agora pertencem exclusivamente ao `90-security.conf`).

   * **Parâmetros de segurança (`/etc/cmdline.d/90-security.conf`):**
     Posicionado com índice `90` para ter menor precedência e ser avaliado após a raiz:
     ```bash
     cat << 'EOF' | sudo tee /etc/cmdline.d/90-security.conf
     intel_iommu=on iommu=pt
     EOF
     ```
     *(Em processadores AMD, utilize `amd_iommu=on`. Observação: o parâmetro `lockdown=integrity` será adicionado na Fase 5, após a infraestrutura MOK e o driver de vídeo estarem instalados e testados).*

#### 2.3. Cuidados Prévios e Validação do Secure Boot Base (Reboot Intermediário)

Antes de reiniciar para validar o Secure Boot base e os arquivos modulares do kernel, adote impreterivelmente os seguintes cuidados preventivos:

> [!CAUTION]
> **Checklist Essencial de Segurança Pré-Reboot:**
> 1. **Assinaturas da Partição ESP (`sbctl verify`):** Execute `sudo sbctl verify`. Todos os executáveis de boot (`/boot/EFI/BOOT/BOOTX64.EFI`, `/boot/EFI/systemd/systemd-bootx64.efi` e a imagem UKI `/boot/EFI/Linux/arch-linux.efi`) **devem** estar com a marcação verde `✓ is signed`. Se a imagem UKI não estiver assinada e o Secure Boot for exigido pelo firmware, o computador bloqueará o boot com mensagem de *Access Denied / Security Violation*.
> 2. **Conferir o `PARTUUID` no `10-root.conf`:** Verifique se o `PARTUUID` preenchido corresponde exatamente à partição raiz informada pelo `lsblk -o NAME,PARTUUID,MOUNTPOINTS`. Qualquer caractere incorreto impedirá a montagem da raiz, caindo no shell de resgate do initramfs.
> 3. **Garantir as Chaves Microsoft (`sbctl enroll-keys -m`):** Certifique-se de que a flag `-m` foi utilizada. Em placas de vídeo dedicadas NVIDIA ou telas de laptops, a ausência das chaves da Microsoft no banco `db` impede a inicialização do vídeo durante o POST/bootloader.
> 4. **Mídia de Instalação (Live USB do Arch) em mãos:** Tenha um pendrive de instalação do Arch Linux preparado. Caso ocorra qualquer erro de configuração de boot, você pode inicializar pelo pendrive (desativando temporariamente o Secure Boot na BIOS se necessário) e utilizar o `arch-chroot` para corrigir os arquivos.

**Gerar a UKI e Reiniciar para Validação Base:**
```bash
# 1. Compilar a UKI integrando a nova linha de comando modular:
sudo mkinitcpio -P

# 2. Confirmar que a nova UKI foi automaticamente assinada pelo hook do sbctl:
sudo sbctl verify

# 3. Reiniciar o sistema:
sudo reboot
```

**Validação Pós-Reboot:**
Ao retornar ao sistema, confirme que o Secure Boot base está ativo:
```bash
bootctl status | grep "Secure Boot:"
```
*Saída esperada: `Secure Boot: enabled (user)`.*
Com a base validada com sucesso, passe com total segurança para a Fase 3 para configurar o Shim e a infraestrutura MOK.

---

### Fase 3: Cadeia de Boot do Shim e Infraestrutura MOK

Antes de instalar os drivers de vídeo proprietários, configuramos os certificados MOK e a cadeia de inicialização com o preloader Shim.

1. **Gerar o Par de Chaves MOK Dedicado:**
   ```bash
   sudo openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 \
     -subj "/CN=Arch Linux Kernel Modules MOK/" \
     -keyout /etc/dkms/mok.key \
     -outform DER -out /etc/dkms/mok.der

   sudo openssl x509 -in /etc/dkms/mok.der -inform DER -out /etc/dkms/mok.pem
   ```

2. **Configurar o Framework de Assinatura do DKMS:**
   Configurar o [DKMS Secure Boot](https://wiki.archlinux.org/title/Dynamic_Kernel_Module_Support#Secure_Boot) antecipadamente garante que qualquer módulo compilado seja automaticamente assinado pelos hooks do pacman:
   ```bash
   sudo mkdir -p /etc/dkms/framework.conf.d
   cat << 'EOF' | sudo tee /etc/dkms/framework.conf.d/signing.conf
   sign_file="/usr/lib/modules/$kernelver/build/scripts/sign-file"
   mok_signing_key="/etc/dkms/mok.key"
   mok_certificate="/etc/dkms/mok.pem"
   EOF
   ```

3. **Instalar o `mokutil` e Enfileirar a Chave MOK:**
   O `mokutil` está disponível nos repositórios oficiais do Arch:
   ```bash
   sudo pacman -S mokutil
   sudo mokutil --import /etc/dkms/mok.der
   ```
   *O sistema solicitará uma senha temporária (memorize-a para a confirmação na tela azul).*
   *Confirme o enfileiramento com `sudo mokutil --list-new`.*

4. **Obter e Instalar o `shim-signed` via `makepkg`:**
   O preloader `shimx64.efi` oficial assinado pela Microsoft UEFI CA deve ser obtido através do pacote do AUR: [`shim-signed`](https://aur.archlinux.org/packages/shim-signed).

   > [!WARNING]
   > **Aviso de Segurança e Cuidados Essenciais com o AUR (Arch User Repository):**
   > O AUR é um repositório comunitário cujos scripts de compilação (`PKGBUILD`) **não passam por auditoria prévia da equipe oficial de segurança do Arch Linux**. Qualquer usuário pode enviar ou atualizar pacotes. Para manter seu sistema seguro, adote impreterivelmente os seguintes cuidados:
   > 1. **Inspecione o PKGBUILD:** Nunca instale um pacote do AUR às cegas. Abra o `PKGBUILD` com o **Vim** e confira os endereços das fontes (`source=`) e os hashes de integridade (`sha256sums=`). No caso do `shim-signed`, certifique-se de que o arquivo baixa o binário oficial empacotado pelo Fedora/Red Hat contendo a assinatura digital da Microsoft Corporation.
   > 2. **Nunca compile como root:** O utilitário `makepkg` deve sempre ser executado por um usuário comum sem privilégios administrativos.
   > 3. **Evite automação cega:** Não dependa de parsers ou helpers automáticos de terceiros; realize o processo nativo e auditável via `makepkg`.
   >
   > **Procedimento Oficial Nativo via `makepkg`:**
   > ```bash
   > git clone https://aur.archlinux.org/shim-signed.git
   > cd shim-signed
   > vim PKGBUILD   # Inspecione minuciosamente a procedência dos binários e checksums
   > makepkg -si
   > cd .. && rm -rf shim-signed
   > ```

5. **Copiar os Binários do Shim para a Partição ESP (`/boot/EFI/systemd/`):**
   ```bash
   sudo cp /usr/share/shim-signed/shimx64.efi /boot/EFI/systemd/
   sudo cp /usr/share/shim-signed/mmx64.efi /boot/EFI/systemd/
   sudo sbctl sign -s /boot/EFI/systemd/mmx64.efi
   ```

6. **Criar o Executável `grubx64.efi` a Partir do [systemd-boot](https://wiki.archlinux.org/title/Systemd-boot):**
   ```bash
   sudo cp /boot/EFI/systemd/systemd-bootx64.efi /boot/EFI/systemd/grubx64.efi
   sudo sbctl sign -s /boot/EFI/systemd/grubx64.efi
   ```

7. **Adicionar a Entrada do Shim na NVRAM com `efibootmgr`:**
   ```bash
   sudo efibootmgr --create --disk /dev/nvme0n1 --part 1 \
     --label "Arch Linux (Shim MOK)" \
     --loader '\EFI\systemd\shimx64.efi'
   ```

8. **Matrícula na Tela Azul do MokManager (No Reboot):**
   Reinicie o computador: `sudo reboot`. O Shim detectará a chave pendente e abrirá a tela azul do **MokManager**:
   * Pressione qualquer tecla para interromper a contagem regressiva.
   * Selecione **Enroll MOK** -> **Continue** (ou *View key 0* para conferir `Arch Linux Kernel Modules MOK`).
   * Selecione **Yes** e digite a senha temporária definida no `mokutil` -> **Reboot**.

---

### Fase 4: Instalação e Validação dos Módulos DKMS (NVIDIA e Jogos)

Com o sistema inicializado através do Shim e a chave MOK ativa no chaveiro `%:.machine`, proceda com a instalação dos módulos gráficos:

1. **Instalar o Driver NVIDIA (e Qualquer Outro Módulo DKMS):**
   Com o `signing.conf` ativo, a própria transação do pacman compilará e assinará os módulos na hora:
   ```bash
   # Driver principal para jogos (NVIDIA Open Kernel Modules):
   sudo pacman -S nvidia-open-dkms

   # Qualquer outro módulo DKMS necessário no seu ecossistema (ex.: VirtualBox, v4l2loopback, Wi-Fi):
   # sudo pacman -S virtualbox-host-dkms v4l2loopback-dkms
   ```

2. **Verificar a Assinatura Criptográfica dos Módulos:**
   ```bash
   modinfo nvidia | grep signer
   # Ou para qualquer outro módulo DKMS instalado:
   # modinfo vboxdrv | grep signer
   ```
   *Esperado: `signer: Arch Linux Kernel Modules MOK`.*

3. **Verificar o Reconhecimento da Placa de Vídeo:**
   ```bash
   nvidia-smi
   ```

---

### Fase 5: Ativação Definitiva do Kernel Lockdown

Com todos os módulos de terceiros devidamente assinados e validados pelo chaveiro `.machine`, ative a trava de integridade exigida pelo EAC v2:

1. **Adicionar `lockdown=integrity` ao `/etc/cmdline.d/90-security.conf`:**
   ```bash
   cat << 'EOF' | sudo tee /etc/cmdline.d/90-security.conf
   intel_iommu=on iommu=pt lockdown=integrity
   EOF
   ```

2. **Regenerar a UKI e Reiniciar:**
   Regenere a sua [UKI](https://wiki.archlinux.org/title/Unified_kernel_image) com o `lockdown=integrity` na linha de comando assinada e reinicie:
   ```bash
   sudo mkinitcpio -P
   sudo reboot
   ```

---

### Opção Alternativa: Perfil de Duplo Boot UKI (Desktop/Hibernação vs. Gaming/Lockdown)

Como o Kernel Lockdown em modo `[integrity]` bloqueia a restauração de imagem em disco (`LOCKDOWN_HIBERNATION`), usuários que dependem da **hibernação** no dia a dia podem configurar o `systemd-boot` com **duas entradas UKI independentes**:
* **Entrada Padrão (`arch-linux.efi`):** Uso diário para trabalho e produtividade com hibernação/swap ativo (sem `lockdown=integrity`).
* **Entrada Gaming (`arch-linux-lockdown.efi`):** Ambiente blindado para jogos com `lockdown=integrity`, `intel_iommu=on iommu=pt`, `efi=disable_early_pci_dma` e `kexec_load_disabled=1`.

#### 1. Estruturar `/etc/cmdline.d/` com Subdiretório Isolado

O `mkinitcpio` avalia de forma não-recursiva os arquivos `*.conf` dentro de `/etc/cmdline.d/`. Podemos isolar a entrada de jogos em uma subpasta `lockdown/`:

1. **Parâmetros base e de hibernação na raiz de `/etc/cmdline.d/` (Entrada Padrão):**
   ```bash
   # Base do sistema
   cat << 'EOF' | sudo tee /etc/cmdline.d/10-root.conf
   root=PARTUUID=<SEU-ROOT-PARTUUID> rw rootfstype=ext4 zswap.enabled=0 quiet splash
   EOF

   # Hibernação / Swapfile
   cat << 'EOF' | sudo tee /etc/cmdline.d/20-resume.conf
   resume=UUID=<SEU-SWAP-UUID> resume_offset=<SEU-OFFSET-SWAPFILE>
   EOF

   # IOMMU base
   cat << 'EOF' | sudo tee /etc/cmdline.d/30-security.conf
   intel_iommu=on iommu=pt
   EOF
   ```

2. **Criar a subpasta `lockdown/` com symlink da raiz e parâmetros de segurança:**
   ```bash
   sudo mkdir -p /etc/cmdline.d/lockdown

   # Link simbólico para reaproveitar os parâmetros da raiz sem duplicação
   sudo ln -sf /etc/cmdline.d/10-root.conf /etc/cmdline.d/lockdown/10-root.conf

   # Parâmetros de segurança e Kernel Lockdown
   cat << 'EOF' | sudo tee /etc/cmdline.d/lockdown/30-security.conf
   lockdown=integrity intel_iommu=on iommu=pt efi=disable_early_pci_dma kexec_load_disabled=1
   EOF
   ```

#### 2. Configurar os Presets no `/etc/mkinitcpio.d/linux.preset`

Edite o arquivo `/etc/mkinitcpio.d/linux.preset` (`sudo vim /etc/mkinitcpio.d/linux.preset`):

```ini
ALL_kver="/boot/vmlinuz-linux"

PRESETS=('default' 'lockdown')

# --- Entrada 1: Desktop / Hibernação (Padrão) ---
default_uki="/boot/EFI/Linux/arch-linux.efi"
default_options="--splash /boot/loader/background.bmp"

# --- Entrada 2: Gaming / EAC Anti-Cheat (Lockdown) ---
lockdown_uki="/boot/EFI/Linux/arch-linux-lockdown.efi"
lockdown_options="--splash /boot/loader/background.bmp --cmdline /etc/cmdline.d/lockdown"
```

#### 3. Compilar, Assinar e Definir o Padrão

```bash
# 1. Compilar ambas as imagens UKI
sudo mkinitcpio -P

# 2. Registrar a imagem de lockdown no sbctl (se ainda não assinado automaticamente)
sudo sbctl sign -s /boot/EFI/Linux/arch-linux-lockdown.efi

# 3. Definir a entrada com hibernação como inicialização padrão no systemd-boot
sudo bootctl set-default arch-linux.efi

# 4. Verificar as entradas detectadas
bootctl list
```

Ao ligar o computador, o sistema entra automaticamente na entrada com hibernação. Quando desejar jogar títulos protegidos por anti-cheat, pressione a tecla **Espaço** durante o boot e selecione a entrada `Arch Linux (...~lockdown)`.

---

## 4. Auditor Automatizado de Kernel Direto (`check-eac-compliance.sh`)

Imediatamente após reiniciar o sistema, execute o script auditor independente fornecido neste repositório ([`check-eac-compliance.sh`](check-eac-compliance.sh)) para verificar diretamente as interfaces do kernel sem depender de comandos de alto nível do sistema:

```bash
chmod +x check-eac-compliance.sh
sudo ./check-eac-compliance.sh
```

### Interfaces do Kernel (`sysfs` / `procfs`) Auditadas:

| Alvo | Caminho Direto no Kernel | Critério de Sucesso |
|---|---|---|
| **Secure Boot** | `/sys/firmware/efi/efivars/SecureBoot-*` | 5º byte == `0x01` |
| **Setup Mode** | `/sys/firmware/efi/efivars/SetupMode-*` | 5º byte == `0x00` (Modo Usuário ativo) |
| **TPM 2.0** | `/sys/class/tpm/tpm0/tpm_version_major` | Reporta versão `2` |
| **Measured Boot** | `/sys/kernel/security/tpm0/binary_bios_measurements` | Log de eventos > 0 bytes |
| **Kernel Lockdown** | `/sys/kernel/security/lockdown` | Contém `[integrity]` |
| **kexec Bloqueado** | `/proc/sys/kernel/kexec_load_disabled` | Igual a `1` |
| **Grupos IOMMU** | `/sys/kernel/iommu_groups` | Contagem de grupos > 0 |
| **LSM BPF** | `/sys/kernel/security/lsm` | Contém `bpf` |
| **MokListRT (Shim)**| `/sys/firmware/efi/efivars/MokListRT-*` | Tabela exportada em runtime presente |
| **Chaveiro MOK** | `/proc/keys` | Certificado presente na tabela de chaves |
| **Taint do Kernel** | `/proc/sys/kernel/tainted` | Bit 13 (`8192` - Não assinado) em `0`; Bit 12 (`4096` - OOT DKMS) permitido |
| **Cmdline Ativo** | `/proc/cmdline` | Contém `lockdown=integrity` e `intel_iommu=on` |

---

## 5. Guia de Verificação Pós-Boot

Você também pode realizar checagens pontuais nas interfaces de integridade:

| Métrica | Comando de Auditoria Direta | Saída Esperada |
|---|---|---|
| **Status do Lockdown** | `cat /sys/kernel/security/lockdown` | `none [integrity] confidentiality` |
| **kexec Desativado** | `cat /proc/sys/kernel/kexec_load_disabled` | `1` |
| **Chave MOK no Kernel** | `keyctl show %:.machine` ou `cat /proc/keys` | Contém `Arch Linux Kernel Modules MOK` |
| **Taint do Kernel** | `cat /proc/sys/kernel/tainted` | `4096` (OOT DKMS) ou `0` (limpo) |
| **Host Security ID** | `fwupdmgr security` | HSI-1 válido, Intel BootGuard habilitado |
| **Driver 3D NVIDIA** | `nvidia-smi` | GPU funcional em Wayland/X11 |

---

## 6. Manutenção: Como Reassinar e Reconstruir Módulos DKMS

Sempre que houver atualizações do kernel Linux ou caso você instale novos dispositivos com drivers de terceiros, utilize estes procedimentos padrão:

### A. Reconstrução e Assinatura Automática (Padrão)
Como o `/etc/dkms/framework.conf.d/signing.conf` é permanente, os hooks do `pacman` reconstroem e assinam todos os módulos DKMS automaticamente a cada atualização de kernel. Para acionar manualmente:
```bash
sudo dkms autoinstall
```

### B. Forçar a Reconstrução de um Módulo Específico
Para limpar completamente e forçar a recompilação e assinatura de qualquer módulo (substitua pelo nome e versão do seu driver):
```bash
# Verificar status dos módulos instalados:
dkms status

# Reconstruir e reassinar do zero:
sudo dkms remove <modulo>/<versao> --all
sudo dkms install <modulo>/<versao>
```
*Exemplo prático para o driver NVIDIA:*
```bash
sudo dkms remove nvidia/615.78.08 --all && sudo dkms install nvidia/615.78.08
```

### C. Assinatura Manual Direta com `sign-file`
Se você compilar manualmente um arquivo de módulo `.ko` fora da árvore do DKMS, pode assiná-lo diretamente com o utilitário oficial do kernel:
```bash
sudo /usr/lib/modules/$(uname -r)/build/scripts/sign-file sha256 \
  /etc/dkms/mok.key \
  /etc/dkms/mok.pem \
  /caminho/para/o/modulo.ko
```

---

## 7. Referências Oficiais

* [Introducing Easy Anti-Cheat Linux v2 - Epic Online Services](https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2)
* [ArchWiki: Unified Extensible Firmware Interface/Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
* [ArchWiki: sbctl](https://wiki.archlinux.org/title/Sbctl)
* [ArchWiki: Unified Kernel Image (UKI)](https://wiki.archlinux.org/title/Unified_kernel_image)
* [ArchWiki: systemd-boot](https://wiki.archlinux.org/title/Systemd-boot)
* [ArchWiki: DKMS Secure Boot](https://wiki.archlinux.org/title/Dynamic_Kernel_Module_Support#Secure_Boot)
* [Linux Kernel Module Signing Documentation](https://docs.kernel.org/admin-guide/module-signing.html)

---

## Licença

Distribuído sob a [Licença MIT](LICENSE).
