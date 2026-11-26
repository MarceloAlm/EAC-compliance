# Referência Histórica / Alternativa Manual: Cadeia Shim + MOK + UKI Lockdown no Arch Linux

> [!NOTE]
> **Documento de Referência à Parte**  
> Voltar para o guia principal (Arquitetura com Kernel Assinado CachyOS): **[README.pt-BR.md](README.pt-BR.md)**  
> Guia de migração de Shim/MOK para `linux-cachyos-eac`: **[MIGRACAO-CACHYOS-EAC.md](MIGRACAO-CACHYOS-EAC.md)**

Este documento preserva a arquitetura manual baseada em **Shim (`shimx64.efi`) + MOK + `sbctl` + UKI Lockdown** no kernel `linux` upstream do Arch Linux.

> [!WARNING]
> **Limitação com o EAC Linux v2:** A Epic Games **não aceita chaves MOK geradas localmente** na sua *Well-Known Key List*. Embora esta arquitetura cumpra tecnicamente todos os requisitos de segurança do sistema operacional (Secure Boot, TPM 2.0, Lockdown `[integrity]`, IOMMU, `kexec` desabilitado, LSM BPF e módulos assinados sem taint bit 13), ela **não** libera jogos com EAC Linux v2. Para compatibilidade real com o EAC v2 no Arch Linux, siga o guia principal em [README.pt-BR.md](README.pt-BR.md) utilizando `linux-cachyos-eac`.

---

## 1. A Arquitetura de Confiança de Duplo Chaveiro (`.platform` vs `.machine`)

### O Problema do Kernel Upstream com o `sbctl` e o Lockdown
No Arch Linux ao utilizar o [sbctl](https://wiki.archlinux.org/title/Sbctl), a chave mestre (`Database Key`) é gravada na memória NVRAM do firmware UEFI no banco `db`.

Quando o Linux inicializa:
* O kernel lê o banco `db` da UEFI e o adiciona ao chaveiro **`.platform`**.
* **Trava de Segurança Upstream:** O kernel Linux proíbe que o chaveiro `.platform` valide módulos de kernel (`.ko`), pois quase todas as placas-mãe possuem certificados da Microsoft no `db`.
* **Consequência sob Lockdown:** Ao ativar `lockdown=integrity`, o kernel do Arch ignora a `Database Key` no `.platform`, trata módulos DKMS locais como **não assinados** e bloqueia o carregamento com `Operation not permitted` ou `Key was rejected by service`.

### A Solução Manual: Shim + MOK + `sbctl`

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Firmware UEFI (NVRAM)                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                  Chama shimx64.efi (Assinatura Microsoft - Intocado)
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

## 2. Cadeia de Boot do Shim e Infraestrutura MOK

1. **Gerar o Par de Chaves MOK Dedicado e Proteger Permissões:**
   ```bash
   sudo openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 \
     -subj "/CN=Arch Linux Kernel Modules MOK/" \
     -keyout /etc/dkms/mok.key \
     -outform DER -out /etc/dkms/mok.der

   sudo openssl x509 -in /etc/dkms/mok.der -inform DER -out /etc/dkms/mok.pem
   sudo chmod 600 /etc/dkms/mok.key
   ```

2. **Configurar o Framework de Assinatura do DKMS:**
   ```bash
   sudo mkdir -p /etc/dkms/framework.conf.d
   cat << 'EOF' | sudo tee /etc/dkms/framework.conf.d/signing.conf
   sign_file="/usr/lib/modules/$kernelver/build/scripts/sign-file"
   mok_signing_key="/etc/dkms/mok.key"
   mok_certificate="/etc/dkms/mok.pem"
   EOF
   ```

3. **Instalar o `mokutil` e Enfileirar a Chave MOK:**
   ```bash
   sudo pacman -S mokutil
   sudo mokutil --import /etc/dkms/mok.der
   ```
   *(Confirme o enfileiramento com `sudo mokutil --list-new`).*

4. **Obter e Instalar `shim-signed-bin` via `makepkg` (AUR):**
   Inspecione o `PKGBUILD` antes de compilar:
   ```bash
   git clone https://aur.archlinux.org/shim-signed-bin.git
   cd shim-signed-bin
   vim PKGBUILD
   makepkg -si
   cd .. && rm -rf shim-signed-bin
   ```

5. **Copiar os Binários do Shim para a Partição ESP (`/boot/EFI/systemd/`):**
   ```bash
   sudo cp /usr/share/shim-signed/shimx64.efi /boot/EFI/systemd/
   sudo cp /usr/share/shim-signed/mmx64.efi /boot/EFI/systemd/
   sudo sbctl sign -s /boot/EFI/systemd/mmx64.efi
   ```
   > [!WARNING]
   > **NÃO altere nem assine o `shimx64.efi`:** Ele deve permanecer inalterado com a assinatura da Microsoft Corporation UEFI CA.

6. **Criar e Cadastrar o Executável `grubx64.efi` no `sbctl`:**
   ```bash
   sudo cp /usr/lib/systemd/boot/efi/systemd-bootx64.efi /boot/EFI/systemd/grubx64.efi
   sudo sbctl sign -s /boot/EFI/systemd/grubx64.efi
   ```

7. **Criar o Hook do Pacman para Atualização Automática do `systemd-boot` ([95-systemd-boot.hook](95-systemd-boot.hook)):**
   ```bash
   sudo mkdir -p /etc/pacman.d/hooks
   cat << 'EOF' | sudo tee /etc/pacman.d/hooks/95-systemd-boot.hook
   [Trigger]
   Type = Package
   Operation = Upgrade
   Target = systemd

   [Action]
   Description = Atualizando systemd-boot e sincronizando grubx64.efi para o Shim...
   When = PostTransaction
   Exec = /bin/sh -c "/usr/bin/bootctl update && /usr/bin/cp -f /boot/EFI/systemd/systemd-bootx64.efi /boot/EFI/systemd/grubx64.efi"
   EOF
   ```

8. **Adicionar a Entrada do Shim na NVRAM com `efibootmgr`:**
   ```bash
   sudo efibootmgr --create --disk /dev/nvme0n1 --part 1 \
     --label "Arch Linux (Shim MOK)" \
     --loader '\EFI\systemd\shimx64.efi'
   ```

9. **Matrícula na Tela Azul do MokManager (No Reboot):**
   Reinicie (`sudo reboot`), selecione **Enroll MOK** -> **Continue** -> **Yes**, digite a senha temporária do `mokutil` e reinicie.

---

## 3. Módulos DKMS e Perfil de Duplo Boot UKI (Desktop/Hibernação vs. Lockdown)

Com o Shim ativo e a chave MOK no chaveiro `.machine`:
```bash
sudo pacman -S nvidia-open-dkms
modinfo nvidia | grep signer
```

Para manter hibernação no uso diário e `lockdown=integrity` apenas na segunda entrada UKI:

1. **Estruturar `/etc/cmdline.d/` e `/etc/cmdline-lockdown.d/`:**
   ```bash
   # Entrada padrão (com hibernação)
   cat << 'EOF' | sudo tee /etc/cmdline.d/10-root.conf
   root=PARTUUID=<SEU-ROOT-PARTUUID> rw rootfstype=ext4 zswap.enabled=0 quiet splash
   EOF
   cat << 'EOF' | sudo tee /etc/cmdline.d/20-resume.conf
   resume=UUID=<SEU-SWAP-UUID> resume_offset=<SEU-OFFSET-SWAPFILE>
   EOF
   cat << 'EOF' | sudo tee /etc/cmdline.d/30-security.conf
   intel_iommu=on iommu=pt
   EOF

   # Entrada lockdown (sem resume=)
   sudo mkdir -p /etc/cmdline-lockdown.d
   sudo ln -sf /etc/cmdline.d/10-root.conf /etc/cmdline-lockdown.d/10-root.conf
   cat << 'EOF' | sudo tee /etc/cmdline-lockdown.d/30-security.conf
   lockdown=integrity intel_iommu=on iommu=pt efi=disable_early_pci_dma
   EOF
   ```

2. **Configurar os Presets no `/etc/mkinitcpio.d/linux.preset`:**
   ```ini
   ALL_kver="/boot/vmlinuz-linux"
   PRESETS=('default' 'lockdown')

   default_uki="/boot/EFI/Linux/arch-linux.efi"
   default_options="--splash /boot/loader/background.bmp"

   lockdown_uki="/boot/EFI/Linux/arch-linux-lockdown.efi"
   lockdown_options="--splash /boot/loader/background.bmp --cmdline /etc/cmdline-lockdown.d/"
   ```

3. **Compilar e assinar:**
   ```bash
   sudo mkinitcpio -P
   sudo sbctl sign -s /boot/EFI/Linux/arch-linux-lockdown.efi
   sudo bootctl set-default arch-linux.efi
   ```

---

## 4. Manutenção: Reconstruir e Reassinar Módulos DKMS Manualmente

```bash
# Reconstruir e assinar automaticamente via signing.conf
sudo dkms autoinstall -k $(uname -r)

# Ou reconstruir módulo específico
sudo dkms remove <modulo>/<versao> --all
sudo dkms install <modulo>/<versao>

# Ou assinar manualmente um .ko avulso com sign-file
sudo /usr/lib/modules/$(uname -r)/build/scripts/sign-file sha256 \
  /etc/dkms/mok.key \
  /etc/dkms/mok.pem \
  /caminho/para/o/modulo.ko
```

---

## 5. Referências

* [ArchWiki: Unified Extensible Firmware Interface/Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
* [ArchWiki: DKMS Secure Boot](https://wiki.archlinux.org/title/Dynamic_Kernel_Module_Support#Secure_Boot)
* [Linux Kernel Module Signing Documentation](https://docs.kernel.org/admin-guide/module-signing.html)
