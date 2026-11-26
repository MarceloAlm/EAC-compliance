# Guia de Migração: Shim/MOK Manual → Kernel Assinado CachyOS (`linux-cachyos-eac`)

Este guia documenta a transição do setup atual de **Secure Boot + Shim + MOK + UKI Lockdown** para o kernel oficial pré-assinado do CachyOS (**`linux-cachyos-eac`**) com **`eac-setup`**, mantendo o kernel `linux` padrão para uso diário com hibernação.

> [!IMPORTANT]
> **Pré-requisito de Repositórios:** Como o host utiliza Arch Linux, os pacotes `linux-cachyos-eac`, `cachyos-eac-signing-key`, `systemd-boot-cachyos-signed` e `linux-cachyos-eac-nvidia-open` exigem que os **repositórios do CachyOS** estejam configurados no `/etc/pacman.conf`.
>
> **Ordem de Execução:** Execute as Fases 1, 2 e 3 **antes** de reiniciar o computador para evitar ficar sem uma entrada de boot válida durante a transição.

---

## Estado Atual do Boot (Pré-Migração)

Saída observada do `efibootmgr -v`:

- `Boot0000* Arch Linux (Shim MOK)` → `\EFI\systemd\shimx64.efi` *(será removida)*
- `Boot0003* Linux Boot Manager` → `\EFI\systemd\systemd-bootx64.efi` *(já existe e será promovida a padrão)*
- `Boot0001* Fallback Linux Boot Manager` → `\EFI\systemd\systemd-boot-fallbackx64.efi`
- `BootOrder` atual: `0000,0003,0001,0004,2001,2002,2003`

---

## Fase 1: Remover a Entrada UKI `lockdown` Atual

1. **Remover o diretório de cmdline isolado do lockdown:**

   ```bash
   sudo rm -rf /etc/cmdline.d/lockdown
   ```

2. **Remover o preset `lockdown` do `/etc/mkinitcpio.d/linux.preset`:**
   Edite o arquivo `/etc/mkinitcpio.d/linux.preset` para manter apenas o preset padrão:

   ```ini
   ALL_kver="/boot/vmlinuz-linux"

   PRESETS=('default')

   default_uki="/boot/EFI/Linux/arch-linux.efi"
   default_options="--splash /boot/loader/background.bmp"
   ```

3. **Remover a imagem UKI de lockdown do `/boot` e do banco do `sbctl`:**

   ```bash
   sudo sbctl remove-file /boot/EFI/Linux/arch-linux-lockdown.efi
   sudo rm -f /boot/EFI/Linux/arch-linux-lockdown.efi
   sudo mkinitcpio -P
   ```

---

## Fase 2: Remover Chaves MOK, Shim e Hooks

1. **(Opcional) Agendar remoção da chave MOK na NVRAM:**
   Caso queira remover explicitamente a chave MOK da NVRAM via `mokutil` (caso contrário, o reset para *Setup Mode* na BIOS durante a Fase 4 também limpa as chaves personalizadas):

   ```bash
   sudo mokutil --delete /etc/dkms/mok.der
   ```

2. **Promover `Linux Boot Manager` (`0003`) e remover `Arch Linux (Shim MOK)` (`0000`):**

   ```bash
   sudo efibootmgr -o 0003,0001,0004,2001,2002,2003
   sudo efibootmgr -b 0000 -B
   ```

   Confirme que o `BootOrder` agora inicia com `0003` executando:

   ```bash
   efibootmgr
   ```

3. **Remover os binários do Shim, MokManager e `grubx64.efi` da ESP e do `sbctl`:**

   ```bash
   sudo sbctl remove-file /boot/EFI/systemd/mmx64.efi
   sudo sbctl remove-file /boot/EFI/systemd/grubx64.efi
   sudo rm -f /boot/EFI/systemd/shimx64.efi /boot/EFI/systemd/mmx64.efi /boot/EFI/systemd/grubx64.efi
   ```

4. **Remover o hook customizado do Pacman (`95-systemd-boot.hook`):**

   ```bash
   sudo rm -f /etc/pacman.d/hooks/95-systemd-boot.hook
   ```

5. **Remover a configuração de assinatura DKMS e as chaves MOK locais:**

   ```bash
   sudo rm -f /etc/dkms/framework.conf.d/signing.conf /etc/dkms/mok.key /etc/dkms/mok.der /etc/dkms/mok.pem
   ```

6. **Desinstalar os pacotes `shim-signed` e `mokutil`:**

   ```bash
   sudo pacman -Rns shim-signed mokutil
   ```

---

## Fase 3: Trocar o Driver da NVIDIA (`nvidia-open-dkms` → Pré-compilados)

Para a GPU **RTX 4050** (arquitetura Ada Lovelace), utilize os pacotes pré-compilados **`nvidia-open`** (para o kernel `linux` padrão) e **`linux-cachyos-eac-nvidia-open`** (para o kernel EAC, já que módulos DKMS não são aceitos sob lockdown no kernel EAC):

1. **Substituir `nvidia-open-dkms` por `nvidia-open`:**
   *(Confirme a remoção do `nvidia-open-dkms` quando o `pacman` informar o conflito).*

   ```bash
   sudo pacman -S nvidia-open
   ```

2. **Regenerar a UKI do kernel padrão:**

   ```bash
   sudo mkinitcpio -P
   ```

3. **Garantir que os binários restantes no `sbctl` estão assinados antes do próximo reboot:**

   ```bash
   sudo sbctl verify
   ```

---

## Fase 4: Instalar o Kernel `linux-cachyos-eac` e Configurar o Secure Boot

1. **Confirmar os repositórios do CachyOS no `/etc/pacman.conf` e atualizar o sistema:**

   ```bash
   sudo pacman -Syu
   ```

2. **Instalar os pacotes do EAC, chaves de assinatura, bootloader assinado e driver NVIDIA do EAC:**

   ```bash
   sudo pacman -S sbctl sbsigntools tpm2-tools efibootmgr cachyos-eac-signing-key linux-cachyos-eac systemd-boot-cachyos-signed linux-cachyos-eac-nvidia-open
   ```

3. **Colocar o Secure Boot em *Setup Mode* na BIOS/UEFI:**
   - Reinicie e entre na BIOS/UEFI.
   - Limpe/resete as chaves do Secure Boot para colocá-lo em **Setup Mode** (`SetupMode = 1`).
   - Inicie o sistema normalmente pela entrada `Linux Boot Manager` (`arch-linux.efi`).

4. **Matricular as chaves (Microsoft + `sbctl` + CachyOS EAC CA):**

   ```bash
   sudo sbctl enroll-keys --microsoft --custom
   ```

5. **Executar o configurador automático do CachyOS:**

   ```bash
   sudo eac-setup
   ```

   > [!WARNING]
   > **Não** execute `sbctl sign` manualmente no kernel `linux-cachyos-eac` nem no binário do `systemd-boot-cachyos-signed`. Eles já possuem assinaturas oficiais do CachyOS; re-assiná-los com sua chave local quebra a validação do EAC.

---

## Fase 5: Testar o Boot e Validar

1. **Ativar o Secure Boot na BIOS/UEFI:**
   - Reinicie, entre na BIOS/UEFI e altere o Secure Boot para **Enabled**.

2. **Testar a entrada padrão (`arch-linux.efi`):**
   - Deixe iniciar normalmente (sem pressionar **Espaço**).
   - Confirme que a GPU está ativa e que a hibernação continua funcionando:
     ```bash
     nvidia-smi
     cat /sys/kernel/security/lockdown
     ```

3. **Testar a entrada EAC (`linux-cachyos-eac`):**
   - Reinicie e segure **Espaço** durante o boot para exibir o menu do `systemd-boot`.
   - Selecione a entrada do **kernel EAC**.
   - Valide o driver da GPU e a conformidade completa com o EAC Linux v2:
     ```bash
     nvidia-smi
     eac-status
     ```

   *(Nota: o script [check-eac-compliance.sh](check-eac-compliance.sh) deste repositório foi atualizado para validar também a assinatura EFI via `sbverify`, `sig_enforce` e os módulos carregados; use-o em conjunto com o `eac-status`).*

---

## Referências Oficiais

* [CachyOS Wiki: Easy Anti-Cheat (Linux v2)](https://wiki.cachyos.org/configuration/easy_anti_cheat/)
* [CachyOS Wiki: Optimized Repositories](https://wiki.cachyos.org/configuration/optimized_repositories/)
* [GitHub: CachyOS Linux Kernel (`linux-cachyos-eac`)](https://github.com/CachyOS/linux-cachyos)
* [GitHub: CachyOS-Settings (`eac-setup` / `eac-status`)](https://github.com/CachyOS/CachyOS-Settings)
* [Introducing Easy Anti-Cheat Linux v2 - Epic Online Services](https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2)
