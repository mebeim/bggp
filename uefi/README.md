# BGGP5 - @mebeim - UEFI

This directory will hold my attempts and submissions for BGGP5 in the form of
UEFI applications written for [EDK II][edk2]. Its contents will be updated with
the source code for my solution and a writeup soon, before the competition is
over.


## Building

In order to run my UEFI app, you need UEFI firmware that supports networking and
most importantly HTTPS, meaning HTTP + TLS. I opted for [EDK II][edk2] as it is
very straightforward to build and run in a QEMU VM.

Building is done through Docker to make things simple and reproducible. A couple
of patches ([`edk2_patches/`](./edk2_patches)) are applied to the EDK II source
code when building to fix a build dependency problem and disable TLS handshake
verification in order to simplify things avoiding the need to build a CA
certificate bundle from your host and provide it to OVMF through QEMU.

This directory includes a [`Dockerfile`](./Dockerfile) that can be used to
build:

- EDK II [OVMF][ovmf] UEFI firmware.
- EDK II UEFI network stack drivers (ARP, IPv4, UDP, TCP, DNS, HTTP, TLS, etc.).

You can build everything (EDK II OVMF + UEFI drivers) using a single Docker
command:

```sh
DOCKER_BUILDKIT=1 docker build . --target release --output type=local,dest=build
```

**NOTE:** if you run `docker` as root you will have to fix the output dir
permissions after building with `sudo chown -R $USER:$USER build/`.

The result will be a `build/` directory containing the following:

- `OVMF_CODE.fd`: OVMF firmware.
- `OVMF_VARS.fd`: OVMF firmware NVRAM variables.
- A bunch of `xxxDxe.efi` files: the EDK II UEFI drivers.
- `startup.nsh`: a UEFI shell script that loads the drivers and sets up the
  `eth0` interface with DHCP at startup.


## Running

You will need `qemu-system-x86_64` installed with virtio-net support. Everything
was tested on Debian 12 using `qemu-system-x86_64` version 7.2.11 from the
official Debian repositories and also QEMU 9.0.0 built from source using the
following configuration:

```none
$ ./configure --target-list=x86_64-softmmu \
    --enable-slirp \
    --enable-multiprocess \
    --disable-tools \
    --disable-kvm \
    --disable-debug-info \
    --disable-lto \
    --disable-werror
```

After building the EDK II OVMF as described in the [Building](#building) section
above, you can copy whatever UEFI application you want to run in the `build/`
directory and then use the [`./run.sh`](./run.sh) Bash script to run the OVMF
firmware using QEMU:

```none
$ echo 'BASE64_HERE' | base64 -d > build/app.efi
$ sha256sum build/app.efi
$ ./run.sh
```

After QEMU starts and iPXE starts the UEFI shell, the
[`startup.nsh`](startup.nsh) UEFI shell script will automatically load the UEFI
network drivers (`*Dxe.efi`) and request a DHCP lease for `eth0`. **Wait for it
to get a lease** checking with the command `ifconfig -l`, then run the
application you want (use `ls` to get a dir listing). All the files inside
`build/` will be available in the UEFI shell.

One small caveat: don't use a terminal window that is too tall or the EDK II
UEFI shell may overwrite output lines with the prompt, making things harder to
read. 30 lines of height work fine for me.

Example output after starting `./run.sh`:

```none
iPXE 1.0.0+git-20190125.36a4c85-5.1 -- Open Source Network Boot Firmware -- http://ipxe.org
Features: DNS HTTP iSCSI NFS TFTP AoE EFI Menu

net0: 52:54:00:12:34:56 using virtio-net on 0000:00:02.0 (open)
  [Link:up, TX:0 TXE:0 RX:0 RXE:0]
Configuring (net0 52:54:00:12:34:56)...... ok
net0: 10.0.2.15/255.255.255.0 gw 10.0.2.2
net0: fec0::5054:ff:fe12:3456/64 gw fe80::2
net0: fe80::5054:ff:fe12:3456/64
Nothing to boot: No such file or directory (http://ipxe.org/2d03e18e)

BdsDxe: failed to load Boot0002 "UEFI PXEv4 (MAC:525400123456)" from PciRoot(0x0)/Pci(0x2,0x0)/MAC(525400123456,0x1): Not Found
BdsDxe: loading Boot0003 "EFI Internal Shell" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(7C04A583-9E3E-4F1C-AD65-E05268D0B4D1)
BdsDxe: starting Boot0003 "EFI Internal Shell" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(7C04A583-9E3E-4F1C-AD65-E05268D0B4D1)
UEFI Interactive Shell v2.2
EDK II
UEFI v2.70 (EDK II, 0x00010000)
Mapping table
      FS0: Alias(s):HD0a65535a1:;BLK1:
          PciRoot(0x0)/Pci(0x1F,0x2)/Sata(0x0,0xFFFF,0x0)/HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)
     BLK0: Alias(s):
          PciRoot(0x0)/Pci(0x1F,0x2)/Sata(0x0,0xFFFF,0x0)
     BLK2: Alias(s):
          PciRoot(0x0)/Pci(0x1F,0x2)/Sata(0x2,0xFFFF,0x0)
Press ESC in 1 seconds to skip startup.nsh or any other key to continue.
Shell> echo -off
Image 'FS0:\SnpDxe.efi' loaded at 7E3BA000 - Success
Image 'FS0:\MnpDxe.efi' loaded at 7E38D000 - Success
Image 'FS0:\ArpDxe.efi' loaded at 7E1BE000 - Success
Image 'FS0:\RngDxe.efi' loaded at 7E1BA000 - Success
Image 'FS0:\Ip4Dxe.efi' loaded at 7E19A000 - Success
Image 'FS0:\Dhcp4Dxe.efi' loaded at 7E193000 - Success
Image 'FS0:\Udp4Dxe.efi' loaded at 7E187000 - Success
Image 'FS0:\TcpDxe.efi' loaded at 7E160000 - Success
Image 'FS0:\DnsDxe.efi' loaded at 7E14C000 - Success
Image 'FS0:\TlsDxe.efi' loaded at 7DF8C000 - Success
Image 'FS0:\HttpDxe.efi' loaded at 7E11E000 - Success
Image 'FS0:\HttpUtilitiesDxe.efi' loaded at 7E12B000 - Success
~
You should see all Success messages above
~
Now wait for eth0 to get a DHCP lease... should take max 5s
Check with the ifconfig command (see 'help ifconfig')
When it gets one you can run my BGGP5 UEFI app
~
The TAB key works for auto completion
Use CTRL+H for backspace and CTRL+C to exit when done
FS0:\>
FS0:\> ifconfig -l

-----------------------------------------------------------------

name         : eth0
Media State  : Media present
policy       : dhcp
mac addr     : 52:54:00:12:34:56

ipv4 address : 10.0.2.15

subnet mask  : 255.255.255.0

default gateway: 10.0.2.2

  Routes (2 entries):
    Entry[0]
     Subnet : 10.0.2.0
     Netmask: 255.255.255.0
     Gateway: 0.0.0.0
    Entry[1]
     Subnet : 0.0.0.0
     Netmask: 0.0.0.0
     Gateway: 10.0.2.2

DNS server   :
      10.0.2.3


-----------------------------------------------------------------
FS0:\> ls app.efi
Directory of: FS0:\
07/21/2024  22:35                 324  app.efi
          1 File(s)         324 bytes
          0 Dir(s)
FS0:\> app
Another #BGGP5 download!! @binarygolf https://binary.golf
```

---

*Copyright &copy; 2024 Marco Bonelli (@mebeim). Licensed under the MIT License.*


[edk2]: https://github.com/tianocore/edk2
[ovmf]: https://github.com/tianocore/tianocore.github.io/wiki/OVMF
