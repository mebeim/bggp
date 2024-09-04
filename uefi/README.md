# BGGP5 - @mebeim - UEFI

These are UEFI Applications for [EDK II][edk2] that can be run throug the EDK II
UEFI shell. They all accomplish the same thing: download the file at
`https://binary.golf/5/5` to memory and print its contents to console
(VGA/serial).

To build and run the apps, check the [Building](#building) and
[Running](#running) sections below. For a more detailed writeup, keep
reading on!

| File                                                 | Compiled size | Notes |
|------------------------------------------------------|---------------|-------|
| [`asm/BGGP5.asm`](asm/BGGP5.asm)                     | 316 bytes     | Will hang in an infinite loop after doing its job. |
| [`asm/BGGP5_Asm_v3.asm`](asm/BGGP5_Asm_v3.asm)       | 452 bytes     | |
| [`asm/BGGP5_Asm_v2.asm`](asm/BGGP5_Asm_v2.asm)       | 700 bytes     | |
| [`asm/BGGP5_Asm_v1.asm`](asm/BGGP5_Asm_v1.asm)       | 754 bytes     | |
| [`c/BGGP5_Raw_v4.c`](c/BGGP5_Raw_v4.c)               | 1408 bytes    | |
| [`c/BGGP5_Raw_v3.c`](c/BGGP5_Raw_v3.c)               | 6848 bytes    | |
| [`c/BGGP5_Raw_v2.c`](c/BGGP5_Raw_v2.c)               | 8128 bytes    | |
| [`c/BGGP5_HttpIoLib.c`](c/BGGP5_HttpIoLib.c)         | 8448 bytes    | |
| [`c/BGGP5_Raw_v1.c`](c/BGGP5_Raw_v1.c)               | 8576 bytes    | |


## UEFI specification

The first thing I did to figure if and how it was possible to perform an HTTPS
request from UEFI firmware was reading through the [UEFI spec][uefi-spec]
(release 2.10 of Aug 29, 2022). It describes both low level networking protocols
such ARP/DHCP/DNS, and high level protocols such as HTTP and TLS. I would
actually recommend downloading [the PDF version][uefi-spec-pdf] of the specas
the formatting is way better.

At first glance, it does not look like HTTPS is explicitly mentioned, described
as a protocol, or even supported at all out of the box. However, there is a
single instance in the whole spec where the term "HTTPS" is mentioned, and it's
in the context of the `EFI_HTTP_PROTOCOL.Request()` method: more specifically,
when the `EFI_HTTP_REQUEST_DATA` structure used to perform requests is
mentioned.

Here's the relevant part (bold emphasis mine):

> ```c
> //*******************************************
> // EFI_HTTP_REQUEST_DATA
> //*******************************************
> typedef struct {
>     EFI_HTTP_METHOD Method;
>     CHAR16 *Url;
> } EFI_HTTP_REQUEST_DATA;
> ```
>
> `Method`: The HTTP method (e.g. GET, POST) for this HTTP Request.<br>
> `Url`: The URI of a remote host. From the information in this field, the HTTP
> instance will be able to determine **whether to use HTTP or HTTPS** and will
> also be able to determine the port number to use.

So a conforming UEFI implementation should indeed be able to perform HTTPS
requests! After googling around a bit more, after all, this makes sense, as it
also seems that UEFI HTTPS boot is a thing.


## EDK II UEFI Implementation

[EDK II][edk2] is a popular open-source UEFI implementation (I would go as far
as to say *THE* implementation). I have some familiarity with EDK II and I have
hacked around it for a few CTF challenges. EDK II implements all the protocols
described in the UEFI spec and provides various utility libraries to perform
common operations such as printing, managing memory, random number generation,
and so on. These libraries can be used when writing UEFI drivers or UEFI apps
and are statically linked at build time.

The build system seems convoluted at first, but once you get the hang of it, it
becomes quite straightforward. Most importantly, it provides an easy way to
build an ["OVMF"][ovmf], i.e. a UEFI firmware that can be easily run in virtual
machines and emulators such as QEMU.

### Patching EDK II Code To Make Thinkgs Work Smoothly

Performing HTTPS requests requires performing a proper TLS handshake and
validating the server's certificate, all things that the TLS UEFI protocol does
automatically. However, this requires either embedding CA certificates in the
UEFI firmware at build time, or providing them at runtime from QEMU (in case of
OVMF).

This should be easily doable as explained [here][qemu-uefi-tls-certs]. However,
when I tried it using my host system's CA certificates, it only worked for some
websites, and not for `https://binary.golf`, for which apparently EDK II was not
happy to complete a TLS handshake. I did not want to bother with this, so I
decided to simply ignore the TLS handshake verification with [a simple
patch](edk2_patches/ovmf_tlslib_verify_none.patch) to `TlsLib` that sets
`SSL_VERIFY_NONE` on the underlying libopenssl context. I don't consider this
cheating as HTTPS with TLS is still used, the only thing that changes is that
the server's certificate is always trusted. This also makes it simpler to test
the apps as you don't have to fiddle around building and passing CA certificate
bundles from your host to the OVMF through QEMU, but of course, using such an
OVMF build for anything else that has to do with TLS/HTTPS is a bad idea.

Furthermore (unsure why), it seems to me that building EDK II OVMF with network
protocols and HTTP + TLS support is currently broken on the latest release,
because of a dependency of some of the protocols on the `RngDxe` driver that is
not built by default for OVMF. I wrote
[a second simple patch](edk2_patches/ovmf_rng.patch) to include it in the build
dependencies of `OvmfPkgX64.dsc`, and this fixes the issue.


## C UEFI Applications (using EDK II libs)

Looking at the [UEFI spec][uefi-spec], I found a nice complete example of
performing an HTTP request using `EFI_HTTP_PROTOCOL` in section 29.6.9.1, and
skimming through EDK II sources I also found that it provides a nice library
called `HttpIoLib` exposing a more user-friendly and higher-level API built on
top of `EFI_HTTP_PROTOCOL`. Thus, I started writing some C UEFI apps.

The UEFI applications in the [`c/`](c/) directory are written in C and use the
EDK II libraries and build framework. They need to be compiled using EDK II
sources (see the [Building](#building) section below for more info). The code
should be simple enough to understand, and is also commented, so I won't go into
much detail here.

Here's a short description of the various versions:

- [`c/BGGP5_HttpIoLib.c`](c/BGGP5_HttpIoLib.c) uses EDK II `HttpIoLib` for
  simplicity and performs appropriate error checking and cleanup. The
  HttpIoLib's interface allows to easily perform requests and is by far the
  easiest way to do this using EDK II libs.

- [`c/BGGP5_Raw_v1.c`](c/BGGP5_Raw_v1.c) uses raw UEFI services as per UEFI spec
  with no EDK II library functions apart from `Print()`. It uses
  `EFI_BOOT_SERVICES.CreateEvent()` to implement asynchronous callbacks for the
  request, while the main application sleeps for at most 10 seconds before
  canceling the request. It uses `EFI_BOOT_SERVICES.LocateHandleBuffer()` to
  query all the HTTP drivers (i.e. basically one per NIC) and then uses
  `EFI_BOOT_SERVICES.OpenProtocol()` on the first one. This is a "nice" and
  almost raw way to do things.

- [`c/BGGP5_Raw_v2.c`](c/BGGP5_Raw_v2.c) accomplishes pretty much the same thing
  as v1, with the only difference being the usage of
  `EFI_BOOT_SERVICES.LocateProtocol()` and `EFI_BOOT_SERVICES.HandleProtocol()`
  instead of `EFI_BOOT_SERVICES.LocateHandleBuffer()` and
  `EFI_BOOT_SERVICES.OpenProtocol()`. HTTP callbacks are still there. This is a
  simpler way to do things and it's more or less the way that it's done in the
  example I found for the `EFI_HTTP_PROTOCOL` in the [UEFI spec][uefi-spec]
  (Section 29.6.9.1 of v2.10).

- [`c/BGGP5_Raw_v3.c`](c/BGGP5_Raw_v3.c) drops the asynchronous callbacks and
  performs the request synchronously. This results in a bit less code.

- [`c/BGGP5_Raw_v4.c`](c/BGGP5_Raw_v4.c) is a stripped down version of v3 that
  also does not perform any error checking nor cleanup. Additionally, all EDK II
  libs are dropped, including `PrintLib` and therefore the `Print()` function,
  which when statically linked at build time adds a lot of code. The compiler
  also uses `UefiMain()` itself as entry point (there is no separate entry point
  function that then calls `UefiMain()` like in the other versions).
  This achieves the smallest size of all the C UEFI applications I wrote at
  1408 bytes on my system when built along with the EDK II OVMF in RELEASE mode
  (again, see [Building](#building) instructions below).


## Assembly UEFI Applications

Once it was clear how to perform an HTTPS request from UEFI firmware, I started
from the final minimal version of the C code
([`c/BGGP5_Raw_v4.c`](c/BGGP5_Raw_v4.c)) with the intention of writing a
[Portable Executable][pe] by hand using [NASM][nasm] and x86 assembly.

As it turns out, in the previous edition of BGGP, there was a
[UEFI application entry and writeup][netspooky-bggp4] by
[@netspooky][netspooky], who had written a hand-crafted PE using NASM, and also
did a nice talk about it. This was a great starting point for me as I was not
familiar at all with the Portable Executable file format. The final generated PE
files are rather small as they contain the bare minimum metadata needed to get
loaded by the EDK II PE loader. Additionally, code/data is stuffed pretty much
wherever possible in the DOS/PE header and section headers.

The UEFI applications in the [`asm/`](asm/) directory are (mostly) hand-crafted
[PE][pe] files written in assembly ([NASM][nasm] directives + x86 Intel asm) to
minimize their size. They are basically different iterations of size
optimizations: the higher the version, the smaller the final compiled size. They
can be compiled standalone using `nasm` (se also
[`asm/Makefile`](asm/Makefile)). The final version is
[`asm/BGGP5.asm`](asm/BGGP5.asm) at 316 bytes of size when compiled.

These PEs accomplish the job pretty much in the same way as the C version at
[`c/BGGP5_Raw_v4.c`](c/BGGP5_Raw_v4.c). No error checking is performed. All the
function calls are assumed to succeed.

The steps are:

1. Locate HTTP Service Binding protocol (`EFI_HTTP_SERVICE_BINDING_PROTOCOL`)
   via `EFI_BOOT_SERVICES.LocateProtocol()`.
2. Create a child handle via `EFI_HTTP_SERVICE_BINDING_PROTOCOL.CreateChild()`.
3. Get ahold of the HTTP protocol driver (`EFI_HTTP_PROTOCOL`) via
   `EFI_BOOT_SERVICES.HandleProtocol()`.
4. Configure the protovol via `EFI_HTTP_PROTOCOL.Configure()` and perform a
   synchronouse GET request via `EFI_HTTP_PROTOCOL.Request()` and
   `EFI_HTTP_PROTOCOL.Response()`.
5. Convert the response from ASCII to UTF-16 and print it to the console using
   `EFI_BOOT_SERVICES.ConOut::OutputString()`. The final ASM version simplifies
   this step by writing the ASCII response to serial port directly instead (see
   below).

You are welcome to
**check out the comments in the source code itself for more details**, but here
is a rundown of the different versions:

- [`asm/BGGP5_Asm_v1.asm`](asm/BGGP5_Asm_v1.asm) is the first implemenation I
  wrote. Pretty straightforward, nothing amazing going on. The layout of the PE
  header is based on [@netspooky's BGGP4 entry][netspooky-bggp4], but the holes
  in the DOS/PE headers are simply filled with zeroes instead of code. All the
  code is past the headers and the needed data structures are embedded in the
  file right after the code. This includes both structures that will be
  populated and passed around at runtime and constants such as GUIDs and
  strings.

- [`asm/BGGP5_Asm_v2.asm`](asm/BGGP5_Asm_v2.asm) is a slightly optimized
  version of v1. Available holes in DOS/PE headers are still unused and
  zero-filled. 32-bit registers are used instead of 64-bit ones where possible
  to save space since EDK II address space uses addresses that fit in 32 bits.
  The data structs are overlapped and compressed a bit more.

- [`asm/BGGP5_Asm_v3.asm`](asm/BGGP5_Asm_v3.asm) is where things are taken to
  the next level. A total of 66 instructions (ignoring stack frame setup and
  teardown) are present. Only *2* of them are longer than 3 bytes: one
  `LEA [RIP + off]` and one `CALL [REG + off]`. This makes the final step of
  fitting the code in the header holes much more manageable.

  The main changes from v2 are:

  - A couple of additional holes in the section headers are made available,
    since I also found out that various section header field are ignored by the
    EDK II loader. All the holes are however still unused, they will only be
    used in the next (final) version.
  - The code is optimized down to the single instruction encoding to be as small
    as possible. Some long instructions are also split into multiple shorter
    ones that accomplish the same thing in order to make them easier to manage
    later on.
  - The URL embedded at the end of the file is ASCII instead of UTF-16. It is
    converted to UTF-16 at runtime to save space.
  - Raw serial output is performed to I/O port 0x3F8 (COM1) instead of calling
    `EFI_BOOT_SERVICES.ConOut::OutputString()`, which also saves the conversion
    of the response to UTF-16.
  - The data structures needed at runtime are removed from the end of the file
    and pushed on the stack at runtime, saving a lot of space. Some of them are
    even overlapped on the stack to save instructions. Only GUIDs and string
    constants are kept at the end of the file.
  - The `VirtualSize` of the only declared section is set to be larger than its
    `SizeOfRawData`. This makes the EDK II PE loader zero-out memory past the end
    of the file for us, which allows omitting a final NUL-terminator for the
    request URL.

- [`asm/BGGP5.asm`](asm/BGGP5.asm) is the final form, result of optimally
  packing the v3 code into the DOS/PE/section header holes (see next section for
  a more detailed explanation).

  The only difference in terms of code between this final version and v3, is
  that the code will jump into an infinite loop and hang forever after printing
  the response to the serial port. This is done to prevent a crash, since in
  order to save as much space as possible no callee-saved registers are
  saved/restored and no proper stack frame setup/tedown is performed.

  Starting from the PE entry point (`ENTRY:` label), execution jumps through the
  various `HOLEn:` labels. The v3 code is short enough that we don't even need a
  final JMP instruction to go back after the entry point after executing the
  code in the last hole.

  **The final size of the compiled PE binary is a measly 316 bytes. Sweet!**


## Shrinking Things Down To The Limit

After writing the first 3 assembly versions, and in particular after optimizing
the code for size as much as possible in v3, there was only one thing left to do
to produce [`asm/BGGP5.asm`](asm/BGGP5.asm): **finding the optimal way to pack
the code in the DOS/PE header and section header holes**.

This may seem like a trivial task at first, specially if it only has to be done
once, but it's not as simple when you also consider the fact that *any change to
the code means re-arranging most of the instructions* to fit in the various
holes. In fact, during development, I kept constantly coming up with new
optimizations and changes to the code, and after the first couple of times of
manually moving things around, I realized it was going to be way too much work.
Therefore, in order to help me accomplish the task, I (mostly) automated this
last step.

The final code will need to jump around to different chunks in the various
header holes using JMP instructions. The first problem that comes to mind is
therefore finding a nice order for the chunks to minimize the space wasted by
JMP instructions. If two chunks are too far apart, jumping from one to the other
requries a 5-byte relative long JMP with a 32-bit offset. However, if the chunks
are close enough, a 2-byte short JMP with an 8-bit offset can be used.

Furthermore, and this is the annoying part, the order of the chunks also
indirectly affects the way instructions can be packed and the consequent amount
of wasted space, given that instructions have fixed sizes and need to be
executed in a specific fixed order.

For example, consider the case of two chunks A and B of sizes 3 and 5
respectively, and two instructions X and Y of sizes 3 and 1 respectively.
Assuming 2-byte JMPs, the best order for the chunks is B->A, as we can fit X +
JMP in chunk A, then Y + JMP in chunk B. On the contrary, ordering the chunks as
A->B wouldn't be as good: the first X instruction wouldn't fit in chunk A and we
would have to only put a JMP there, wasting 1 byte of space.

Finally, the amount of instructions we put after the initial `ENTRY:` label
before jumping to the first header chunk will also affect the result: depending
on the (ordered) sizes of the leftover instructions, there will be different
ways to fit them in the subsequent chunks more or less optimally.

The [`./minimize.py`](./minimize.py) Python 3 script takes
[`asm/BGGP5_Asm_v3.asm`](asm/BGGP5_Asm_v3.asm), compiles it to using the
`Makefile` in the `asm/` directory, and extracts the code after the `ENTRY:`
label. It then decodes the instructions to know their size, and finds the
optimal packing of the instructions in the various header holes to minimize the
final file size.

Given the offset and size of each header hole (`HOLEn:` labels) and the offset
of the entry point (`ENTRY:` label), the script uses a simple greedy recursive
DFS algorithm to solve the chunk ordering problem. As per how many instructions
to put after the initial `ENTRY:` point before the first JMP into the header
chunks, it simply checks all possibilities, from 0 instructions (only the JMP)
upwards, stopping at the first optimal solution found (header holes completely
filled with instructions with no space wasted).

Additionally, the script also gets rid of any callee-saved register save/restore
instructions, stack frame setup/teardown, and final RET instruction before
optimizing things. The code can in fact do its job without a proper function
prolog/epilog. What happens after the job is done is not important, as long as
we download and display the contents of the file at `https://binary.golf/5/5`.

The output of the script only consists of a simple assembly listing where the
original instructions taken from v3 are reordered and a few JMPs are inserted.
All instructions are assumed to NOT change encoding size based on their
location. The instructions are not actually re-assembled based on their new
position, so the offsets embedded in them are not valid, but their size is. The
output cannot therefore be simply copy-pasted and executed is. A final manual
step was required to transcribe the output into
[`asm/BGGP5.asm`](asm/BGGP5.asm). In this final version, since there were 2
bytes of space left, I simply let the code hang in an infinite loop after doing
its job.


## Building

In order to run these UEFI apps, you need UEFI firmware that supports networking
and most importantly HTTPS, meaning HTTP + TLS. [EDK II][edk2] is used as it is
very straightforward to build and run in a QEMU VM. It implements the HTTP and
TLS protocol part of the [UEFI spec][uefi-spec], including transparent support
for HTTPS through the HTTP protocol, which is quite nice. HTTP + TLS support
requires the selection of appropriate build-time options. *These apps are build
for EDK II.*

Building is done through Docker to make things simple and reproducible. A few
patches ([`edk2_patches/`](./edk2_patches)) are applied to the EDK II source
code when building to include my apps in the default OVMF build, fix a build
dependency and disable TLS handshake verification as explained in the
[Patching EDK II Code To Make Things Work Smoothly](#patching-edk-ii-code-to-make-thinkgs-work-smoothly)
section above.

This directory includes a [`Dockerfile`](./Dockerfile) that can be used to
build:

- EDK II [OVMF][ovmf] UEFI firmware.
- EDK II UEFI network stack drivers (ARP, IPv4, UDP, TCP, DNS, HTTP, TLS, etc.).
- The UEFI applications in the [`c/`](C/) directory (that use EDK II libraries)
- THE UEFI applications in the [`asm/`](asm/) directory (these can also be built
  standalone using `nasm`).

You can build everything (EDK II OVMF + UEFI drivers + C apps + ASM apps) using
a single Docker command:

```sh
DOCKER_BUILDKIT=1 docker build . --target release --output type=local,dest=build
```

**NOTE:** if you run `docker` as root you will have to fix the output dir
permissions after building with `sudo chown -R $USER:$USER build/`.

The result will be a `build/` directory containing the following:

- `OVMF_CODE.fd`: OVMF firmware.
- `OVMF_VARS.fd`: OVMF firmware NVRAM variables.
- A bunch of `xxxDxe.efi` files: the EDK II UEFI drivers.
- Some `BGGP5*.efi` files: my UEFI apps (from `asm/` and `c/`).
- `startup.nsh`: a UEFI shell script that loads the drivers and sets up the
  `eth0` interface with DHCP at startup.

You can also build the ASM UEFI apps alone with `make -C asm`. The compiled
binaries will be at `asm/*.efi`.


## Running

You will need `qemu-system-x86_64` installed with virtio-net support! Everything
was tested on Debian 12 using `qemu-system-x86_64` version 7.2.11 from the
official Debian repositories and also QEMU 9.0.0 built from source using the
following configuration:

```sh
./configure --target-list=x86_64-softmmu \
    --enable-slirp \
    --enable-multiprocess \
    --disable-tools \
    --disable-kvm \
    --disable-debug-info \
    --disable-lto \
    --disable-werror
```

*One small caveat: don't use a terminal window that is too tall or the EDK II
UEFI shell may overwrite output lines with the prompt, making things harder to
read. 30 lines of height works fine for me.*

Use the [`./run.sh`](./run.sh) Bash script after building to run the OVMF
firmware using QEMU. After QEMU starts and iPXE starts the UEFI shell, the
[`startup.nsh`](startup.nsh) UEFI shell script will automatically load the UEFI
network drivers (`*Dxe.efi`) and request a DHCP lease for `eth0`. **Wait for it
to get a lease** checking with the command `ifconfig -l`, then run the
`BGGP5*.efi` application you want (use `ls` to list them).

The more advanced [`./run.py`](./run.py) Python 3 script also supports
automatically running the UEFI apps by sending keystrokes to the UEFI shell
through QEMU monitor, and can also verify their output. See `./run.py --help`
for more info.


### Running existing pre-compiled UEFI applications

After building the base OVMF system (see [Building](#building) section above),
you can copy any file you want in the `build/` directory and then use
[`./run.sh`](./run.sh) to run QEMU. All the files inside `build/` will be
available in the UEFI shell.

Example of testing [my submission][submission]:

```sh
base64 -d > build/submission.efi
# Paste Base64, press ENTER followed by CTRL+D when done

sha256sum build/submission.efi
# Verify the hash

./run.sh
# Wait for UEFI shell and DHCP, then run submission.efi
```

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
Image 'FS0:\SnpDxe.efi' loaded at 7E3B8000 - Success
Image 'FS0:\MnpDxe.efi' loaded at 7E38C000 - Success
Image 'FS0:\ArpDxe.efi' loaded at 7E1BC000 - Success
Image 'FS0:\RngDxe.efi' loaded at 7E1BA000 - Success
Image 'FS0:\Ip4Dxe.efi' loaded at 7E199000 - Success
Image 'FS0:\Dhcp4Dxe.efi' loaded at 7E192000 - Success
Image 'FS0:\Udp4Dxe.efi' loaded at 7E18C000 - Success
Image 'FS0:\TcpDxe.efi' loaded at 7E161000 - Success
Image 'FS0:\DnsDxe.efi' loaded at 7E14D000 - Success
Image 'FS0:\TlsDxe.efi' is not an image.
Image 'FS0:\HttpDxe.efi' loaded at 7E144000 - Success
Image 'FS0:\HttpUtilitiesDxe.efi' loaded at 7E16F000 - Success
FS0:\> ifconfig -l

-----------------------------------------------------------------

name         : eth0
Media State  : Media present
policy       : dhcp
mac addr     : 52:54:00:12:34:56

ipv4 address : 0.0.0.0

subnet mask  : 0.0.0.0

default gateway: 0.0.0.0

  Routes (0 entries):

DNS server   :

-----------------------------------------------------------------
FS0:\> echo -off
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
You should see all Success messages above
~
Now wait for eth0 to get a DHCP lease... should take max 5s
Check with the ifconfig command (see 'help ifconfig')
When it gets one you can run the BGGP5* apps
~
The TAB key works for auto completion
Use CTRL+H for backspace
Use CTRL+C to exit when you are done
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
FS0:\> ls submission.efi
Directory of: FS0:\
07/21/2024  22:35                 316  app.efi
          1 File(s)         316 bytes
          0 Dir(s)
FS0:\> submission
Another #BGGP5 download!! @binarygolf https://binary.golf
^C
qemu-system-x86_64: terminating on signal 2
```

---

*Copyright &copy; 2024 Marco Bonelli (@mebeim). Licensed under the MIT License.*


[edk2]: https://github.com/tianocore/edk2
[nasm]: https://github.com/netwide-assembler/nasm
[pe]: https://en.wikipedia.org/wiki/Portable_Executable
[ovmf]: https://github.com/tianocore/tianocore.github.io/wiki/OVMF
[netspooky]: https://x.com/netspooky
[netspooky-bggp4]: https://github.com/netspooky/golfclub/tree/master/uefi/bggp4
[qemu-uefi-tls-certs]: https://github.com/tianocore/edk2/blob/489e4a60ea88326a07a7cee8086227c3df2bf93d/OvmfPkg/README#L328
[ovmf]: https://github.com/tianocore/tianocore.github.io/wiki/OVMF
[uefi-spec]: https://uefi.org/specs/UEFI/2.10/
[uefi-spec-pdf]: https://uefi.org/sites/default/files/resources/UEFI_Spec_2_10_Aug29.pdf
[submission]: https://github.com/binarygolf/BGGP/issues/130
