# BGGP5 - @mebeim

My attempts and submissions for the [Binary Golf Grand Prix 5][bggp5]
competition, which took place from June 21 2024 to September 6 2024. This year's
goal: download and display the contents of the file at
`https://binary.golf/5/5`.

## Summary of my entries

| Kind                                   | Source                                                                                 | Entry size | Issue link                                    |
|:---------------------------------------|:---------------------------------------------------------------------------------------|:-----------|:----------------------------------------------|
| PHP script                             | [`php/BGGP5.php`](php/BGGP5.php)                                                       | 26 bytes   | https://github.com/binarygolf/BGGP/issues/69  |
| Linux ELF i386 exec                    | [`elf/exec_i386/exec_curl_needs_arg.asm`](elf/exec_i386/exec_curl_needs_arg.asm)       | 76 bytes   | https://github.com/binarygolf/BGGP/issues/117 |
| Linux ELF i386 exec                    | [`elf/exec_i386/exec_curl_short_url_v2.asm`](elf/exec_i386/exec_curl_needs_arg.asm)    | 82 bytes   | https://github.com/binarygolf/BGGP/issues/118 |
| Linux ELF x86-64 exec                  | [`elf/exec_x86_64/exec_curl_needs_arg.asm`](elf/exec_x86_64/exec_curl_needs_arg.asm)   | 112 bytes  | https://github.com/binarygolf/BGGP/issues/123 |
| Go program                             | [`go/cgo_system_curl_env_trick.go`](go/cgo_system_curl_env_trick.go)                   | 136 bytes  | https://github.com/binarygolf/BGGP/issues/116 |
| UEFI application                       | [`uefi/asm/BGGP5.asm`](uefi/asm/BGGP5.asm)                                             | 316 bytes  | https://github.com/binarygolf/BGGP/issues/130 |
| Linux ELF x86-64 dyn<sup>**(1)**</sup> | [`elf/dyn_x86_64/system_curl_pwd_trick.asm`](elf/dyn_x86_64/system_curl_pwd_trick.asm) | 456 bytes  | N/A<sup>**(1)**</sup>                         |

<sup>***(1)**: Not submitted as it would fall in the same category as the 64-bit exec version, which is smaller.*</sup>


## UEFI applications

**See writeup and source code in the [`uefi/`](uefi/) directory.**

I wrote various UEFI applications and tested them on QEMU with [EDK II][edk2]
OVMF firmware. You can see the different iterations, which are all commented.
These apps use the UEFI HTTP(S) protocol to download download the file at
`https://binary.golf/5/` to memory and display it.

Some of the programs are written in C using the EDK II C APIs, while others are
carefully hand-crafted using NASM assembler syntax and x86 assembly operations.
Of course, the latter are quite smaller. The base I used for the assembly
programs was [the BGGP4 UEFI entry by @netspooky][netspooky-bggp4]. It was a
good starting point since I was not very familiar with the PE before attempting
this.

This was definitely the most interesting and fun entry to write. Took me quite a
while to get it down to the final size, including writing
[a Python script](uefi/minimize.py) to optimize the packing and scheduling of
x86 instructions in the various PE/COFF header holes.

I also had fun writing automated QEMU runner scripts to test things and a
Docker-based build environment to make things easily reproducible (mainly to
make the life of whoever would be validating my entry easier).


## ELF programs

**See writeup and source code in the [`elf/`](elf/) directory.**

I wrote a bunch of different ELF programs for Linux x86 and x86-64, both static
`ET_EXEC` and dynamic `ET_DYN` using `libcurl`. The dynamic ones are quite
larger for obvious reasons so in the end I did not submit those, as it seems
like this year the ELF category does not distinguisy between `ET_EXEC` and
`ET_DYN`.

All these ELFs are hand crafted using NASM. They abuse the fact that the Linux
kernel ELF loader does not care about most of the ELF header and is very lenient
about its content. Code is stuffed in unused parts of ELF headers.

All the `ET_EXEC` ELFs end up executing `curl`. Some of them also download the
BGGP5 file from the `7f.uk` shorter URL, which redirects to the actual URL and
also redirects HTTP to HTTPS (not sure who created it, but thanks!).

Some of the `ET_DYN` ELFs link `libcurl.so` instead of executing the `curl`
binary. They make the dynamic linker load and resolve the necessary library
functions through appropriately crafted dynamic section, string table and
PLT/GOT tables. Writing dynamic ELFs that link and call library functions by
hand was pretty interesting. I had to dig into Glibc `ld.so` source code a few
times to understand how some of the things work at a low level.

Since this year's BGGP entries are differentiated based on the need of command
line args, which is why I have submitted two entries for x86 32-bit `ET_EXEC`.
At the end of the day, the smallest one simply performs `execve("/bin/curl",
argv, NULL)` and needs a command line argument.


## Go programs

**See writeup and source code in the [`go/`](go/) directory.**

This was a short experiment. These programs use [cgo][cgo] to call
[`system(3)`][man3system] from the C library directly.


## PHP script

**See writeup and source code in the [`php/`](php/) directory.**

This was also a very short experiment, just for fun. I almost put negative
effort into it. LOL.

---

*Copyright &copy; 2024 Marco Bonelli (@mebeim). Licensed under the MIT License.*


[bggp5]: https://binary.golf/5/
[edk2]: https://github.com/tianocore/edk2
[netspooky-bggp4]: https://github.com/netspooky/golfclub/tree/master/uefi/bggp4
[cgo]: https://go.dev/wiki/cgo
[man3system]: https://manned.org/man/system
