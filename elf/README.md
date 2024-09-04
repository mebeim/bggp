# BGGP5 - @mebeim - ELF

These are hand-crafted [ELF][elf] files for Linux x86_64, written in assembly
([NASM][nasm] directives + x86 Intel asm) to minimize their size. They all
accomplish the same thing: download the file at `https://binary.golf/5/5` to
memory and output its contents.

See the detailed comments inside the source files themselves for more info!
Consider them a writeup of themselves.

Compile everything with `make` and run each file as `./path/to/file` after
building. Some binaries need a special setup to run (see notes column and legend
below the table).

Build dependencies are GNU Make (if you want to use the `Makefile` in this dir),
and the NASM x86 assembler. Tested on Debian 12 x86_64 with Linux kernel
6.1.0-22-amd64.

| File                                        | ELF kind                    | Compiled size | Notes           |
|---------------------------------------------|-----------------------------|---------------|-----------------|
| [`exec_i386/exec_curl_needs_arg.asm`][0]    | 32bit ET_EXEC, Linux x86    | 76 bytes      | *(1), (3)*      |
| [`exec_i386/exec_curl_short_url_v2.asm`][1] | 32bit ET_EXEC, Linux x86    | 82 bytes      | *(1), (4), (x)* |
| [`exec_i386/exec_curl_short_url_v1.asm`][2] | 32bit ET_EXEC, Linux x86    | 86 bytes      | *(1), (4), (x)* |
| [`exec_i386/exec_curl.asm`][3]              | 32bit ET_EXEC, Linux x86    | 97 bytes      | *(1), (4)*      |
| [`exec_x86_64/exec_curl_needs_arg.asm`][4]  | 64bit ET_EXEC, Linux x86_64 | 112 bytes     | *(1), (3)*      |
| [`exec_x86_64/exec_curl_short_url.asm`][5]  | 64bit ET_EXEC, Linux x86_64 | 127 bytes     | *(1), (4), (x)* |
| [`exec_x86_64/exec_curl.asm`][6]            | 64bit ET_EXEC, Linux x86_64 | 138 bytes     | *(1), (4)*      |
| [`dyn_x86_64/system_curl_pwd_trick.asm`][7] | 64bit ET_DYN, Linux x86_64  | 456 bytes     | *(1), (5)*      |
| [`dyn_x86_64/system_curl.asm`][8]           | 64bit ET_DYN, Linux x86_64  | 464 bytes     | *(1)*           |
| [`dyn_x86_64/libcurl_v7.asm`][9]            | 64bit ET_DYN, Linux x86_64  | 602 bytes     | *(2)*           |
| [`dyn_x86_64/libcurl_v6.asm`][10]           | 64bit ET_DYN, Linux x86_64  | 610 bytes     | *(2)*           |
| [`dyn_x86_64/libcurl_v5.asm`][11]           | 64bit ET_DYN, Linux x86_64  | 650 bytes     | *(2)*           |
| [`dyn_x86_64/libcurl_v4.asm`][12]           | 64bit ET_DYN, Linux x86_64  | 684 bytes     | *(2)*           |
| [`dyn_x86_64/libcurl_v3.asm`][13]           | 64bit ET_DYN, Linux x86_64  | 1050 bytes    | *(2)*           |
| [`dyn_x86_64/libcurl_v2.asm`][14]           | 64bit ET_DYN, Linux x86_64  | 1115 bytes    | *(2)*           |
| [`dyn_x86_64/libcurl_v1.asm`][15]           | 64bit ET_DYN, Linux x86_64  | 1148 bytes    | *(2)*           |

***(1)** Needs `curl` installed at `/bin/curl`.*
<br>
***(2)** Needs `libcurl` installed (e.g. `libcurl4` pkg on Debian 12).*
<br>
***(3)** Needs to be invoked with `https://binary.golf/5/5` as first argument.*
<br>
***(4)** Needs `/proc/sys/vm/mmap_min_addr` set to `0`.*
<br>
***(5)** Needs to be invoked with `/binary.golf/5/5` as the current working directory.*
<br>
***(x)** Does a request to `http://7f.uk`, which redirects to the right URL.*

---

*Copyright &copy; 2024 Marco Bonelli (@mebeim). Licensed under the MIT License.*


[0]: exec_i386/exec_curl_needs_arg.asm
[1]: exec_i386/exec_curl_short_url_v2.asm
[2]: exec_i386/exec_curl_short_url_v1.asm
[3]: exec_i386/exec_curl.asm
[4]: exec_x86_64/exec_curl_needs_arg.asm
[5]: exec_x86_64/exec_curl_short_url.asm
[6]: exec_x86_64/exec_curl.asm
[7]: dyn_x86_64/system_curl_pwd_trick.asm
[8]: dyn_x86_64/system_curl.asm
[9]: dyn_x86_64/libcurl_v7.asm
[10]: dyn_x86_64/libcurl_v6.asm
[11]: dyn_x86_64/libcurl_v5.asm
[12]: dyn_x86_64/libcurl_v4.asm
[13]: dyn_x86_64/libcurl_v3.asm
[14]: dyn_x86_64/libcurl_v2.asm
[15]: dyn_x86_64/libcurl_v1.asm

[elf]: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
[nasm]: https://github.com/netwide-assembler/nasm
