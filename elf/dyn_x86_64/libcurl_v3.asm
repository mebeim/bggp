; @mebeim - 2024-06-26
;
; 64-bit ET_DYN ELF for Linux x86_64
;
;     CURL *h = curl_easy_init()
;     curl_easy_setopt(h, CURLOPT_URL, "https://binary.golf/5/5")
;     curl_easy_perform(h)
;     exit(0)

[bits 64]

FILE_LOAD_VA: equ 0 ; we are ET_DYN, position independent
N_PROGRAM_HEADERS: equ (program_headers_end - program_headers) / 0x38
N_SECTION_HEADERS: equ (section_headers_end - section_headers) / 0x40

; ELF header
db 0x7f, 'E', 'L', 'F'           ; e_ident[EI_MAG]
db 2                             ; e_ident[EI_CLASS] = ELFCLASS64
db 1                             ; e_ident[EI_DATA] = ELFDATA2LSB
db 1                             ; e_ident[EI_VERSION] = EV_CURRENT
db 0                             ; e_ident[EI_OSABI] = ELFOSABI_NONE
dq 0                             ; e_ident[EI_ABIVERSION] + padding
dw 3                             ; e_type = ET_DYN
dw 0x3e                          ; e_machine = EM_X86_64
dd 1                             ; e_version
dq entry_point + FILE_LOAD_VA    ; e_entry
dq program_headers               ; e_phoff
dq section_headers               ; e_shoff
dd 0                             ; e_flags
dw 0x40                          ; e_ehsize
dw 0x38                          ; e_phentsize
dw N_PROGRAM_HEADERS             ; e_phnum
dw 0x40                          ; e_shentsize
dw N_SECTION_HEADERS             ; e_shnum
dw 2                             ; e_shstrndx

program_headers:
	; [0]
	dd 6                                        ; p_type  = PT_PHDR
	dd 4                                        ; p_flags = R
	dq program_headers                          ; p_offset
	dq FILE_LOAD_VA + program_headers           ; p_vaddr
	dq FILE_LOAD_VA + program_headers           ; p_paddr
	dq 0x40 * N_PROGRAM_HEADERS                 ; p_filesz
	dq 0x40 * N_PROGRAM_HEADERS                 ; p_memsz
	dq 8                                        ; p_align
	; [1]
	dd 3                                        ; p_type  = PT_INTERP
	dd 4                                        ; p_flags = R
	dq interpreter_path                         ; p_offset
	dq FILE_LOAD_VA + interpreter_path          ; p_vaddr
	dq FILE_LOAD_VA + interpreter_path          ; p_paddr
	dq interpreter_path_sz                      ; p_filesz
	dq interpreter_path_sz                      ; p_memsz
	dq 1                                        ; p_align
	; [2]
	; Make everything RWX, we don't care
	dd 1                                        ; p_type  = PT_LOAD
	dd 7                                        ; p_flags = RWE
	dq 0                                        ; p_offset
	dq FILE_LOAD_VA                             ; p_vaddr
	dq FILE_LOAD_VA                             ; p_paddr
	dq file_end                                 ; p_filesz
	dq file_end                                 ; p_memsz
	dq 0x1000                                   ; p_align
	; [3]
	dd 2                                        ; p_type  = PT_DYNAMIC
	dd 6                                        ; p_flags = RW
	dq dynamic_section                          ; p_offset
	dq FILE_LOAD_VA + dynamic_section           ; p_vaddr
	dq FILE_LOAD_VA + dynamic_section           ; p_paddr
	dq dynamic_section_end - dynamic_section    ; p_filesz
	dq dynamic_section_end - dynamic_section    ; p_memsz
	dq 8                                        ; p_align
program_headers_end:

section_headers:
	; [0]
	times 0x40 db 0 ; needed NULL section
	; [1]
	; Make everything RWX, we don't care
	dd text_section_name - string_table          ; sh_name = ".text"
	dd 1                                         ; sh_type = SHT_PROGBITS
	dq 6                                         ; sh_flags = AX
	dq FILE_LOAD_VA                              ; sh_addr
	dq 0                                         ; sh_offset
	dq file_end                                  ; sh_size
	dd 0                                         ; sh_link
	dd 0                                         ; sh_info
	dq 16                                        ; sh_addralign
	dq 0                                         ; sh_entsize
	; [2]
	dd string_table_name - string_table          ; sh_name = ".shstrtab"
	dd 3                                         ; sh_type = SHT_STRTAB
	dq 0                                         ; sh_flags
	dq FILE_LOAD_VA + string_table               ; sh_addr
	dq string_table                              ; sh_offset
	dq string_table_end - string_table           ; sh_size
	dd 0                                         ; sh_link
	dd 0                                         ; sh_info
	dq 1                                         ; sh_addralign
	dq 0                                         ; sh_entsize
	; [3]
	dd dynamic_section_name - string_table       ; sh_name = ".dynamic"
	dd 6                                         ; sh_type = SHT_DYNAMIC
	dq 3                                         ; sh_flags = WA
	dq FILE_LOAD_VA + dynamic_section            ; sh_addr
	dq dynamic_section                           ; sh_offset
	dq dynamic_section_end - dynamic_section     ; sh_size
	dd 2                                         ; sh_link -> .shstrtab
	dd 0                                         ; sh_info
	dq 8                                         ; sh_addralign
	dq 16                                        ; sh_entsize
	; [4]
	dd symbol_table_name - string_table          ; sh_name = ".dynsym"
	dd 11                                        ; sh_type = SHT_DYNSYM
	dq 2                                         ; sh_flags = A
	dq FILE_LOAD_VA + symbol_table               ; sh_addr
	dq symbol_table                              ; sh_offset
	dq symbol_table_end - symbol_table           ; sh_size
	dd 2                                         ; sh_link -> .shstrtab
	dd 1                                         ; sh_info
	dq 1                                         ; sh_addralign
	dq 24                                        ; sh_entsize
section_headers_end:

plt:
plt_resolve_stub:
	push   rax
	push   qword [rel got_plt_link_map]
	jmp    [rel got_plt_dl_runtime_resolve]

got_plt:
	dq dynamic_section
got_plt_link_map:
	dq 0
got_plt_dl_runtime_resolve:
	dq 0

entry_point:
	; handle = curl_easy_init()
	mov    eax, 1
	call   plt_resolve_stub

	; curl_easy_setopt(handle, CURLOPT_URL, "https://binary.golf/5/5")
	lea    rdx, qword [rel url]
	mov    esi, 0x2712
	mov    rdi, rax
	push   rax
	xor    eax, eax
	call   plt_resolve_stub

	; curl_easy_perform(handle)
	pop    rdi
	mov    eax, 2
	call   plt_resolve_stub

symbol_table:
	; Dummy symbol (apparently needed) also containing code for exit(0)
	mov    eax, 60
	xor    edi, edi
	syscall
	times 0x18 - ($ - symbol_table) db 0
	; ---
	dd sym_name_curl_easy_setopt - string_table   ; st_name
	db 0x12                                       ; st_info
	times 0x13 db 0                               ; st_other, st_shndx, st_value, st_size
	; ---
	dd sym_name_curl_easy_init - string_table     ; st_name
	db 0x12                                       ; st_info
	times 0x13 db 0                               ; st_other, st_shndx, st_value, st_size
	; ---
	dd sym_name_curl_easy_perform - string_table  ; st_name
	db 0x12                                       ; st_info
	times 0x13 db 0                               ; st_other, st_shndx, st_value, st_size
symbol_table_end:

dynamic_section:
	dq 0x01, dt_needed_libcurl - string_table ; DT_NEEDED "libcurl.so"
	dq 0x03, got_plt                          ; DT_PLTGOT
	dq 0x05, string_table                     ; DT_STRTAB
	dq 0x06, symbol_table                     ; DT_SYMTAB
	dq 0x17, plt_jmprel                       ; DT_JMPREL
dynamic_section_end:

string_table:
	dt_needed_libcurl:          db "libcurl.so", 0
	sym_name_curl_easy_init:    db "curl_easy_init", 0
	sym_name_curl_easy_setopt:  db "curl_easy_setopt", 0
	sym_name_curl_easy_perform: db "curl_easy_perform", 0
string_table_end:

; Actual section names aren't really needed, point them to a NUL byte
text_section_name:    equ string_table_end - 1 ; .text (but actually "")
string_table_name:    equ string_table_end - 1 ; .shstrtab (but actually "")
dynamic_section_name: equ string_table_end - 1 ; .dynamic (but actually "")
symbol_table_name:    equ string_table_end - 1 ; .dynsym (but actually "")

; RELA relocations for GOT.
; Normally these would point to GOT entries, but we don't really care this time.
plt_jmprel:
	dq interpreter_path, 0x100000007, 0  ; r_offset, r_info, r_addend
	dq interpreter_path, 0x200000007, 0  ; r_offset, r_info, r_addend
	dq interpreter_path, 0x300000007, 0  ; r_offset, r_info, r_addend
plt_jmprel_end:

url: db "https://binary.golf/5/5", 0
interpreter_path: db "/lib64/ld-linux-x86-64.so.2", 0
interpreter_path_sz: equ $ - interpreter_path

file_end:
