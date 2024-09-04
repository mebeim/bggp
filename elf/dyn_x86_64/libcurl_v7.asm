; @mebeim - 2024-06-28
;
; 64-bit ET_DYN ELF for Linux x86_64
;
;     CURL *h = curl_easy_init()
;     curl_easy_setopt(h, CURLOPT_URL, "https://binary.golf/5/5")
;     curl_easy_perform(h)
;     exit(0)

[bits 64]

VA:                  equ 0 ; We are ET_DYN, position independent
FILE_SIZE:           equ file_end
N_PROGRAM_HEADERS:   equ (program_headers_end_plus1 - 1 - program_headers) / 0x38
DYNAMIC_SECTION_SZ:  equ dynamic_section_end - dynamic_section
STRING_TABLE_SZ:     equ string_table_end - string_table
INTERPRETER_PATH_SZ: equ interpreter_path_end - interpreter_path

CURL_EASY_INIT_STROFF:    equ sym_name_curl_easy_init - string_table
CURL_EASY_SETOPT_STROFF:  equ sym_name_curl_easy_setopt - string_table
CURL_EASY_PERFORM_STROFF: equ sym_name_curl_easy_perform - string_table
DT_NEEDED_LIBCURL_STROFF: equ dt_needed_libcurl - string_table

; ELF header
db 0x7f, 'ELF'                                  ; e_ident[EI_MAG]

; Stuff some code here since the kernel literally ignores the rest of e_ident[]
plt_resolve_stub:
	push   rax
	push   qword [rel got_plt_link_map]
	jmp    plt_resolve_stub_2
	times 12 - ($ - plt_resolve_stub) db 0

dw 3                                            ; e_type = ET_DYN
dw 0x3e                                         ; e_machine = EM_X86_64
dd 1                                            ; e_version
dq VA + entry                                   ; e_entry
dq program_headers                              ; e_phoff

; Rest of the code for plt_resolve_stub above
plt_resolve_stub_2:
	jmp    [rel got_plt_dl_runtime_resolve]     ; e_shoff
	times 8 - ($ - plt_resolve_stub_2) db 0

dd 0                                            ; e_flags
dw 0x40                                         ; e_ehsize
dw 0x38                                         ; e_phentsize
; Surprisingly enough, we can get away with no section headers at all, and we
; can also collide e_phnum, e_shentsize, e_shnum, and e_shstrndx with the first
; program header!

program_headers:
; phdrs[0]
; Unsure why this phdr is needed to be honest...
	dd 6                                        ; phdrs[0].p_type  = PT_PHDR  | e_phnum, e_shentsize
	dd 4                                        ; phdrs[0].p_flags = R        | e_shnum, e_shstrndx
; ELF header ends here
	dq program_headers                          ; phdrs[0].p_offset
	dq VA + program_headers                     ; phdrs[0].p_vaddr
	; These 4 are ignored, could be used for something else...
	dq VA + program_headers                     ; phdrs[0].p_paddr
	dq 0x40 * N_PROGRAM_HEADERS                 ; phdrs[0].p_filesz
	dq 0x40 * N_PROGRAM_HEADERS                 ; phdrs[0].p_memsz
	dq 8                                        ; phdrs[0].p_align

; phdrs[1]
	dd 3                                        ; phdrs[1].p_type  = PT_INTERP
	dd 4                                        ; phdrs[1].p_flags = R
	dq interpreter_path                         ; phdrs[1].p_offset
	dq VA + interpreter_path                    ; phdrs[1].p_vaddr
	dq VA + interpreter_path                    ; phdrs[1].p_paddr
	dq INTERPRETER_PATH_SZ                      ; phdrs[1].p_filesz
	dq INTERPRETER_PATH_SZ                      ; phdrs[1].p_memsz
	dq 1                                        ; phdrs[1].p_align

; phdrs[2]
	; Load whole file as RWX
	dd 1                                        ; phdrs[2].p_type  = PT_LOAD
	dd 7                                        ; phdrs[2].p_flags = RWE
	dq 0                                        ; phdrs[2].p_offset
	dq VA                                       ; phdrs[2].p_vaddr
	dq VA                                       ; phdrs[2].p_paddr
	dq FILE_SIZE                                ; phdrs[2].p_filesz
	dq FILE_SIZE                                ; phdrs[2].p_memsz
	dq 0x1000                                   ; phdrs[2].p_align

; phdrs[3]
	dd 2                                        ; phdrs[3].p_type  = PT_DYNAMIC
	dd 6                                        ; phdrs[3].p_flags = RW
	dq dynamic_section                          ; phdrs[3].p_offset
	dq VA + dynamic_section                     ; phdrs[3].p_vaddr

; Stuff .got.plt here inside last program header
got_plt:
	dq VA + dynamic_section                     ; phdrs[3].p_paddr
got_plt_link_map:
	dq dynamic_section_end - dynamic_section    ; phdrs[3].p_filesz
got_plt_dl_runtime_resolve:
	dq dynamic_section_end - dynamic_section    ; phdrs[3].p_memsz

; Stuff entry point code and symbol table start here too
entry:
symbol_table:
; syms[0]
; First symbol is dummy. Unsure why it is needed. Stuff some code in it.
	; handle = curl_easy_init()
	xor    eax, eax                             ; phdrs[3].p_align | syms[0].st_name
	inc    eax
	call   plt_resolve_stub
	; no space left
	times 9 - ($ - entry) nop
program_headers_end_plus1:

	; curl_easy_setopt(handle, CURLOPT_URL, "https://binary.golf/5/5")
	lea    rdx, qword [rel url]
	mov    esi, 0x2712
	jmp    code1
	; 1 byte of space left
	times 0x18 - ($ - symbol_table) nop

; Actual symbols start here (when a PLT entry does `push 0` it means syms[1])
; syms[1]
	dd CURL_EASY_SETOPT_STROFF                  ; syms[1].st_name
	db 0x12                                     ; syms[1].st_info

code1:                                          ; syms[1].{st_other,st_shndx,st_value,st_size}
	; (cont'd) curl_easy_setopt
	mov    rdi, rax
	push   rax
	xor    eax, eax
	call   plt_resolve_stub

	; curl_easy_perform(handle)
	pop    rdi
	mov    eax, 2
	jmp    code2
	; no space left
	times 0x13 - ($ - code1) nop

; syms[2]
	dd CURL_EASY_INIT_STROFF                    ; syms[2].st_name
	db 0x12                                     ; syms[2].st_info

code2:                                          ; syms[2].{st_other,st_shndx,st_value,st_size}
	; (cont'd) curl_easy_perform
	call   plt_resolve_stub

	; exit(0)
	mov    eax, 60
	xor    edi, edi
	syscall
	; 5 bytes of space left
	times 0x13 - ($ - code2) nop

; syms[3]
	dd CURL_EASY_PERFORM_STROFF                 ; syms[3].st_name
	; Cheap out on the final bytes, we can collide with the strings below
symbol_table_end:

url:
	db "https://binary.golf/5/5", 0             ; syms[3].{st_other,st_shndx,st_value,st_size}
interpreter_path:
	db "/lib64/ld-linux-x86-64.so.2", 0
interpreter_path_end:

dynamic_section:
	dq 0x01, DT_NEEDED_LIBCURL_STROFF           ; DT_NEEDED "libcurl.so"
	dq 0x03, got_plt                            ; DT_PLTGOT
	dq 0x05, string_table                       ; DT_STRTAB
	dq 0x06, symbol_table                       ; DT_SYMTAB
	dq 0x17, plt_jmprel                         ; DT_JMPREL
dynamic_section_end:

string_table:
	dt_needed_libcurl:          db "libcurl.so", 0
	sym_name_curl_easy_init:    db "curl_easy_init", 0
	sym_name_curl_easy_setopt:  db "curl_easy_setopt", 0
	sym_name_curl_easy_perform: db "curl_easy_perform", 0
string_table_end:

; RELA relocations for GOT.
; Normally these would point to GOT entries, but we don't really care this time.
plt_jmprel:
	dq interpreter_path, 0x100000007, 0         ; rels[0]
	dq interpreter_path, 0x200000007, 0         ; rels[1]
	dq interpreter_path                         ; rels[2].r_offset
	dd 7                                        ; rels[2].r_info bytes 0..3
	db 3                                        ; rels[2].r_info byte 4
	; Cheap out on the final bytes, memory is zeroed out anyway
plt_jmprel_end:                                 ; rels[2].r_info bytes 5..7
file_end:                                       ; rels[2].r_addend
