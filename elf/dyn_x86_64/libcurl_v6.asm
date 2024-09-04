; @mebeim - 2024-06-27
;
; 64-bit ET_DYN ELF for Linux x86_64
;
;     CURL *h = curl_easy_init()
;     curl_easy_setopt(h, CURLOPT_URL, "https://binary.golf/5/5")
;     curl_easy_perform(h)
;     exit(0)

[bits 64]

FILE_LOAD_VA:        equ 0 ; We are ET_DYN, position independent
FILE_SIZE:           equ file_end
N_PROGRAM_HEADERS:   equ (program_headers_end - program_headers) / 0x38
DYNAMIC_SECTION_SZ:  equ dynamic_section_end - dynamic_section
STRING_TABLE_SZ:     equ string_table_end - string_table
INTERPRETER_PATH_SZ: equ interpreter_path_end - interpreter_path

CURL_EASY_INIT_STROFF:    equ sym_name_curl_easy_init - string_table
CURL_EASY_SETOPT_STROFF:  equ sym_name_curl_easy_setopt - string_table
CURL_EASY_PERFORM_STROFF: equ sym_name_curl_easy_perform - string_table
DT_NEEDED_LIBCURL_STROFF: equ dt_needed_libcurl - string_table

; ELF header
db 0x7f, 'E', 'L', 'F'   ; e_ident[EI_MAG]

; Stuff some code here since the kernel literally ignores the rest of e_ident[]
plt_resolve_stub:
	push   rax
	push   qword [rel got_plt_link_map]
	jmp    plt_resolve_stub_2
	times 12 - ($ - plt_resolve_stub) db 0

dw 3                     ; e_type = ET_DYN
dw 0x3e                  ; e_machine = EM_X86_64
dd 1                     ; e_version
dq FILE_LOAD_VA + entry  ; e_entry
dq program_headers       ; e_phoff
dq 0                     ; e_shoff
dd 0                     ; e_flags
dw 0x40                  ; e_ehsize
dw 0x38                  ; e_phentsize
; Surprisingly enough, we can get away with no section headers at all, and we
; can also collide e_phnum, e_shentsize, e_shnum, and e_shstrndx with the first
; program header!

program_headers:
; [0]
	dd 6                                        ; p_type  = PT_PHDR  | e_phnum, e_shentsize
	dd 4                                        ; p_flags = R        | e_shnum, e_shstrndx
; ELF header ends here
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
	dq INTERPRETER_PATH_SZ                      ; p_filesz
	dq INTERPRETER_PATH_SZ                      ; p_memsz

; Rest of the code for plt_resolve_stub above
plt_resolve_stub_2:
	jmp    [rel got_plt_dl_runtime_resolve]     ; p_align
	times 8 - ($ - plt_resolve_stub_2) db 0

; [2]
	; Load whole file as RWX
	dd 1                                        ; p_type  = PT_LOAD
	dd 7                                        ; p_flags = RWE
	dq 0                                        ; p_offset
	dq FILE_LOAD_VA                             ; p_vaddr
	dq FILE_LOAD_VA                             ; p_paddr
	dq FILE_SIZE                                ; p_filesz
	dq FILE_SIZE                                ; p_memsz
	dq 0x1000                                   ; p_align

; [3]
	dd 2                                        ; p_type  = PT_DYNAMIC
	dd 6                                        ; p_flags = RW
	dq dynamic_section                          ; p_offset
	dq FILE_LOAD_VA + dynamic_section           ; p_vaddr

; Stuff .got.plt here inside last program header
got_plt:
	dq FILE_LOAD_VA + dynamic_section           ; p_paddr
got_plt_link_map:
	dq dynamic_section_end - dynamic_section    ; p_filesz
got_plt_dl_runtime_resolve:
	dq dynamic_section_end - dynamic_section    ; p_memsz
; Stuff entry point code here too
entry:                                          ; p_align
	; handle = curl_easy_init()
	xor    eax, eax
	jmp    code0
	times 8 - ($ - entry) db 0
program_headers_end:

symbol_table:
; First symbol is dummy but seems needed (unsure why). Stuff some code into it.
code0:
	; (cont'd) curl_easy_init
	inc    eax
	call   plt_resolve_stub

	; curl_easy_setopt(handle, CURLOPT_URL, "https://binary.golf/5/5")
	lea    rdx, qword [rel url]
	mov    esi, 0x2712
	mov    rdi, rax

	jmp code1
	times 0x18 - ($ - symbol_table) db 0

; Actual symbols start here
; [0]
	dd CURL_EASY_SETOPT_STROFF   ; st_name
	db 0x12                      ; st_info

code1:                           ; st_other, st_shndx, st_value, st_size
	; (cont'd) curl_easy_setopt
	push   rax
	xor    eax, eax
	call   plt_resolve_stub

	; curl_easy_perform(handle)
	pop    rdi
	mov    eax, 2
	jmp code2
	; 3 bytes still available here!
	times 0x13 - ($ - code1) db 0

; [1]
	dd CURL_EASY_INIT_STROFF     ; st_name
	db 0x12                      ; st_info

code2:                           ; st_other, st_shndx, st_value, st_size
	; (cont'd) curl_easy_perform
	call   plt_resolve_stub

	; exit(0)
	mov    eax, 60
	xor    edi, edi
	syscall
	; 5 bytes still available here!
	times 0x13 - ($ - code2) db 0

; [2]
	dd CURL_EASY_PERFORM_STROFF ; st_name
	; Cheap out on the final bytes, we can collide with the strings below
symbol_table_end:

url:              db "https://binary.golf/5/5", 0
interpreter_path: db "/lib64/ld-linux-x86-64.so.2", 0
interpreter_path_end:

dynamic_section:
	dq 0x01, DT_NEEDED_LIBCURL_STROFF ; DT_NEEDED "libcurl.so"
	dq 0x03, got_plt                  ; DT_PLTGOT
	dq 0x05, string_table             ; DT_STRTAB
	dq 0x06, symbol_table             ; DT_SYMTAB
	dq 0x17, plt_jmprel               ; DT_JMPREL
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
	dq interpreter_path, 0x100000007, 0 ; r_offset, r_info, r_addend
	dq interpreter_path, 0x200000007, 0 ; r_offset, r_info, r_addend
	dq interpreter_path ; r_offset
	dd 7 ; r_info (low 4 bytes)
	db 3 ; r_info (byte 5)
	; Cheap out on the final bytes, memory is zeroed out anyway
plt_jmprel_end:

file_end:
