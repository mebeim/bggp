; @mebeim - 2024-06-28
;
; 64-bit ET_EXEC ELF for Linux x86_64
;
;     execve("/bin/curl", argv, NULL)
;
; NOTE: Expects URL as command line argument!

[bits 64]

VA: equ 0x1337000

db 0x7f, 'ELF'                         ; e_ident[EI_MAG]

entry:                                 ; e_ident[EI_CLASS..EI_ABIVERSION] + pad
	mov al, 0x3b
	mov edi, VA + curl_path
	pop rsi
	jmp ahead
	times 12 - ($ - entry) db 0

	dw 2                               ; e_type = ET_EXEC
	dw 0x3e                            ; e_machine = EM_X86_64
	dd 1                               ; e_version
	dq VA + entry                      ; e_entry
	dq program_headers                 ; e_phoff

curl_path:
	db '/bin/curl', 0                  ; e_shoff, e_flags
	times 12 - ($ - curl_path) db 0

	dw 0x40                            ; e_ehsize
	dw 0x38                            ; e_phentsize

program_headers:
	dd 1                               ; p_type = PT_LOAD | e_phnum, e_shentsize
	dd 7                               ; p_flags = RWE    | e_shnum, e_shstrndx
	dq 0, VA, VA, END, END             ; p_offset, p_vaddr, p_paddr, p_filesz, p_memsz

ahead:
	mov rsi, rsp                       ; p_align
	syscall
	times 8 - ($ - ahead) db 0

END:
