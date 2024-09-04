; @mebeim - 2024-07-06
;
; 32-bit ET_EXEC ELF for Linux x86
;
;     execve("/bin/curl", argv, NULL)
;
; NOTE: Expects URL as command line argument!

[bits 32]

VA: equ 0x1337000

db 0x7f, 'ELF'                         ; e_ident[EI_MAG]

; Stuff code here since the kernel ignores the rest of e_ident[]
entry:
	mov al, 0xb                        ; e_ident[EI_CLASS..EI_ABIVERSION] + pad
	mov ebx, VA + curl_path
	pop ecx
	mov ecx, esp
	int 0x80
	times 12 - ($ - entry) db 0

	dw 2                               ; e_type = ET_EXEC
	dw 3                               ; e_machine = EM_386
	dd 1                               ; e_version = EV_CURRENT
	dd VA + entry                      ; e_entry
	dd program_headers                 ; e_phoff

; Stuff execve path here since the kernel also ignores these fields
curl_path:
	db '/bin/curl', 0                  ; e_shoff, e_flags, e_ehsize
	times 10 - ($ - curl_path) db 0

	dw 0x20                            ; e_phentsize

; Collide e_phnum, e_shentsize, e_shnum, and e_shstrndx with program header.
; Here e_phnum = 1 (LSB of p_type) and the rest is ignored by the kernel.
program_headers:
	dd 1                               ; p_type = PT_LOAD | e_phnum, e_shentsize
	dd 0                               ; p_offset         | e_shnum, e_shstrndx
	dd VA, VA, END, END                ; p_vaddr, p_paddr, p_filesz, p_memsz

	; Add a signature just for fun.
	;
	; p_flags will be 0x6562656d ('mebe'): kernel only cares about bits 0-2,
	; which in this case are 0b101 == PF_R|PF_X
	;
	; p_align can be whatever as it is ignored by the kernel
	db 'mebeim',0,0                    ; p_flags, p_align

END:
