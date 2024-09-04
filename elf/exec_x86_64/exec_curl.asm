; @mebeim - 2024-06-28
;
; 64-bit ET_EXEC ELF for Linux x86_64
;
;     execve("/bin/curl", ["/bin/curl", "https://binary.golf/5/5"], NULL)
;
; NOTE: loads at vaddr 0x0, needs /proc/sys/vm/mmap_min_addr set to 0

[bits 64]

; /proc/sys/vm/mmap_min_addr NEEDS TO BE 0
VA: equ 0

db 0x7f, 'ELF'                         ; e_ident[EI_MAG]

entry:                                 ; e_ident[EI_CLASS] ... e_ident[EI_ABIVERSION] + pad
	; We are loading into DIL and SIL to get shorter instructions. This can only
	; work if VA is very low (0x0 in this case).
	mov dil, VA + argv0
	mov sil, VA + argv
	mov al, 0x3b
	syscall
	times 12 - ($ - entry) db 0

	dw 2                               ; e_type = ET_EXEC
	dw 0x3e                            ; e_machine = EM_X86_64
	dd 1                               ; e_version
	dq VA + entry                      ; e_entry
	dq program_headers                 ; e_phoff

argv0:
	db '/bin/curl', 0                  ; e_shoff, e_flags
	times 12 - ($ - argv0) db 0

	dw 0x40                            ; e_ehsize
	dw 0x38                            ; e_phentsize
	dw 1                               ; e_phnum

argv1:                                 ; e_shentsize, e_shnum, e_shstrndx
	db 'https:/binary.golf/5/5', 0     ; Don't need the second '/' in "https://"

program_headers:
	; Load whole file as RWX
	dd 1                               ; p_type  = PT_LOAD
	dd 7                               ; p_flags = RWE
	dq 0, VA, VA, END, END             ; p_offset, p_vaddr, p_paddr, p_filesz, p_memsz

argv:
	dq VA + argv0                      ; p_align
	; Cheap out on the final bytes, memory is zeroed out anyway. This is again
	; only possible because VA is very low (0x0 in this case).
	db VA + argv1

END:
