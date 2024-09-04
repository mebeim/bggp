; @mebeim - 2024-07-06
;
; 32-bit ET_EXEC ELF for Linux x86
;
;     execve("/bin/curl", ["/bin/curl", "https://binary.golf/5/5"], NULL)
;
; NOTE: loads at vaddr 0x0, needs /proc/sys/vm/mmap_min_addr set to 0

[bits 32]

; /proc/sys/vm/mmap_min_addr NEEDS TO BE 0
VA: equ 0

db 0x7f, 'ELF'                         ; e_ident[EI_MAG]

; Stuff code here since the kernel literally ignores the rest of e_ident[]
entry:
	mov bl, VA + argv0                 ; e_ident[EI_CLASS..EI_ABIVERSION] + pad
	mov cl, VA + argv
	mov al, 0xb
	int 0x80
	times 12 - ($ - entry) db 0

	dw 2                               ; e_type = ET_EXEC
	dw 3                               ; e_machine = EM_X86_64
	dd 1                               ; e_version
	dd VA + entry                      ; e_entry
	dd program_headers                 ; e_phoff

; Stuff execve path here since the kernel also ignores these fields
argv0:
	db '/bin/curl', 0                  ; e_shoff, e_flags, e_ehsize
	times 10 - ($ - argv0) db 0

	dw 0x20                            ; e_phentsize

; Collide e_phnum, e_shentsize, e_shnum, and e_shstrndx with program header.
; Here e_phnum = 1 (LSB of p_type) and the rest is ignored by the kernel.
program_headers:
	dd 1                               ; p_type = PT_LOAD | e_phnum, e_shentsize
	dd 0                               ; p_offset         | e_shnum, e_shstrndx
	dd VA, VA, END, END                ; p_vaddr, p_paddr, p_filesz, p_memsz

; Collide p_flags and p_align with argv[]
;
; p_flags will be 0x74746805 ('\x05htt'): kernel only cares about bits 0-2,
; which in this case are 0b101 == PF_R|PF_X
;
; p_align can be whatever as it is ignored by the kernel
	db 5                               ; p_flags (low byte)
argv1:
	db 'https:/binary.golf/5/5', 0     ; p_flags (top 3 bytes), p_align
                                       ; Don't need the second '/' in "https://"

argv:
	dd VA + argv0                      ; argv[0]
	; Cheap out on the final bytes, memory is zeroed out anyway
	db VA + argv1                      ; argv[1]

END:                                   ; argv[2] = NULL
