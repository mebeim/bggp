; @mebeim - 2024-07-09
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

; Collide e_phnum, e_shentsize, e_shnum, and e_shstrndx with program header.
; The only important thing is e_phnum = 1 (LSB of p_type) as the kernel ignores
; e_shentsize, e_shnum, and e_shstrndx.
program_headers:
	; Load whole file as RWX
	dd 1                               ; p_type  = PT_LOAD
	dd 7                               ; p_flags = RWE
	dq 0, VA, VA, END                  ; p_offset, p_vaddr, p_paddr, p_filesz

; Collide p_memsz and p_align with argv[]
; p_memsz will be 0x37004c2d ('-L\0\0\0\0\0\0'): kernel is happy to map it
; p_align can be whatever as it is ignored by the kernel
argv1:
	db '-L', 0, 0, 0, 0, 0, 0          ; p_memsz (0x00004c2d)
argv2:
	db '7f.uk', 0                      ; p_align (low 6 bytes)

argv:
	dq VA + argv0                      ; argv[0] | p_align (high 2 bytes)
	dq VA + argv1                      ; argv[1]
	; Cheap out on the final bytes, memory is zeroed out anyway. This is again
	; only possible because VA is very low (0x0 in this case).
	db VA + argv2                      ; argv[2]

END:                                   ; argv[3] = NULL
