; @mebeim - 2024-07-06
;
; 32-bit ET_EXEC ELF for Linux x86
;
;     execve("/bin/curl", ["/bin/curl", "-L", "7f.uk", NULL], NULL)
;
; NOTE: loads at vaddr 0x0, needs /proc/sys/vm/mmap_min_addr set to 0

[bits 32]

; /proc/sys/vm/mmap_min_addr NEEDS TO BE 0
VA: equ 0

db 0x7f, 'ELF'                         ; e_ident[EI_MAG]

; Stuff code here since the kernel ignores the rest of e_ident[]
entry:
	; We are loading into BL and CL to get shorter instructions. This can only
	; work if VA is very low (0x0 in this case).
	mov bl, VA + argv0
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
; The only important thing is e_phnum = 1 (LSB of p_type) as the kernel ignores
; e_shentsize, e_shnum, and e_shstrndx.
program_headers:
	dd 1                               ; p_type = PT_LOAD | e_phnum, e_shentsize
	dd 0                               ; p_offset         | e_shnum, e_shstrndx
	dd VA, VA, END                     ; p_vaddr, p_paddr, p_filesz

; Collide p_memsz, p_flags, and p_align with argv[]
;
; p_memsz will be 0x37004c2d ('-L\x007'): kernel is happy to map 880 MiB
;
; p_flags will be 0x2e756b66 ('f.uk'): kernel only cares about bits 0-2, which
; in this case are 0b110 == PF_R|PF_W. We lack PF_X, however we also lack a
; PT_GNU_STACK program header, so as far as the kernel is concerned PF_R implies
; PF_X and everything will be mapped as executable. See "has NX, ia32" here:
; https://elixir.bootlin.com/linux/v6.9/source/arch/x86/include/asm/elf.h#L274
;
; p_align can be whatever as it is ignored by the kernel
argv1:
	db '-L', 0                         ; p_memsz (low 3 bytes)
argv2:
	db '7f.uk', 0                      ; p_memsz (MSB), p_flags, p_align (LSB)

argv:
	dd VA + argv0                      ; argv[0] | p_align (top 3 bytes)
	dd VA + argv1                      ; argv[1]
	; Cheap out on the final bytes, memory is zeroed out anyway. This is again
	; only possible because VA is very low (0x0 in this case).
	db VA + argv2                      ; argv[2]

END:                                   ; argv[3] = NULL
