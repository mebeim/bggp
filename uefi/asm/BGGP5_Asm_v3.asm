;
; @mebeim - 2024-07-20
;
; UEFI application that downloads the file at https://binary.golf/5/5 and
; displays its contents on the screen. Written for and tested on EDK II OVMF.
;
; Several parts of the DOS/PE/section header (labeled `HOLEn`) are ignored by
; the EDK II loader and are simply filled with zeroes. They will be used to
; store code in the next iteration.
;
; Code is now optimized for size as much as possible. Next (final) step is to
; move parts of it filling the holes in the headers to save space.
;
; Changes/improvements from v2:
;
;   - Optimize code for size as much as possible.
;   - Identify 2 more holes in file headers that can be filled with code.
;   - Allocate space for data structures on the stack instead of embedding them
;     in the file, which also eliminates the need for runtime relocations.
;   - Embed URL as ASCII string instead of UTF-16 and convert to UTF-16 at
;     runtime to save space.
;   - Get rid of saved local variables avoiding RSP-relative LEAs/MOVs.
;   - Re-use callee-saved RBX to hold HttpProtocol after we are done with
;     BootServices to save some LEAs.
;   - Use callee-saved RDI to store data pointers: only use one LEA in total.
;   - Break 16-byte stack alignment, EDK II code does not care.
;   - Let EDK II loader zero-out memory past end of file by setting
;     Section.VirtualSize = Section.SizeOfRawData + 0x400 thus saving a final
;     zero byte for a string constant.
;
[bits 64]

;====[ CONSTANTS & MACROS ]=====================================================

; Constants and struct offsets from EDK II source
SUBSYSTEM_EFI_APPLICATION                              equ 0xa
STRUCT_EFI_BOOT_SERVICES.OffHandleProtocol             equ 0x98
STRUCT_EFI_BOOT_SERVICES.OffLocateProtocol             equ 0x140
STRUCT_EFI_HTTP_PROTOCOL.OffConfigure                  equ 0x8
STRUCT_EFI_HTTP_PROTOCOL.OffRequest                    equ 0x10
STRUCT_EFI_HTTP_PROTOCOL.OffResponse                   equ 0x20
STRUCT_EFI_SERVICE_BINDING_PROTOCOL.OffCreateChild     equ 0x0
STRUCT_EFI_SYSTEM_TABLE.OffBootServices                equ 0x60

; We expect exactly 58 bytes from https://binary.golf/5/5:
; 'Another #BGGP5 download!! @binarygolf https://binary.golf\n'
EXPECTED_RESPONSE_SIZE equ 58

; ASCII URL size (including NUL terminator) for easier math later on.
URL_SIZE equ utf16UrlMinus1 + 1 - asciiUrl

; Macro to pack a GUID into memory.
%macro EFI_GUID 4
    dd %1
    dw %2, %3
    dq %4
%endmacro

; Macro to ensure we are filling exactly as many bytes as needed padding with
; zeroes. This also errors out if we exceed the specified size, which is nice.
%macro PAD_CHECK 2
    times %2 - ($ - %1) db 0
%endmacro


;=====[ START OF FILE ]=========================================================
;                                        ;                       | DOS HEADER
;                                        ;                       +--------------
db 'MZ'                                  ; PE HEADER             | e_magic
dw 0x100                                 ; ----------------------+ e_cblp
db 'PE', 0, 0                            ; Signature             | e_cp, e_crlc
dw 0x8664                                ; Machine               | e_cparhdr
dw 1                                     ; NumberOfSections      | e_minalloc
;_______________________________________________________________________________

HOLE0:
    PAD_CHECK HOLE0, 12
;_______________________________________________________________________________
;
    dw pe_opt_header_end - pe_opt_header ; SizeOfOptionalHeader  | e_lsarlc
    dw 0x0206                            ; Characteristics       | e_ovno
;________________________________________;_______________________|______________
pe_opt_header:                           ;                       |
    dw 0x20b                             ; Magic (PE32+)         | e_res[0]
;_______________________________________________________________________________

HOLE1:
    PAD_CHECK HOLE1, 14
;_______________________________________________________________________________
;
; At first glance it may look like BaseOfCode, BaseOfData and ImageBase are
; usable. The EDK II loader indeed does not care about their value, but
; overwrites them with actual addresses, so they cannot be used.
;
    dd ENTRY                             ; AddressOfEntryPoint   | e_res2[2:4]
    db 'BGGP'                            ; BaseOfCode            | e_res2[4:6]
    db 0, 'MEBEIM', 0                    ; ImageBase             | e_res2[6:10]
    dd 4                                 ; SectionAlignment      | e_lfanew
    dd 4                                 ; FileAlignment         o--------------
;_______________________________________________________________________________

HOLE2:
    PAD_CHECK HOLE2, 16
;_______________________________________________________________________________
;
    dd 0x1000                            ; SizeOfImage
    dd headers_end                       ; SizeOfHeaders
;_______________________________________________________________________________

HOLE3:
    PAD_CHECK HOLE3, 4
;_______________________________________________________________________________
;
; Subsystem is checked, we can use 0xA (EFI_APPLICATION).
;
    dw SUBSYSTEM_EFI_APPLICATION         ; Subsystem
;_______________________________________________________________________________

HOLE4:
    PAD_CHECK HOLE4, 38
;_______________________________________________________________________________
;
    dd 6                                 ; NumberOfRvaAndSizes (need 6)
;_______________________________________________________________________________
;
; EFI_IMAGE_DIRECTORY_ENTRY_{EXPORT,IMPORT,RESOURCE,EXCEPTION} can be whatever.
;
HOLE5:
    PAD_CHECK HOLE5, 32
;_______________________________________________________________________________
;
; These two are needed and checked. We cannot overlap the end of the PE OPT
; header with the start of the section header (i.e. pe_opt_header_end label
; must come before section_header label).
;add
    dq 0                                 ; EFI_IMAGE_DIRECTORY_ENTRY_SECURITY
    dq 0                                 ; EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC
pe_opt_header_end:
;_______________________________________________________________________________
section_header:
;
; We can stuff some code inside the section Name[], which is ignored
;
HOLE6:
    PAD_CHECK HOLE6, 8
;_______________________________________________________________________________
;
; Here we set VirtualSize = SizeOfRawData + 0x400 to let the loader zero-out
; memory past the end of the file for us. This saves 1 zero byte at the end of
; the file for the asciiUrl string.
;
    dd END - ENTRY + 0x400 ; VirtualSize
    dd ENTRY               ; VirtualAddress
    dd END - ENTRY         ; SizeOfRawData
    dd ENTRY               ; PointerToRawData
;_______________________________________________________________________________
;
; PointerTo{Relocations,Linenumbers}, NumberOf{Relocations,Linenumbers} and
; Characteristics can be whatever.
;
HOLE7:
    PAD_CHECK HOLE7, 16
;_______________________________________________________________________________
headers_end:
;
;======[ ENTRY POINT ]==========================================================
;
; We cannot overlap the section headers with the entry point. The former must
; come first entirely. We can however jump back into section/PE headers.
;
ENTRY:
    ; Save callee-saved registers to avoid breaking things.
    push   rbx
    push   rsi
    push   rdi

    ; Allocate space for HttpServiceBinding (used for gBS->LocateProtocol()).
    push   rax

    ; ^^^ Instructions above this comment will be removed in the final version.

    ; Use callee-saved RBX to hold BootServices and advance it by 0x78 to save
    ; 3 bytes on the encoding of a CALL [RBX + OFF] later. The ADD here is also
    ; 3 bytes: two 3-byte insns are more flexible than one 6-byte insn. This
    ; will be useful for the final version where we'll fill header holes holes
    ; with code.
    mov    ebx, [rdx + STRUCT_EFI_SYSTEM_TABLE.OffBootServices]
    add    ebx, 0x78

    ; Use callee-saved RDI to point to data (at the end of the file) so we can
    ; simply advance it later avoiding additional LEAs, which are quite long.
    lea    edi, [rel gEfiHttpServiceBindingProtocolGuid]

    ; Locate the HttpServiceBinding protocol. Pass as stack pointer for output.
    ;
    ; gBS->LocateProtocol(&gEfiHttpServiceBindingProtocolGuid, NULL,
    ;                     &HttpServiceBinding);
    mov    ecx, edi
    xor    edx, edx
    mov    r8, rsp ; &HttpServiceBinding
    call   [rbx - 0x78 + STRUCT_EFI_BOOT_SERVICES.OffLocateProtocol]

    ; Each time we make a call, assuming it succeeds, RAX will be set to 0
    ; (EFI_SUCCESS). Most of the following code makes this assumption to save
    ; XOR EAX,EAX instructions. The first example is right here where we do a
    ; PUSH RAX to push a NULL ptr.

    ; Create child handle. Pass RDI data pointer for output. This will
    ; overwrite gEfiHttpServiceBindingProtocolGuid, but we already used it so
    ; it's fine.
    ;
    ; HttpChildHandle = NULL;
    ; HttpServiceBinding->CreateChild(HttpServiceBinding, &HttpChildHandle);
    mov    ecx, [rsp]
    push   rax
    mov    edx, esp ; &HttpChildHandle
    call   [rcx + STRUCT_EFI_SERVICE_BINDING_PROTOCOL.OffCreateChild]

    ; Finally get ahold of the HTTP protocol. Pass RDI data pointer for output.
    ; This will overwrite gEfiHttpProtocolGuid, but only after reading it to
    ; resolve the protocol, so it's fine.
    ;
    ; gBS->HandleProtocol(HttpChildHandle, &gEfiHttpProtocolGuid, &HttpProtocol)
    mov    ecx, [rsp]
    add    edi, gEfiHttpProtocolGuid - gEfiHttpServiceBindingProtocolGuid
    mov    edx, edi
    mov    r8, rdi
    call   [rbx - 0x78 + STRUCT_EFI_BOOT_SERVICES.OffHandleProtocol]

    ; RBX = HttpProtocol from now on (don't need BootServices anymore)
    mov    ebx, [rdi]

    ; Allocate these overlapping structs (since HttpVersion11 == 1 == TRUE).
    ;
    ; union {
    ;     EFI_HTTP_CONFIG_DATA Cfg;
    ;     EFI_HTTPv4_ACCESS_POINT Ap;
    ; } CfgAndAp = {
    ;     .Cfg.HttpVersion        = HttpVersion11, // Also Ap.UseDefaultAddress
    ;     .Cfg.TimeOutMillisec    = 0,
    ;     .Cfg.LocalAddressIsIPv6 = FALSE,
    ;     .Cfg.IPv4Node           = &CfgAndAp.Ap   // Points to itself
    ; };
    push   rsp
    push   rax
    inc    eax
    push   rax

    ; HttpProtocol->Configure(HttpProtocol, &CfgAndAp.Cfg);
    mov    ecx, ebx
    mov    edx, esp
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffConfigure]

    ; Setup RSI/RDI/RCX for upcoming LODSB/STOSW/LOOP.
    add    edi, asciiUrl - gEfiHttpProtocolGuid
    mov    esi, edi
    xor    ecx, ecx
    mov    cl, utf16UrlMinus1 + 1 - asciiUrl
    add    edi, ecx

    ; Convert URL from ASCII to UTF-16-LE using a nice LODSB + STOSW loop. Less
    ; space is used converting the URL at runtime than embedding it directly as
    ; UTF-16.
    cld
.urlconv:
    lodsb
    stosw
    loop   .urlconv

    ; Allocate EFI_HTTP_REQUEST_DATA and save a pointer to it in RCX for later.
    ;
    ; RAX = 0 at the end of the above loop because asciiUrl is NUL-terminated
    ; and the last LODSB reads 0. This saves a XOR EAX,EAX.
    ;
    ; EFI_HTTP_REQUEST_DATA ReqData = {
    ;     .Method = HttpMethodGet,              // 0x0
    ;     .Url    = L"https://binary.golf/5/5"
    ; }
    push   rsi
    push   rax
    mov    ecx, esp

    ; Allocate EFI_HTTP_HEADER and save a pointer to it in RDX for later.
    ;
    ; EFI_HTTP_HEADER Header = {
    ;     .FieldName  = "Host",
    ;     .FieldValue = "binary.golf"
    ; };
    sub    edi, utf16UrlMinus1 + 1 + 2 * URL_SIZE - strHostHeaderValue
    push   rdi
    add    edi, strHostHeaderName - strHostHeaderValue
    push   rdi
    mov    edx, esp

    ; Allocate EFI_HTTP_MESSAGE. Since we are doing a GET and we set
    ; Message.BodyLength = 0, overlap the ignored Message.Body field with the
    ; previously pushed Header.FieldName to save a PUSH.
    ;
    ; Save RSI = &Message.BodyLength to modify and re-use the struct later.
    ;
    ; EFI_HTTP_MESSAGE Message = {
    ;     .Data.Request = &ReqData,
    ;     .HeaderCount  = 1UL,
    ;     .Headers      = &Header,
    ;     .BodyLength   = 0UL,
    ;     .Body         = "Host"    // Overlaps with Header.FieldName
    ; };
    push   rax       ; BodyLength
    mov    esi, esp  ; RSI = &Message.BodyLength
    push   rdx       ; Headers
    inc    eax
    push   rax       ; HeaderCount
    push   rcx       ; Data.Request

    ; Allocate EFI_HTTP_TOKEN for request. Technically .Event should be NULL,
    ; but 1 works anyway and saves us a DEC RAX. The .Status field is unchecked
    ; so it can be any value.
    ;
    ; EFI_HTTP_TOKEN Token = {
    ;     .Event   = (void *)1,
    ;     .Status  = 1UL,
    ;     .Message = &Message
    ; };
    push   rsp
    push   rax
    push   rax

    ; HttpProtocol->Request(HttpProtocol, &Token);
    mov    ecx, ebx
    mov    edx, esp
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffRequest]

    ; Reuse the same EFI_HTTP_TOKEN and EFI_HTTP_MESSAGE structs for the call
    ; to HttpProtocol->Response(). The token does not need any change. We only
    ; need to set Message.Body and Message.BodyLength. BodyLength is already 0
    ; (it is not written by HttpProtocol->Request()), so subtract 1 from its
    ; low dword to make it 0xffffffff, avoiding a longer MOV instr. We only
    ; actually reserve 0x78 bytes on the stack for the response, but that's
    ; fine since we know it will only be 58 (0x3a) bytes long anyway.

    ; 2nd arg (&Token) used later for HttpProtocol->Response()
    mov    edx, esp

    ; Reuse Message structure for response. We previously set .BodyLength to 0,
    ; so we can decrement a dword to make it 0xffffffff avoiding a longer MOV.
    ;
    ; Message.BodyLength = 0xffffffff;
    ; Message.Body = alloca(0x78);
    dec    dword [rsi]
    sub    esp, 0x78
    mov    [rsi + 8], esp

    ; HttpProtocol->Response(HttpProtocol, &Token);
    mov    ecx, ebx
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffResponse]

    ; Output the response to serial port COM1 (0x3f8). We already know what the
    ; response size will be so we can set RCX and use REP OUTSB. Pretty neat.
    ; Setting DX is split into two 2-byte instructions instead of a single
    ; 4-byte MOV to DX: smaller instructions are more flexible.
    mov    esi, esp
    xor    ecx, ecx
    mov    cl, EXPECTED_RESPONSE_SIZE
    mov    dh, 0x03
    mov    dl, 0xf8
    cld
    rep outsb

    ; vvv Instructions below this comment will be removed in the final version.

    ; Destroy stack frame, restore callee-saved registers and return.
    add    esp, 8 * 16 + 0x78
    pop    rdi
    pop    rsi
    pop    rbx
    ret
;
;=====[ DATA ]==================================================================
;
; It's more expensive to push these on the stack than to put them here at the
; end of the file and use a LEA. Furthermore, we keep RDI pointing to the data
; here and move it with ADDs, so only a single LEA at the start is ever needed.
;
gEfiHttpServiceBindingProtocolGuid:
    EFI_GUID 0xbdc8e6af, 0xd9bc, 0x4379, 0x1cae5de7c4e02aa7
gEfiHttpProtocolGuid:
    EFI_GUID 0x7a59b29b, 0x910b, 0x4171, 0x5b5bf20d5aa84282
strHostHeaderValue:
    db 'binary.golf', 0
strHostHeaderName:
    db 'Host', 0
;
; Will be converted to UTF-16 at runtime. Since our only section has
; VirtualSize = SizeOfRawData + 0x400, the loader will write the final
; NUL-terminator for us (hence the name utf16UrlMinus1).
asciiUrl:
    db 'https://binary.golf/5/5'
utf16UrlMinus1:
;
;===============================================================================
END:
