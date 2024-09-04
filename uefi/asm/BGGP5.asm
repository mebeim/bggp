;=====[ BGGP5 UEFI APP ]========================================================;
;                                                                               ;
; @mebeim - 2024-07-22                                                          ;
;                                                                               ;
; UEFI application that downloads the file at https://binary.golf/5/5 and       ;
; displays its contents on the screen. Written for and tested on EDK II OVMF.   ;
;                                                                               ;
; Instruction placement optimized for size, based on BGGP5_Asm_v3.asm code.     ;
;                                                                               ;
; Several parts of the DOS/PE/section header are ignored by the EDK II loader   ;
; and therefore are used to store code. These correspond to the `HOLEx` labels. ;
; Instruction placement optimized for size, based on v3 code.                   ;
;                                                                               ;
; Execution will start at the `ENTRY` label, jumping around into the various    ;
; numbered holes as follows:                                                    ;
;                                                                               ;
; ENTRY -> HOLE5 -> HOLE2 -> HOLE0 -> HOLE1 -> HOLE3 -> HOLE7 -> HOLE6 -> HOLE4 ;
;                                                                               ;
; This order minimizes the space used by JMP instructions as the distance       ;
; between consecutive code blocks is always small enough to guarante a 2-byte   ;
; JMP rel8 instruction.                                                         ;
;                                                                               ;
; Instructions are also placed optimally to fill the header holes and therefore ;
; minimize the amount of wasted space. This optimal instruction packing was     ;
; calculated based on the code in BGGP5_Asm_v3.asm using the ../minimize.py     ;
; Python 3 script.                                                              ;
;                                                                               ;
; After the job is done, the application will jump into an infinite loop and    ;
; hang indefinitely. This is just to avoid crashing due to the lack of a proper ;
; frame setup and restoring of callee-saved registers. In any case, as long as  ;
; the file is downloaded and its content is displayed we still have a valid     ;
; BGGP5 entry!                                                                  ;
;                                                                               ;
; See BGGP5_Asm_v3.asm for essentially the same code laid out linearly and with ;
; function prolog/epilog to perform clean return without hanging.               ;
;                                                                               ;
[bits 64]                                                                       ;
;                                                                               ;
;====[ CONSTANTS & MACROS ]=====================================================;
;                                                                               ;
; Constants and struct offsets from EDK II source                               ;
SUBSYSTEM_EFI_APPLICATION                              equ 0xa                  ;
STRUCT_EFI_BOOT_SERVICES.OffHandleProtocol             equ 0x98                 ;
STRUCT_EFI_BOOT_SERVICES.OffLocateProtocol             equ 0x140                ;
STRUCT_EFI_HTTP_PROTOCOL.OffConfigure                  equ 0x8                  ;
STRUCT_EFI_HTTP_PROTOCOL.OffRequest                    equ 0x10                 ;
STRUCT_EFI_HTTP_PROTOCOL.OffResponse                   equ 0x20                 ;
STRUCT_EFI_SERVICE_BINDING_PROTOCOL.OffCreateChild     equ 0x0                  ;
STRUCT_EFI_SYSTEM_TABLE.OffBootServices                equ 0x60                 ;
;                                                                               ;
; We expect exactly 58 bytes from https://binary.golf/5/5:                      ;
; 'Another #BGGP5 download!! @binarygolf https://binary.golf\n'                 ;
EXPECTED_RESPONSE_SIZE equ 58                                                   ;
;                                                                               ;
; ASCII URL size (including NUL terminator) for easier math later on.           ;
URL_SIZE equ utf16UrlMinus1 + 1 - asciiUrl                                      ;
;                                                                               ;
; Macro to pack a GUID into memory.                                             ;
%macro EFI_GUID 4                                                               ;
    dd %1                                                                       ;
    dw %2, %3                                                                   ;
    dq %4                                                                       ;
%endmacro                                                                       ;
;                                                                               ;
; Macro to ensure we are filling exactly as many bytes as needed padding with   ;
; zeroes. This also errors out if we exceed the specified size, which is nice.  ;
%macro PAD_CHECK 2                                                              ;
    times %2 - ($ - %1) db 0                                                    ;
%endmacro                                                                       ;
;                                                                               ;
;                                                                               ;
;=====[ START OF FILE ]=========================================================;
;                                        ;                       | DOS HEADER   ;
;                                        ;                       +--------------;
db 'MZ'                                  ; PE HEADER             | e_magic      ;
dw 0x100                                 ; ----------------------+ e_cblp       ;
db 'PE', 0, 0                            ; Signature             | e_cp, e_crlc ;
dw 0x8664                                ; Machine               | e_cparhdr    ;
dw 1                                     ; NumberOfSections      | e_minalloc   ;
;_______________________________________________________________________________;
;                                                                               ;
HOLE0: ;<---------------------------------------------------------------------------o
    ;                                                                           ;   |
    ; HttpProtocol->Configure(HttpProtocol, &CfgAndAp.Cfg);                     ;   ^
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffConfigure]                        ;   |
    ;                                                                           ;   |
    ; Setup RSI/RDI/RCX for upcoming LODSB/STOSW/LOOP.                          ;   ^
    add    edi, asciiUrl - gEfiHttpProtocolGuid                                 ;   |
    mov    esi, edi                                                             ;   |
    xor    ecx, ecx                                                             ;   ^
    jmp    HOLE1 ;>-----------------------------------------------------------------+---o
    PAD_CHECK HOLE0, 12                                                         ;   |   |
;_______________________________________________________________________________;   ^   |
;                                                                               ;   |   v
    dw pe_opt_header_end - pe_opt_header ; SizeOfOptionalHeader  | e_lsarlc     ;   |   |
    dw 0x0206                            ; Characteristics       | e_ovno       ;   ^   |
;________________________________________;_______________________|______________;   |   v
pe_opt_header:                           ;                       |              ;   |   |
    dw 0x20b                             ; Magic (PE32+)         | e_res[0]     ;   ^   |
;_______________________________________________________________________________;   |   v
;                                                                               ;   |   |
HOLE1: ;<---------------------------------------------------------------------------+---o
    ;                                                                           ;   |
    ; Finish setup of RSI/RDI/RCX for upcoming LODSB/STOSW/LOOP.                ;   |
    mov    cl, utf16UrlMinus1 + 1 - asciiUrl                                    ;   ^
    add    edi, ecx                                                             ;   |
    ;                                                                           ;   |
    ; Convert URL from ASCII to UTF-16-LE using a nice LODSB + STOSW loop. Less ;   ^
    ; space is used converting the URL at runtime than embedding it directly as ;   |
    ; UTF-16.                                                                   ;   |
    cld                                                                         ;   ^
.urlconv:                                                                       ;   |
    lodsb                                                                       ;   |
    stosw                                                                       ;   ^
    loop   .urlconv                                                             ;   |
    ;                                                                           ;   |
    ; RAX = 0 at the end of the above loop because asciiUrl is NUL-terminated   ;   ^
    ; and the last LODSB reads 0. This saves a XOR EAX,EAX.                     ;   |
    ;                                                                           ;   |
    ; Allocate EFI_HTTP_REQUEST_DATA ReqData = {                                ;   ^
    ;     .Method = HttpMethodGet,              // 0x0                          ;   |
    ;     .Url    = L"https://binary.golf/5/5"                                  ;   |
    ; }                                                                         ;   ^
    push   rsi                                                                  ;   |
    push   rax                                                                  ;   |
    jmp    HOLE3 ;>-----------------------------------------------------------------+-------o
    PAD_CHECK HOLE1, 14                                                         ;   |       |
;_______________________________________________________________________________;   |       |
;                                                                               ;   ^       v
; At first glance it may look like BaseOfCode, BaseOfData and ImageBaaddse are  ;   |       |
; usable. The EDK II loader indeed does not care about their value, but         ;   |       |
; overwrites them with actual addresses, so they cannot be used.                ;   ^       v
;                                                                               ;   |       |
    dd ENTRY                             ; AddressOfEntryPoint   | e_res2[2:4]  ;   |       |
    db 'BGGP'                            ; BaseOfCode            | e_res2[4:6]  ;   ^       v
    db 0, 'MEBEIM', 0                    ; ImageBase             | e_res2[6:10] ;   |       |
    dd 4                                 ; SectionAlignment      | e_lfanew     ;   |       |
    dd 4                                 ; FileAlignment         o--------------;   ^       v
;_______________________________________________________________________________;   |       |
;                                                                               ;   |       |
HOLE2: ;<---------------------------------------------------------------------------+---o   v
    ;                                                                           ;   |   |   |
    ; gBS->HandleProtocol(HttpChildHandle, &gEfiHttpProtocolGuid, &HttpProtocol);   |   ^   |
    call   [rbx - 0x78 + STRUCT_EFI_BOOT_SERVICES.OffHandleProtocol]            ;   ^   |   v
    ;                                                                           ;   |   |   |
    ; RBX = HttpProtocol from now on (don't need BootServices anymore)          ;   |   ^   |
    mov    ebx, [rdi]                                                           ;   ^   |   v
    ;                                                                           ;   |   |   |
    ; Allocate these overlapping structs (since HttpVersion11 == 1 == TRUE).    ;   |   ^   |
    ;                                                                           ;   ^   |   v
    ; union {                                                                   ;   |   |   |
    ;     EFI_HTTP_CONFIG_DATA Cfg;                                             ;   |   ^   |
    ;     EFI_HTTPv4_ACCESS_POINT Ap;                                           ;   ^   |   v
    ; } CfgAndAp = {                                                            ;   |   |   |
    ;     .Cfg.HttpVersion        = HttpVersion11, // Also Ap.UseDefaultAddress ;   |   ^   |
    ;     .Cfg.TimeOutMillisec    = 0,                                          ;   ^   |   v
    ;     .Cfg.LocalAddressIsIPv6 = FALSE,                                      ;   |   |   |
    ;     .Cfg.IPv4Node           = &CfgAndAp.Ap   // Points to itself          ;   |   ^   |
    ; };                                                                        ;   ^   |   v
    push   rsp                                                                  ;   |   |   |
    push   rax                                                                  ;   |   ^   |
    inc    eax                                                                  ;   ^   |   v
    push   rax                                                                  ;   |   |   |
    ;                                                                           ;   |   ^   |
    ; Args for HttpProtocol->Configure(), called right after this JMP.          ;   ^   |   v
    mov    ecx, ebx                                                             ;   |   |   |
    mov    edx, esp                                                             ;   |   ^   |
    jmp    HOLE0 ;>-----------------------------------------------------------------o   |   v
    PAD_CHECK HOLE2, 16                                                         ;       |   |
;_______________________________________________________________________________;       ^   |
;                                                                               ;       |   v
    dd 0x1000                            ; SizeOfImage                          ;       |   |
    dd headers_end                       ; SizeOfHeaders                        ;       ^   |
;_______________________________________________________________________________;       |   v
;                                                                               ;       |   |
HOLE3: ;<-------------------------------------------------------------------------------+---o
    ;                                                                           ;       |
    ; Save a pointer to the EFI_HTTP_REQUEST_DATA struct we just pushed on the  ;       |
    ; stack in RCX for later use in EFI_HTTP_MESSAGE.                           ;       ^
    mov    ecx, esp                                                             ;       |
    jmp    HOLE7 ;>---------------------------------------------------------------------+---o
    PAD_CHECK HOLE3, 4                                                          ;       ^   |
;_______________________________________________________________________________;       |   |
;                                                                               ;       |   v
; Subsystem is checked, we can use 0xA (EFI_APPLICATION).                       ;       ^   |
;                                                                               ;       |   |
    dw SUBSYSTEM_EFI_APPLICATION         ; Subsystem                            ;       |   v
;_______________________________________________________________________________;       ^   |
;                                                                               ;       |   |
HOLE4: ;<-------------------------------------------------------------------------------+---+---o
    ;                                                                           ;       ^   |   |
    ; Complete EFI_HTTP_TOKEN pushing its .Event field. Technically it should   ;       |   |   ^
    ; be NULL, but 1 works anyway and saves us a DEC RAX instruction.           ;       |   v   |
    push   rax                                                                  ;       ^   |   |
    ;                                                                           ;       |   |   ^
    ; HttpProtocol->Request(HttpProtocol, &Token);                              ;       |   v   |
    mov    ecx, ebx                                                             ;       ^   |   |
    mov    edx, esp                                                             ;       |   |   ^
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffRequest]                          ;       |   v   |
    ;                                                                           ;       ^   |   |
    ; Reuse the same EFI_HTTP_TOKEN and EFI_HTTP_MESSAGE structs for the call   ;       |   |   ^
    ; to HttpProtocol->Response(). The token does not need any change. We only  ;       |   v   |
    ; need to set Message.Body and Message.BodyLength. BodyLength is already 0  ;       ^   |   |
    ; (it is not written by HttpProtocol->Request()), so subtract 1 from its    ;       |   |   ^
    ; low dword to make it 0xffffffff, avoiding a longer MOV instr. We only     ;       |   v   |
    ; actually reserve 0x78 bytes on the stack for the response, but that's     ;       ^   |   |
    ; fine since we know it will only be 58 (0x3a) bytes long anyway.           ;       |   |   ^
    ;                                                                           ;       |   v   |
    ; 2nd arg (&Token) used later for HttpProtocol->Response()                  ;       ^   |   |
    mov    edx, esp                                                             ;       |   |   ^
    ;                                                                           ;       |   v   |
    ; Reuse Message structure for response. We previously set .BodyLength to 0, ;       ^   |   |
    ; so we can decrement a dword to make it 0xffffffff to avoid a longer MOV.  ;       |   |   ^
    ;                                                                           ;       |   v   |
    ; Message.BodyLength = 0xffffffff;                                          ;       ^   |   |
    ; Message.Body = alloca(0x78);                                              ;       |   |   ^
    dec    dword [rsi]                                                          ;       |   v   |
    sub    esp, 0x78                                                            ;       ^   |   |
    mov    [rsi + 8], esp                                                       ;       |   |   ^
    ;                                                                           ;       |   v   |
    ; HttpProtocol->Response(HttpProtocol, &Token);                             ;       ^   |   |
    mov    ecx, ebx                                                             ;       |   |   ^
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffResponse]                         ;       |   v   |
    ;                                                                           ;       ^   |   |
    ; Output the response to serial port COM1 (0x3f8). We already know what the ;       |   |   ^
    ; response size will be so we can set RCX and use REP OUTSB. Pretty neat.   ;       |   v   |
    mov    esi, esp                                                             ;       ^   |   |
    xor    ecx, ecx                                                             ;       |   |   ^
    mov    cl, EXPECTED_RESPONSE_SIZE                                           ;       |   v   |
    mov    dx, 0x3f8                                                            ;       ^   |   |
    cld                                                                         ;       |   |   ^
    rep outsb                                                                   ;       |   v   |
    ;                                                                           ;       ^   |   |
    ; And we are done!                                                          ;       |   |   ^
    ;                                                                           ;       |   v   |
    ; We don't have space left to clean the stack frame and we also never saved ;       ^   |   |
    ; callee-saved registers, so returning with a RET would crash. Instead of   ;       |   |   ^
    ; crashing, just hang with an infinite loop.                                ;       |   v   |
    jmp    $                                                                    ;       ^   |   |
    PAD_CHECK HOLE4, 38                                                         ;       |   |   ^
;_______________________________________________________________________________;       |   v   |
;                                                                               ;       ^   |   |
    dd 6                                 ; NumberOfRvaAndSizes (need 6)         ;       |   |   ^
;_______________________________________________________________________________;       |   v   |
;                                                                               ;       ^   |   |
; EFI_IMAGE_DIRECTORY_ENTRY_{EXPORT,IMPORT,RESOURCE,EXCEPTION} can be whatever. ;       |   |   ^
;                                                                               ;       |   v   |
HOLE5: ;<---------------------------------------------------------------------------o   ^   |   |
    ;                                                                           ;   |   |   |   ^
    ; Locate the HttpServiceBinding protocol. Pass as stack pointer for output. ;   |   |   v   |
    ;                                                                           ;   ^   ^   |   |
    ; gBS->LocateProtocol(&gEfiHttpServiceBindingProtocolGuid, NULL,            ;   |   |   |   ^
    ;                     &HttpServiceBinding);                                 ;   |   |   v   |
    xor    edx, edx                                                             ;   ^   ^   |   |
    mov    r8, rsp ; &HttpServiceBinding                                        ;   |   |   |   ^
    call   [rbx - 0x78 + STRUCT_EFI_BOOT_SERVICES.OffLocateProtocol]            ;   |   |   v   |
    ;                                                                           ;   ^   ^   |   |
    ; Each time we make a call, assuming it succeeds, RAX will be set to 0      ;   |   |   |   ^
    ; (EFI_SUCCESS). Most of the following code makes this assumption to save   ;   |   |   v   |
    ; XOR EAX,EAX instructions. The first example is right here where we do a   ;   ^   ^   |   |
    ; PUSH RAX to push a NULL ptr.                                              ;   |   |   |   ^
    ;                                                                           ;   |   |   v   |
    ; Create child handle. Pass RDI data pointer for output. This will          ;   ^   ^   |   |
    ; overwrite gEfiHttpServiceBindingProtocolGuid, but we already used it so   ;   |   |   |   ^
    ; it's fine.                                                                ;   |   |   v   |
    ;                                                                           ;   ^   ^   |   |
    ; HttpChildHandle = NULL;                                                   ;   |   |   |   ^
    ; HttpServiceBinding->CreateChild(HttpServiceBinding, &HttpChildHandle);    ;   |   |   v   |
    mov    ecx, [rsp]                                                           ;   ^   ^   |   |
    push   rax                                                                  ;   |   |   |   ^
    mov    edx, esp ; &HttpChildHandle                                          ;   |   |   v   |
    call   [rcx + STRUCT_EFI_SERVICE_BINDING_PROTOCOL.OffCreateChild]           ;   ^   ^   |   |
    ;                                                                           ;   |   |   |   ^
    ; Args for gBS->HandleProtocol(). Pass RDI data pointer for output. We will ;   |   |   v   |
    ; overwrite gEfiHttpProtocolGuid, but only after reading it to resolve the  ;   ^   ^   |   |
    ; protocol, so it's fine.                                                   ;   |   |   |   ^
    mov    ecx, [rsp]                                                           ;   |   |   v   |
    add    edi, gEfiHttpProtocolGuid - gEfiHttpServiceBindingProtocolGuid       ;   ^   ^   |   |
    mov    edx, edi                                                             ;   |   |   |   ^
    mov    r8, rdi                                                              ;   |   |   v   |
    jmp    HOLE2 ;>-----------------------------------------------------------------+---o   |   |
    PAD_CHECK HOLE5, 32                                                         ;   |       |   ^
;_______________________________________________________________________________;   |       v   |
;                                                                               ;   ^       |   |
; These two are needed and checked. We cannot overlap the end of the PE OPT     ;   |       |   ^
; header with the start of the section header (i.e. pe_opt_header_end label     ;   |       v   |
; must come before section_header label).                                       ;   ^       |   |
;                                                                               ;   |       |   ^
    dq 0                                 ; EFI_IMAGE_DIRECTORY_ENTRY_SECURITY   ;   |       v   |
    dq 0                                 ; EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC  ;   ^       |   |
pe_opt_header_end:                                                              ;   |       |   ^
;_______________________________________________________________________________;   |       v   |
section_header:                                                                 ;   ^       |   |
;                                                                               ;   |       |   ^
; We can stuff some code inside the section Name[], which is ignored            ;   |       v   |
;                                                                               ;   ^       |   |
HOLE6: ;<---------------------------------------------------------------------------+---o   |   ^
    ; Finish allocating EFI_HTTP_MESSAGE on stack.                              ;   |   ^   v   |
    ;                                                                           ;   ^   |   |   |
    ; Message.HeaderCount  = 1UL;                                               ;   |   |   |   ^
    ; Message.Data.Request = &ReqData;                                          ;   |   ^   v   |
    inc    eax                                                                  ;   ^   |   |   |
    push   rax                                                                  ;   |   |   |   ^
    push   rcx                                                                  ;   |   ^   v   |
    ;                                                                           ;   ^   |   |   |
    ; Allocate EFI_HTTP_TOKEN Token = {                                         ;   |   |   |   ^
    ;     .Event   = (void *)1,                                                 ;   |   ^   v   |
    ;     .Status  = 1UL,                                                       ;   ^   |   |   |
    ;     .Message = &Message                                                   ;   |   |   |   ^
    ; };                                                                        ;   |   ^   v   |
    ;                                                                           ;   ^   |   |   |
    ; The .Status field is unchecked so it can be any value. Since we           ;   |   |   |   ^
    ; incremented RAX above it will be 1. We are missing one PUSH for .Event,   ;   |   ^   v   |
    ; it's done after the JMP.                                                  ;   ^   |   |   |
    push   rsp                                                                  ;   |   |   |   ^
    push   rax                                                                  ;   |   ^   v   |
    jmp    HOLE4 ;>-----------------------------------------------------------------+---+---+---o
    PAD_CHECK HOLE6, 8                                                          ;   |   |   |
;_______________________________________________________________________________;   |   ^   v
;                                                                               ;   ^   |   |
; Here we set VirtualSize = SizeOfRawData + 0x400 to let the loader zero-out    ;   |   |   |
; memory past the end of the file for us. This saves 1 zero byte at the end of  ;   |   ^   v
; the file for the asciiUrl string.                                             ;   ^   |   |
;                                                                               ;   |   |   |
    dd END - ENTRY + 0x400 ; VirtualSize                                        ;   |   ^   v
    dd ENTRY               ; VirtualAddress                                     ;   ^   |   |
    dd END - ENTRY         ; SizeOfRawData                                      ;   |   |   |
    dd ENTRY               ; PointerToRawData                                   ;   |   ^   v
;_______________________________________________________________________________;   ^   |   |
;                                                                               ;   |   |   |
; PointerTo{Relocations,Linenumbers}, NumberOf{Relocations,Linenumbers} and     ;   |   ^   v
; Characteristics can be whatever.                                              ;   ^   |   |
;                                                                               ;   |   |   |
HOLE7: ;<---------------------------------------------------------------------------+---+---o
    ;                                                                           ;   ^   |
    ; Allocate EFI_HTTP_HEADER and save a pointer to it in RDX for later use    ;   |   |
    ; in EFI_HTTP_MESSAGE.                                                      ;   |   ^
    ;                                                                           ;   ^   |
    ; EFI_HTTP_HEADER Header = {                                                ;   |   |
    ;     .FieldName  = "Host",                                                 ;   |   ^
    ;     .FieldValue = "binary.golf"                                           ;   ^   |
    ; };                                                                        ;   |   |
    sub    edi, utf16UrlMinus1 + 1 + 2 * URL_SIZE - strHostHeaderValue          ;   |   ^
    push   rdi                                                                  ;   ^   |
    add    edi, strHostHeaderName - strHostHeaderValue                          ;   |   |
    push   rdi                                                                  ;   |   ^
    mov    edx, esp                                                             ;   ^   |
    ;                                                                           ;   |   |
    ; Allocate first part of EFI_HTTP_MESSAGE. Since we are doing a GET and we  ;   |   ^
    ; set Message.BodyLength = 0, overlap the ignored Message.Body field with   ;   ^   |
    ; the previously pushed Header.FieldName to save a PUSH.                    ;   |   |
    ;                                                                           ;   |   ^
    ; Save RSI = &Message.BodyLength to modify and re-use the struct later.     ;   ^   |
    ;                                                                           ;   |   |
    ; EFI_HTTP_MESSAGE Message = {                                              ;   |   ^
    ;     /* First 2 fields pushed later after JMP... */                        ;   ^   |
    ;     .Headers      = &Header,                                              ;   |   |
    ;     .BodyLength   = 0UL,                                                  ;   |   ^
    ;     .Body         = "Host"    // Overlaps with Header.FieldName           ;   ^   |
    ; };                                                                        ;   |   |
    push   rax       ; BodyLength                                               ;   |   ^
    mov    esi, esp  ; RSI = &Message.BodyLength                                ;   ^   |
    push   rdx       ; Headers                                                  ;   |   |
    jmp    HOLE6 ;>-----------------------------------------------------------------+---o
    PAD_CHECK HOLE7, 16                                                         ;   ^
;_______________________________________________________________________________;   |
headers_end:                                                                    ;   |
;                                                                               ;   ^
;                                                                               ;   |
;======[ ENTRY POINT ]==========================================================;   |
;                                                                               ;   ^
; We cannot overlap the section headers with the entry point. The former must   ;   |
; come first entirely. We can however jump back into section/PE headers. Since  ;   |
; the code is so short, it fits entirely in the holes in the headers, so this   ;   ^
; is the only instruction we need past the headers!                             ;   |
;                                                                               ;   |
ENTRY:                                                                          ;   ^
    ;                                                                           ;   |
    ; Use callee-saved RBX to hold BootServices and advance it by 0x78 to save  ;   |
    ; 3 bytes on the encoding of a CALL [RBX + OFF] later. The ADD here is also ;   ^
    ; 3 bytes: two 3-byte insns are more flexible than one 6-byte insn when     ;   |
    ; filling header holes.                                                     ;   |
    mov    ebx, [rdx + STRUCT_EFI_SYSTEM_TABLE.OffBootServices]                 ;   ^
    add    ebx, 0x78                                                            ;   |
    ;                                                                           ;   |
    ; Use callee-saved RDI to point to data (at the end of the file) so we can  ;   ^
    ; simply advance it later avoiding additional LEAs, which are quite long.   ;   |
    lea    edi, [rel gEfiHttpServiceBindingProtocolGuid]                        ;   |
    ;                                                                           ;   ^
    ; 1st arg for gBS->LocateProtocol(), called right after this JMP.           ;   |
    mov    ecx, edi                                                             ;   |
    jmp    HOLE5 ;>-----------------------------------------------------------------o
;                                                                               ;
;                                                                               ;
;=====[ DATA ]==================================================================;
;                                                                               ;
; It's more expensive to push these on the stack than to put them here at the   ;
; end of the file and use a LEA. Furthermore, we keep RDI pointing to the data  ;
; here and move it with ADDs, so only a single LEA at the start is ever needed. ;
;                                                                               ;
gEfiHttpServiceBindingProtocolGuid:                                             ;
    EFI_GUID 0xbdc8e6af, 0xd9bc, 0x4379, 0x1cae5de7c4e02aa7                     ;
gEfiHttpProtocolGuid:                                                           ;
    EFI_GUID 0x7a59b29b, 0x910b, 0x4171, 0x5b5bf20d5aa84282                     ;
strHostHeaderValue:                                                             ;
    db 'binary.golf', 0                                                         ;
strHostHeaderName:                                                              ;
    db 'Host', 0                                                                ;
;                                                                               ;
; Will be converted to UTF-16 at runtime. Since our only section has            ;
; VirtualSize = SizeOfRawData + 0x400, the loader will write the final          ;
; NUL-terminator for us (hence the name utf16UrlMinus1).                        ;
asciiUrl:                                                                       ;
    db 'https://binary.golf/5/5'                                                ;
utf16UrlMinus1:                                                                 ;
;                                                                               ;
;===============================================================================;
END:
