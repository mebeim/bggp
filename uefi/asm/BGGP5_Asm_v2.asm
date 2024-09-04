;
; @mebeim - 2024-07-10
;
; UEFI application that downloads the file at https://binary.golf/5/5 and
; displays its contents on the screen. Written for and tested on EDK II OVMF.
;
; Several parts of the DOS/PE header (labeled `HOLEn`) are ignored by
; the EDK II loader and are simply filled with zeroes. They will be used to
; store code in the next iteration.
;
; Changes/improvements from v1:
;
;   - Use 32-bit registers where it makes sense to save space since the whole
;     EDK II address space is < 32-bit.
;   - Rely on calls returning EFI_SUCCESS to avoid zeroing RAX where possible.
;   - Get rid of some DEBUG-only macros.
;   - Compress some more data structs overlapping them.
;

[bits 64]

; === CONSTANTS & MACROS =======================================================

; Constants and struct offsets from EDK II source
SUBSYSTEM_EFI_APPLICATION                              equ 0xa
ENUM_EFI_HTTP_METHOD.HttpMethodGet                     equ 0x0
ENUM_EFI_HTTP_VERSION.HttpVersion11                    equ 0x1
STRUCT_EFI_BOOT_SERVICES.OffHandleProtocol             equ 0x98
STRUCT_EFI_BOOT_SERVICES.OffLocateProtocol             equ 0x140
STRUCT_EFI_HTTP_PROTOCOL.OffConfigure                  equ 0x8
STRUCT_EFI_HTTP_PROTOCOL.OffRequest                    equ 0x10
STRUCT_EFI_HTTP_PROTOCOL.OffResponse                   equ 0x20
STRUCT_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OffOutputString equ 0x8
STRUCT_EFI_SERVICE_BINDING_PROTOCOL.OffCreateChild     equ 0x0
STRUCT_EFI_SYSTEM_TABLE.OffConOut                      equ 0x40
STRUCT_EFI_SYSTEM_TABLE.OffBootServices                equ 0x60

; We expect exactly 58 bytes from https://binary.golf/5/5:
; 'Another #BGGP5 download!! @binarygolf https://binary.golf\n'
EXPECTED_RESPONSE_SIZE equ 58

; We use RSP-relative addressing for local variables, no RBP.
; We only need 2 stack slots to pass poniters to functions.
STACK_FRAME_SIZE equ 0x40
STACK_OFF_SLOT1  equ 0x30
STACK_OFF_SLOT2  equ 0x38

; Use some callee-saved registers used to hold BootServices and ConOut. All
; EDK II addressea are < 32-bit so we can always use 32-bit registers, however
; for some things 64-bit registers are needed (e.g. PUSH/POP) or just better
; (shorter opcode encoding).
%define RegBootServices64 rbx
%define RegBootServices32 ebx
%define RegConOut64       r12
%define RegConOut32       r12d

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


; === START OF FILE ============================================================

                                         ;                       | DOS HEADER
                                         ;                       +--------------
db 'MZ'                                  ; PE HEADER             | e_magic
dw 0x100                                 ; ----------------------+ e_cblp
db 'PE', 0, 0                            ; Signature             | e_cp, e_crlc
dw 0x8664                                ; Machine               | e_cparhdr
dw 1                                     ; NumberOfSections      | e_minalloc

HOLE0:
    PAD_CHECK HOLE0, 12

    dw pe_opt_header_end - pe_opt_header ; SizeOfOptionalHeader  | e_lsarlc
    dw 0x0206                            ; Characteristics       | e_ovno

pe_opt_header:
    dw 0x20b                             ; Magic (PE32+)         | e_res[0]

HOLE1:
    PAD_CHECK HOLE1, 14

    dd ENTRY                             ; AddressOfEntryPoint   | e_res2[2:4]
    db 'BGGP'                            ; BaseOfCode            | e_res2[4:6]
    db 0, 'MEBEIM', 0                    ; ImageBase             | e_res2[6:10]
    dd 4                                 ; SectionAlignment      | e_lfanew
    dd 4                                 ; FileAlignment         +--------------

HOLE2:
    PAD_CHECK HOLE2, 16

    dd 0x1000                            ; SizeOfImage
    dd headers_end                       ; SizeOfHeaders

HOLE3:
    PAD_CHECK HOLE3, 4

    dw SUBSYSTEM_EFI_APPLICATION         ; Subsystem (checked)

HOLE4:
    PAD_CHECK HOLE4, 38

    dd 6                                 ; NumberOfRvaAndSizes (need 6)

; EFI_IMAGE_DIRECTORY_ENTRY_{EXPORT,IMPORT,RESOURCE,EXCEPTION} can be whatever.
HOLE5:
    PAD_CHECK HOLE5, 32

    ; These two are needed and checked. We cannot overlap the end of the PE OPT
    ; header with the start of the section header (i.e. pe_opt_header_end label
    ; must come before section_header label).
    dq 0                                 ; EFI_IMAGE_DIRECTORY_ENTRY_SECURITY
    dq 0                                 ; EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC

pe_opt_header_end:
section_header:
    db '.mebeim!'       ; Name[]
    dd END - ENTRY      ; VirtualSize
    dd ENTRY            ; Virtual Address
    dd END - ENTRY      ; SizeOfRawData
    dd ENTRY            ; PointerToRawData
    dd 0                ; PointerToRelocations
    dd 0                ; PointerToLinenumbers
    dw 0                ; NumberOfRelocations
    dw 0                ; NumberOfLinenumbers
    dd 0x60500020       ; Characteristics
headers_end:


; --- Execution Starts Here ----------------------------------------------------

ENTRY:
    ; Save callee-saved registers and allocate stack frame.
    push   RegBootServices64
    push   RegConOut64
    sub    esp, STACK_FRAME_SIZE

    ; Get ahold of BootServices and ConOut
    mov    RegBootServices32, [rdx + STRUCT_EFI_SYSTEM_TABLE.OffBootServices]
    mov    RegConOut64, qword [rdx + STRUCT_EFI_SYSTEM_TABLE.OffConOut]

    ; Find image base to use it as relocation offset
    call   .here
.here:
    pop    rcx
    and    cx, 0xf000

    ; Perform relocations
    lea    eax, [rel reloc0]
    add    dword [eax + reloc0 - reloc0], ecx
    add    dword [eax + reloc1 - reloc0], ecx
    add    dword [eax + reloc2 - reloc0], ecx
    add    dword [eax + reloc3 - reloc0], ecx
    add    dword [eax + reloc4 - reloc0], ecx
    add    dword [eax + reloc5 - reloc0], ecx
    add    dword [eax + reloc6 - reloc0], ecx
    add    dword [eax + reloc7 - reloc0], ecx
    add    dword [eax + reloc8 - reloc0], ecx
    add    dword [eax + reloc9 - reloc0], ecx

    ; gBS->LocateProtocol(&gEfiHttpServiceBindingProtocolGuid, NULL, (VOID **)&HttpServiceBinding);
    ;   OUT HttpServiceBinding @ rsp + STACK_OFF_SLOT1
    lea    ecx, [rel gEfiHttpServiceBindingProtocolGuid]
    xor    edx, edx
    lea    r8, [rsp + STACK_OFF_SLOT1]
    call   [RegBootServices64 + STRUCT_EFI_BOOT_SERVICES.OffLocateProtocol]

    ; HttpChildHandle = NULL;
    ; HttpServiceBinding->CreateChild(HttpServiceBinding, &HttpChildHandle);
    ;   IN  HttpServiceBinding @ rsp + STACK_OFF_SLOT1
    ;   OUT HttpChildHandle    @ rsp + STACK_OFF_SLOT2
    mov    ecx, [rsp + STACK_OFF_SLOT1]
    lea    edx, [rsp + STACK_OFF_SLOT2]
    xor    eax, eax
    mov    qword [rdx], rax
    call   [rcx + STRUCT_EFI_SERVICE_BINDING_PROTOCOL.OffCreateChild]

    ; gBS->HandleProtocol(HttpChildHandle, &gEfiHttpProtocolGuid, (VOID **)&HttpProtocol);
    ;   OUT HttpProtocol    @ rsp + STACK_OFF_SLOT1
    ;   IN  HttpChildHandle @ rsp + STACK_OFF_SLOT2
    mov    ecx, [rsp + STACK_OFF_SLOT2]
    lea    edx, [rel gEfiHttpProtocolGuid]
    lea    r8, [rsp + STACK_OFF_SLOT1]
    call   [RegBootServices64 + STRUCT_EFI_BOOT_SERVICES.OffHandleProtocol]

    ; HttpProtocol->Configure(HttpProtocol, &HttpConfigData);
    ;   IN  HttpProtocol @ rsp + STACK_OFF_SLOT1
    mov    ecx, [rsp + STACK_OFF_SLOT1]
    lea    edx, [rel HttpConfigData]
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffConfigure]

    ; HttpProtocol->Request(HttpProtocol, &RequestToken);
    ;   IN  HttpProtocol @ rsp + STACK_OFF_SLOT1
    mov    ecx, [rsp + STACK_OFF_SLOT1]
    lea    edx, [rel RequestToken]
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffRequest]

    ; HttpProtocol->Response(HttpProtocol, &ResponseToken);
    ;   IN  HttpProtocol @ rsp + STACK_OFF_SLOT1
    mov    ecx, [rsp + STACK_OFF_SLOT1]
    lea    edx, [rel ResponseToken]
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffResponse]

    ; Setup RSI/RDI for LODSB/STOSW and RCX for LOOP. We already know what the
    ; response size will be so we can already initialize RCX.
    lea    esi, [rel ResponseBuffer]
    lea    edi, [rel ResponseBuffer + EXPECTED_RESPONSE_SIZE]
    xor    ecx, ecx
    mov    cl, EXPECTED_RESPONSE_SIZE

    ; ConOut->OptuptString() argument for later
    mov    edx, edi

    ; Convert response from ASCII to UTF-16-LE using a nice LODSB + STOSW loop.
    ; This turns each byte into 2 (the original followed by a zero). No need to
    ; clear AX since RAX = 0 assuming the previous call returned EFI_SUCCESS.
    ; We write the result starting from ResponseBuffer, overwriting data that we
    ; don't need anymore. The response will be small enough anyway.
    cld
.convert:
    lodsb
    stosw
    loop   .convert

    ; NUL-terminate UTF-16 string
    xor    eax, eax
    stosw

    ; SystemTable->ConOut->OutputString(SystemTable->ConOut, ResponseBuffer);
    mov    ecx, RegConOut32
    call   [rcx + STRUCT_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OffOutputString]

    ; Destroy stack frame, restore callee-saved registers and return.
    ; RAX = 0 assuming the last call returned EFI_SUCCESS.
    add    esp, STACK_FRAME_SIZE
    pop    RegConOut64
    pop    RegBootServices64
    ret


; --- Data ---------------------------------------------------------------------

gEfiHttpServiceBindingProtocolGuid:
    EFI_GUID 0xbdc8e6af, 0xd9bc, 0x4379, 0x1cae5de7c4e02aa7
gEfiHttpProtocolGuid:
    EFI_GUID 0x7a59b29b, 0x910b, 0x4171, 0x5b5bf20d5aa84282
strUrl:
    db __utf16__(`https://binary.golf/5/5\0`)
strHostHeaderName:
    db 'Host', 0
strHostHeaderValue:
    db 'binary.golf', 0

; Overlap Http4AccessPoint with HttpConfigData (UseDefaultAddress == HttpVersion11)
Http4AccessPoint:
HttpConfigData:                                  ; EFI_HTTP_CONFIG_DATA               | EFI_HTTPv4_ACCESS_POINT
        dd ENUM_EFI_HTTP_VERSION.HttpVersion11   ;     EFI_HTTP_VERSION HttpVersion;  |     UseDefaultAddress
        dd 0                                     ;     UINT32 TimeOutMillisec;        |     ...
        db 0                                     ;     BOOLEAN LocalAddressIsIPv6;
        times 7 db 0                             ;     (pad)
reloc0: dq Http4AccessPoint                      ;     EFI_HTTPv4_ACCESS_POINT *IPv4Node;

; Overlap ResponseData with RequestData, the former is just an int anyway
ResponseData:                                    ;
RequestData:                                     ; EFI_HTTP_REQUEST_DATA              | EFI_HTTP_RESPONSE_DATA
        dd ENUM_EFI_HTTP_METHOD.HttpMethodGet    ;     EFI_HTTP_METHOD Method         |     EFI_HTTP_STATUS_CODE StatusCode
        times 4 db 0                             ;     (pad)
reloc1: dq strUrl                                ;     CHAR16 *Url

RequestHeader:                                   ; EFI_HTTP_HEADER
reloc2: dq strHostHeaderName                     ;     CHAR8 *FieldName
reloc3: dq strHostHeaderValue                    ;     CHAR8 *FieldValue

RequestMessage:                                  ; EFI_HTTP_MESSAGE
reloc4: dq RequestData                           ;     EFI_HTTP_REQUEST_DATA *Request;
        dq 1                                     ;     UINTN HeaderCount;
reloc5: dq RequestHeader                         ;     EFI_HTTP_HEADER *Headers;

; Overlap RequestMessage with RequestToken
RequestToken:                                    ; EFI_HTTP_TOKEN                    | EFI_HTTP_MESSAGE
        dq 0                                     ;     EFI_EVENT Event;              |     UINTN BodyLength;
        dq 0                                     ;     EFI_STATUS Status;            |     VOID *Body;
reloc6: dq RequestMessage                        ;     EFI_HTTP_MESSAGE *Message;

ResponseMessage:                                 ; EFI_HTTP_MESSAGE
reloc7: dq ResponseData                          ;     EFI_HTTP_REQUEST_DATA *Response;
        dq 1                                     ;     UINTN HeaderCount;
        dq 0                                     ;     EFI_HTTP_HEADER *Headers;
        dq EXPECTED_RESPONSE_SIZE                ;     UINTN BodyLength;
reloc8: dq ResponseBuffer                        ;     VOID *Body;

ResponseToken:                                   ; EFI_HTTP_TOKEN
        dq 0                                     ;     EFI_EVENT Event;
        dq 0                                     ;     EFI_STATUS Status;
reloc9: dq ResponseMessage                       ;     EFI_HTTP_MESSAGE *Message;

; We can go past the end of the file for writing. Memory will be mapped RWX here
; anyway as we are smaller than 1 page. Reading is a bit trickier though, as
; memory is poisoned with 0xAF bytes.
ResponseBuffer:

END:
