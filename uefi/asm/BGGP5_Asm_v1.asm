;
; @mebeim - 2024-07-09
;
; UEFI application that downloads the file at https://binary.golf/5/5 and
; displays its contents on the screen. Written for and tested on EDK II OVMF.
;
; This initial layout is based on @netspooky's BGGP4 UEFI entry:
; https://github.com/netspooky/golfclub/blob/e791160e84b4ca6b29ad17adc9c518df83de52eb/uefi/bggp4/bggp4.uefi.asm
;
; Several parts of the DOS/PE header (labeled `HOLEn`) are ignored by
; the EDK II loader and are simply filled with zeroes. They will be used to
; store code in the next iteration.
;
; Not much interesting going on except some very simple optimizations with data
; struct overlaps. Everything is RWX so we have a lot of freedom! Next step is
; to optimize the code for size.
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
STRUCT_EFI_HTTP_MESSAGE.OffBodyLength                  equ 0x18
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

; Use some callee-saved registers used to hold BootServices and ConOut
%define RegBootServices rbx
%define RegConOut       r12

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

; Debug-only macro to check return value of functions returning EFI_STATUS and
; trap in case of error
%macro DEBUG_CHECK_EFI_STATUS 0
%ifdef DEBUG
    inc    byte [rel debug_counter]
    test   rax, rax
    jz     $ + 10
    mov    rbp, [rel debug_counter]
    int3
%endif
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
    dw 0x0206                            ; e_ovno                | e_ovno

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

    dw    SUBSYSTEM_EFI_APPLICATION      ; Subsystem (checked)

HOLE4:
    PAD_CHECK HOLE4, 38

    dd 6                                 ; NumberOfRvaAndSizes (need 6, checked)

; EFI_IMAGE_DIRECTORY_ENTRY_{EXPORT,IMPORT,RESOURCE,EXCEPTION} can be whatever.
HOLE5:
    PAD_CHECK HOLE5, 32

    ; These are needed and checked
    dq 0                                 ; EFI_IMAGE_DIRECTORY_ENTRY_SECURITY
    dq 0                                 ; EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC

pe_opt_header_end:
section_header:
    db '.mebeim', 0     ; Name
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
    ; Keep stack 16-byte aligned!
    push   RegBootServices
    push   RegConOut
    sub    rsp, STACK_FRAME_SIZE

    mov    RegBootServices, [rdx + STRUCT_EFI_SYSTEM_TABLE.OffBootServices]
    mov    RegConOut, [rdx + STRUCT_EFI_SYSTEM_TABLE.OffConOut]

    ; gBS->LocateProtocol(&gEfiHttpServiceBindingProtocolGuid, NULL, (VOID **)&HttpServiceBinding);
    ;   OUT HttpServiceBinding @ rsp + STACK_OFF_SLOT1
    lea    rcx, [rel gEfiHttpServiceBindingProtocolGuid]
    xor    edx, edx
    lea    r8, [rsp + STACK_OFF_SLOT1]
    call   [RegBootServices + STRUCT_EFI_BOOT_SERVICES.OffLocateProtocol]
    DEBUG_CHECK_EFI_STATUS

    ; HttpChildHandle = NULL;
    ; HttpServiceBinding->CreateChild(HttpServiceBinding, &HttpChildHandle);
    ;   IN  HttpServiceBinding @ rsp + STACK_OFF_SLOT1
    ;   OUT HttpChildHandle    @ rsp + STACK_OFF_SLOT2
    mov    rcx, [rsp + STACK_OFF_SLOT1]
    lea    rdx, [rsp + STACK_OFF_SLOT2]
    mov    qword [rdx], 0
    call   [rcx + STRUCT_EFI_SERVICE_BINDING_PROTOCOL.OffCreateChild]
    DEBUG_CHECK_EFI_STATUS

    ; gBS->HandleProtocol(HttpChildHandle, &gEfiHttpProtocolGuid, (VOID **)&HttpProtocol);
    ;   OUT HttpProtocol    @ rsp + STACK_OFF_SLOT1
    ;   IN  HttpChildHandle @ rsp + STACK_OFF_SLOT2
    mov    rcx, [rsp + STACK_OFF_SLOT2]
    lea    rdx, [rel gEfiHttpProtocolGuid]
    lea    r8, [rsp + STACK_OFF_SLOT1]
    call   [RegBootServices + STRUCT_EFI_BOOT_SERVICES.OffHandleProtocol]
    DEBUG_CHECK_EFI_STATUS

    ; Find image base, put it in RCX to use as relocation offset
    call   .here
.here:
    pop    rcx
    sub    rcx, .here

    ; Point RAX to first thing that needs to be relocated
    lea    rax, [rel reloc0]

    ; Perform all relocations
    add    qword [rax + reloc0 - reloc0], rcx
    add    qword [rax + reloc1 - reloc0], rcx
    add    qword [rax + reloc2 - reloc0], rcx
    add    qword [rax + reloc3 - reloc0], rcx
    add    qword [rax + reloc4 - reloc0], rcx
    add    qword [rax + reloc5 - reloc0], rcx
    add    qword [rax + reloc6 - reloc0], rcx
    add    qword [rax + reloc7 - reloc0], rcx
    add    qword [rax + reloc8 - reloc0], rcx
    add    qword [rax + reloc9 - reloc0], rcx

    ; HttpProtocol->Configure(HttpProtocol, &HttpConfigData);
    ;   IN  HttpProtocol @ rsp + STACK_OFF_SLOT1
    mov    rcx, [rsp + STACK_OFF_SLOT1]
    lea    rdx, [rel HttpConfigData]
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffConfigure]
    DEBUG_CHECK_EFI_STATUS

    ; HttpProtocol->Request(HttpProtocol, &RequestToken);
    ;   IN  HttpProtocol @ rsp + STACK_OFF_SLOT1
    mov    rcx, [rsp + STACK_OFF_SLOT1]
    lea    rdx, [rel RequestToken]
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffRequest]
    DEBUG_CHECK_EFI_STATUS

    ; HttpProtocol->Response(HttpProtocol, &ResponseToken);
    ;   IN  HttpProtocol @ rsp + STACK_OFF_SLOT1
    mov    rcx, [rsp + STACK_OFF_SLOT1]
    lea    rdx, [rel ResponseToken]
    call   [rcx + STRUCT_EFI_HTTP_PROTOCOL.OffResponse]
    DEBUG_CHECK_EFI_STATUS

    ; Setup RSI/RDI for LODSB/STOSW and RCX for LOOP
    lea    rsi, [rel ResponseBuffer]
    lea    rdi, [rel ResponseBuffer + EXPECTED_RESPONSE_SIZE]
    mov    rcx, [rel ResponseMessage + STRUCT_EFI_HTTP_MESSAGE.OffBodyLength]
    mov    rdx, rdi

    ; Convert response from ASCII to UTF-16-LE using a nice LODSB + STOSW loop.
    ; This turns each byte into 2 (the original followed by a zero). We write
    ; the result starting from ResponseBuffer, overwriting data that we don't
    ; need anymore. The response will be small enough anyway.
    cld
    xor    ax, ax
.convert:
    lodsb
    stosw
    loop   .convert

    ; NULterminate UTF-16 string
    xor    ax, ax
    stosw

    ; SystemTable->ConOut->OutputString(SystemTable->ConOut, ResponseBuffer);
    mov    rcx, RegConOut
    call   [rcx + STRUCT_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OffOutputString]
    DEBUG_CHECK_EFI_STATUS

    ; Destroy stack frame, restore callee-saved registers and return.
    add    rsp, STACK_FRAME_SIZE
    pop    RegConOut
    pop    RegBootServices
    xor    eax, eax
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

; Overlap Http4AccessPoint with HttpConfigData:
; UseDefaultAddress == HttpVersion11 and the rest is zeroed.
Http4AccessPoint:
HttpConfigData:                                  ; EFI_HTTP_CONFIG_DATA                   | EFI_HTTPv4_ACCESS_POINT
        dd ENUM_EFI_HTTP_VERSION.HttpVersion11   ;     EFI_HTTP_VERSION HttpVersion;      |     UseDefaultAddress
        dd 0                                     ;     UINT32 TimeOutMillisec;            |     ...
        db 0                                     ;     BOOLEAN LocalAddressIsIPv6;        |
        times 7 db 0                             ;     (pad)                              |
reloc0: dq Http4AccessPoint                      ;     EFI_HTTPv4_ACCESS_POINT *IPv4Node; |

RequestData:                                     ; EFI_HTTP_REQUEST_DATA
        dd ENUM_EFI_HTTP_METHOD.HttpMethodGet    ;     EFI_HTTP_METHOD Method
        times 4 db 0                             ;     (pad)
reloc1: dq strUrl                                ;     CHAR16 *Url

RequestHeader:                                   ; EFI_HTTP_HEADER
reloc2: dq strHostHeaderName                     ;     CHAR8 *FieldName
reloc3: dq strHostHeaderValue                    ;     CHAR8 *FieldValue

RequestMessage:                                  ; EFI_HTTP_MESSAGE
reloc4: dq RequestData                           ;     EFI_HTTP_REQUEST_DATA *Request;
        dq 1                                     ;     UINTN HeaderCount;
reloc5: dq RequestHeader                         ;     EFI_HTTP_HEADER *Headers;
        dq 0                                     ;     UINTN BodyLength;
        dq 0                                     ;     VOID *Body;

RequestToken:                                    ; EFI_HTTP_TOKEN
        dq 0                                     ;     EFI_EVENT Event;
        dq 0                                     ;     EFI_STATUS Status;
reloc6: dq RequestMessage                        ;     EFI_HTTP_MESSAGE *Message;

ResponseData:                                    ; EFI_HTTP_RESPONSE_DATA
        dd 0                                     ;     EFI_HTTP_STATUS_CODE StatusCode;

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

%ifdef DEBUG
debug_counter:
    db 0
%endif

; We can go past the end of the file, memory will be mapped RWX here anyway as
; we are smaller than 1 page.
ResponseBuffer:

END:
