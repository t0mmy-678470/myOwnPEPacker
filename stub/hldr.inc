ORIGINAL_SIZE                   equ     10h

COMPRESSION_FORMAT_LZNT1        equ     2

CREATE_ALWAYS                   equ     2
FILE_WRITE_DATA                 equ     2

PAGE_EXECUTE_READ               equ     20h
PAGE_EXECUTE_READWRITE          equ     40h
PAGE_READWRITE                  equ     4 

MEM_COMMIT                      equ     1000h
MEM_RESERVE                     equ     2000h

tebProcessEnvironmentBlock      equ     60h
pebLdr                          equ     18h
imageBaseAddr                   equ     8
ldrInLoadOrderModuleList        equ     10h
ldrInMemmoryOrderModuleList     equ     20h
mlDllBase                       equ     30h

lfanew                          equ     3ch

; IMAGE_DIRECTORY_ENTRY_EXPORT    equ     88h ; idx 0 ; from nt header offset ; 18+70
; IMAGE_DIRECTORY_ENTRY_IMPORT    equ     90h ; idx 1 ; from nt header offset
; IMAGE_DIRECTORY_ENTRY_RELOCS    equ     0b0h ; idx 5;  from nt header offset

IMAGE_REL_BASED_HIGHLOW         equ     3

; struc mapstk{
;     hImage dd ?
; }

; struc krncrcstk{{
;     kLoadLibraryA          dd ?
;     kGetProcAddress        dd ?
; }

; struc _IMAGE_FILE_HEADER{
;     fhMachine              dw ?
;     fhNumberOfSections     dw ?
;     fhTimeDateStamp        dd ?
;     fhPointerToSymbolTable dd ?
;     fhNumberOfSymbols      dd ?
;     fhSizeOfOptionalHeader dw ?
;     fhCharacteristics      dw ?
; }

_IMAGE_FILE_HEADER_Machine              equ 0
_IMAGE_FILE_HEADER_NumberOfSections     equ 2
_IMAGE_FILE_HEADER_TimeDateStamp        equ 4
_IMAGE_FILE_HEADER_PointerToSymbolTable equ 8
_IMAGE_FILE_HEADER_NumberOfSymbols      equ 0ch
_IMAGE_FILE_HEADER_SizeOfOptionalHeader equ 10h
_IMAGE_FILE_HEADER_Characteristics      equ 12h
_IMAGE_FILE_HEADER_ze                   equ 14h

; struc _IMAGE_OPTIONAL_HEADER{
;     ohMagic                       dw ?
;     ohMajorLinkerVersion          db ?
;     ohMinorLinkerVersion          db ?
;     ohSizeOfCode                  dd ?
;     ohSizeOfInitializedData       dd ?
;     ohSizeOfUninitializedData     dd ?
;     ohAddressOfEntryPoint         dd ?
;     ohBaseOfCode                  dd ?
;     ohBaseOfData                  dd ?
;     ohImageBasex                  dq ?
;     ohSectionAlignment            dd ?
;     ohFileAlignment               dd ?
;     ohMajorOperatingSystemVersion dw ?
;     ohMinorOperatingSystemVersion dw ?
;     ohMajorImageVersion           dw ?
;     ohMinorImageVersion           dw ?
;     ohMajorSubsystemVersion       dw ?
;     ohMinorSubsystemVersion       dw ?
;     ohWin32VersionValue           dd ?
;     ohSizeOfImage                 dd ?
;     ohSizeOfHeaders               dd ?
; }

_IMAGE_OPTIONAL_HEADER_Magic                       equ 0
_IMAGE_OPTIONAL_HEADER_MajorLinkerVersion          equ 2
_IMAGE_OPTIONAL_HEADER_MinorLinkerVersion          equ 3
_IMAGE_OPTIONAL_HEADER_SizeOfCode                  equ 04h
_IMAGE_OPTIONAL_HEADER_SizeOfInitializedData       equ 08h
_IMAGE_OPTIONAL_HEADER_SizeOfUninitializedData     equ 0ch
_IMAGE_OPTIONAL_HEADER_AddressOfEntryPoint         equ 10h
_IMAGE_OPTIONAL_HEADER_BaseOfCode                  equ 14h
_IMAGE_OPTIONAL_HEADER_ImageBase                   equ 18h
_IMAGE_OPTIONAL_HEADER_SectionAlignment            equ 20h
_IMAGE_OPTIONAL_HEADER_FileAlignment               equ 24h
_IMAGE_OPTIONAL_HEADER_MajorOperatingSystemVersion equ 28h
_IMAGE_OPTIONAL_HEADER_MinorOperatingSystemVersion equ 2ah
_IMAGE_OPTIONAL_HEADER_MajorImageVersion           equ 2ch
_IMAGE_OPTIONAL_HEADER_MinorImageVersion           equ 2eh
_IMAGE_OPTIONAL_HEADER_MajorSubsystemVersion       equ 30h
_IMAGE_OPTIONAL_HEADER_MinorSubsystemVersion       equ 32h
_IMAGE_OPTIONAL_HEADER_Win32VersionValue           equ 34h
_IMAGE_OPTIONAL_HEADER_SizeOfImage                 equ 38h
_IMAGE_OPTIONAL_HEADER_SizeOfHeader                equ 3ch

_IMAGE_OPTIONAL_HEADER_DataDirectory               equ 70h
_IMAGE_OPTIONAL_HEADER_size                        equ f0h

; from NT header
IMAGE_DIRECTORY_ENTRY_EXPORT                       equ  88h   ; Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT                       equ  90h   ; Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE                     equ  98h   ; Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION                    equ 0a0h   ; Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY                     equ 0a8h   ; Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC                    equ 0b0h   ; Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG                        equ 0b8h   ; Debug Directory
IMAGE_DIRECTORY_ENTRY_COPYRIGHT                    equ 0c0h   ; (X86 usage)
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE                 equ 0c0h   ; Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR                    equ 0c8h   ; RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS                          equ 0d0h   ; TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG                  equ 0d8h   ; Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT                 equ 0e0h   ; Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT                          equ 0e8h   ; Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT                 equ 0f0h   ; Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR               equ 0f8h   ; COM Runtime descriptor

DIRECTORY_VirtualAddress                           equ 0
DIRECTORY_Size                                     equ 4
_IMAGE_DATA_DIRECTORY_size                         equ 8


_IMAGE_NT_HEADERS_Signature                        equ 0 
_IMAGE_NT_HEADERS_FileHeader                       equ 4 
_IMAGE_NT_HEADERS_OptionalHeader                   equ 18h
_IMAGE_NT_HEADERS_size                             equ 108h


; struc _IMAGE_SECTION_HEADER{
;     shName                 rb 8
;     shVirtualSize          dd ?
;     shVirtualAddress       dd ?
;     shSizeOfRawData        dd ?
;     shPointerToRawData     dd ?
;     shPointerToRelocations dd ?
;     shPointerToLinenumbers dd ?
;     shNumberOfRelocations  dw ?
;     shNumberOfLinenumbers  dw ?
;     shCharacteristics      dd ?
; }

_IMAGE_SECTION_HEADER_Name                      equ 0
_IMAGE_SECTION_HEADER_VirtualSize               equ 8
_IMAGE_SECTION_HEADER_VirtualAddress            equ 0ch
_IMAGE_SECTION_HEADER_SizeOfRawData             equ 10h
_IMAGE_SECTION_HEADER_PointerToRawData          equ 14h
_IMAGE_SECTION_HEADER_PointerToRelocations      equ 18h
_IMAGE_SECTION_HEADER_PointerToLinenumbers      equ 1ch
_IMAGE_SECTION_HEADER_NumberOfRelocations       equ 20h
_IMAGE_SECTION_HEADER_NumberOfLinenumbers       equ 22h
_IMAGE_SECTION_HEADER_Characteristics           equ 24h
_IMAGE_SECTION_HEADER_size                      equ 28h


; struc _IMAGE_IMPORT_DESCRIPTOR{
;     idOriginalFirstThunk dd ?
;     idTimeDateStamp      dd ?
;     idForwarderChain     dd ?
;     idName               dd ?
;     idFirstThunk         dd ?
; }

_IMAGE_IMPORT_DESCRIPTOR_OriginalFirstThunk equ 0
_IMAGE_IMPORT_DESCRIPTOR_TimeDateStamp      equ 4
_IMAGE_IMPORT_DESCRIPTOR_ForwarderChain     equ 8
_IMAGE_IMPORT_DESCRIPTOR_Name               equ 0ch
_IMAGE_IMPORT_DESCRIPTOR_FirstThunk         equ 10h
_IMAGE_IMPORT_DESCRIPTOR_size               equ 14h


; struc IMAGE_BASE_RELOCATION{
;     rePageRVA     dd ?
;     reSizeOfBlock dd ?
; }

IMAGE_BASE_RELOCATION_PageRVA     equ 0
IMAGE_BASE_RELOCATION_SizeOfBlock equ 4
IMAGE_BASE_RELOCATION_size        equ 8


; struc _IMAGE_EXPORT_DIRECTORY{
;     edCharacteristics       dd ?
;     edTimeDateStamp         dd ?
;     edMajorVersion          dw ?
;     edMinorVersion          dw ?
;     edName                  dd ?
;     edBase                  dd ?
;     edNumberOfFunctions     dd ?
;     edNumberOfNames         dd ?
;     edAddressOfFunctions    dd ?
;     edAddressOfNames        dd ?
;     edAddressOfNameOrdinals dd ?
; }                                   

_IMAGE_EXPORT_DIRECTORY_Characteristics       equ 0
_IMAGE_EXPORT_DIRECTORY_TimeDateStamp         equ 4
_IMAGE_EXPORT_DIRECTORY_MajorVersion          equ 8
_IMAGE_EXPORT_DIRECTORY_MinorVersion          equ 0ah
_IMAGE_EXPORT_DIRECTORY_Name                  equ 0ch
_IMAGE_EXPORT_DIRECTORY_Base                  equ 10h
_IMAGE_EXPORT_DIRECTORY_NumberOfFunctions     equ 14h
_IMAGE_EXPORT_DIRECTORY_NumberOfNames         equ 18h
_IMAGE_EXPORT_DIRECTORY_AddressOfFunctions    equ 1ch
_IMAGE_EXPORT_DIRECTORY_AddressOfNames        equ 20h
_IMAGE_EXPORT_DIRECTORY_AddressOfNameOrdinals equ 24h
_IMAGE_EXPORT_DIRECTORY_size                  equ 28h


COMP_HDR_oep                                  equ 0
COMP_HDR_import_addr                          equ 4
COMP_HDR_import_size                          equ 8
COMP_HDR_export_addr                          equ 0ch
COMP_HDR_export_size                          equ 10h
COMP_HDR_iat_addr                             equ 14h
COMP_HDR_iat_size                             equ 18h
COMP_HDR_reloc_addr                           equ 1ch
COMP_HDR_reloc_size                           equ 20h

stack_headerAddr                              equ 8
stack_sectionNum                              equ 10h
stack_imageBase                                equ 18h
stack_allocMemAddr                            equ 20h
stack_mop1HdrAddr                             equ 28h
stack_decompressedSize                        equ 30h
stack_tmp                                     equ 38h


