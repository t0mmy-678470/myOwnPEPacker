COMPRESSION_FORMAT_LZNT1        equ     2
PAGE_READWRITE                  equ     4

CREATE_ALWAYS                   equ     2
FILE_WRITE_DATA                 equ     2

PAGE_EXECUTE_READWRITE          equ     40h
PAGE_READWRITE                  equ     4 

MEM_COMMIT                      equ     1000h
MEM_RESERVE                     equ     2000h

tebProcessEnvironmentBlock      equ     30h
pebLdr                          equ     18h
imageBaseAddr                   equ     8
ldrInLoadOrderModuleList        equ     10h
ldrInMemmoryOrderModuleList     equ     20h
mlDllBase                       equ     30h

lfanew                          equ     3ch

IMAGE_DIRECTORY_ENTRY_EXPORT    equ     88h ; idx 0 ; from nt header offset ; 18+70
IMAGE_DIRECTORY_ENTRY_IMPORT    equ     90h ; idx 1 ; from nt header offset
IMAGE_DIRECTORY_ENTRY_RELOCS    equ     0b0h ; idx 5;  from nt header offset

IMAGE_REL_BASED_HIGHLOW         equ     3

struc    mapstk
.hImage: resd 1
endstruc

struc   krncrcstk
.kLoadLibraryA:          resd 1
.kGetProcAddress:        resd 1
endstruc

struc _IMAGE_FILE_HEADER
.fhMachine:              resw 1
.fhNumberOfSections:     resw 1
.fhTimeDateStamp:        resd 1
.fhPointerToSymbolTable: resd 1
.fhNumberOfSymbols:      resd 1
.fhSizeOfOptionalHeader: resw 1
.fhCharacteristics:      resw 1
endstruc

struc _IMAGE_OPTIONAL_HEADER
.ohMagic:                       resw 1
.ohMajorLinkerVersion:          resb 1
.ohMinorLinkerVersion:          resb 1
.ohSizeOfCode:                  resd 1
.ohSizeOfInitializedData:       resd 1
.ohSizeOfUninitializedData:     resd 1
.ohAddressOfEntryPoint:         resd 1
.ohBaseOfCode:                  resd 1
.ohBaseOfData:                  resd 1
.ohImageBasex:                  resq 1
.ohSectionAlignment:            resd 1
.ohFileAlignment:               resd 1
.ohMajorOperatingSystemVersion: resw 1
.ohMinorOperatingSystemVersion: resw 1
.ohMajorImageVersion:           resw 1
.ohMinorImageVersion:           resw 1
.ohMajorSubsystemVersion:       resw 1
.ohMinorSubsystemVersion:       resw 1
.ohWin32VersionValue:           resd 1
.ohSizeOfImage:                 resd 1
.ohSizeOfHeaders:               resd 1
endstruc

struc  _IMAGE_NT_HEADERS
.nthSignature:      resd 1
.nthFileHeader:     resb _IMAGE_FILE_HEADER_size
.nthOptionalHeader: resb _IMAGE_OPTIONAL_HEADER_size
endstruc

struc _IMAGE_SECTION_HEADER
.shName:                 resb 8
.shVirtualSize:          resd 1
.shVirtualAddress:       resd 1
.shSizeOfRawData:        resd 1
.shPointerToRawData:     resd 1
.shPointerToRelocations: resd 1
.shPointerToLinenumbers: resd 1
.shNumberOfRelocations:  resw 1
.shNumberOfLinenumbers:  resw 1
.shCharacteristics:      resd 1
endstruc

struc _IMAGE_IMPORT_DESCRIPTOR
.idOriginalFirstThunk: resd 1
.idTimeDateStamp:      resd 1
.idForwarderChain:     resd 1
.idName:               resd 1
.idFirstThunk:         resd 1
endstruc

struc IMAGE_BASE_RELOCATION
.rePageRVA:     resd 1
.reSizeOfBlock: resd 1
endstruc

struc _IMAGE_EXPORT_DIRECTORY
.edCharacteristics:       resd 1
.edTimeDateStamp:         resd 1
.edMajorVersion:          resw 1
.edMinorVersion:          resw 1
.edName:                  resd 1
.edBase:                  resd 1
.edNumberOfFunctions:     resd 1
.edNumberOfNames:         resd 1
.edAddressOfFunctions:    resd 1
.edAddressOfNames:        resd 1
.edAddressOfNameOrdinals: resd 1
endstruc                                   