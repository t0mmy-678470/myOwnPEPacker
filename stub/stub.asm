format binary
use64
org 0

include "hldr.inc"

; section .text

_main:
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    pushfq
    push rbp
    mov rbp, rsp
    sub rsp, 0x58
    ; -0x8:  exe section header address
    ; -0x10:  exe section header num
    ; -0x18: imageBase
    ; -0x20: allocation memory addr 
    ; -0x28: mop1 header addr
    ; -0x30: mop1 decompressed size
    ; -0x38: tmp buffer

    call get_sectionHeaderAddr_sectionNums_imageBase
    mov [rbp-0x8], rax ; exe section header address
    mov [rbp-0x10], rbx ; exe section header num
    mov [rbp-0x18], rcx ; exe image base

    ;;;;;;;;;;;;;; find compress data address
    mov rax, [rbp-0x10] ; total section num
    sub rax, 3
    mov bl, _IMAGE_SECTION_HEADER_size
    mul bl
    add rax, [rbp-0x8] ; mop1 header addr
    mov [rbp-0x28], rax ; mop1 header addr

    ;;;;;;;;;;;;;;;; alloc memory to store compressed section
    ; can't use movzx rax, ... ; mov eax, ... will extend to rax automatically
    ; mov ecx, DWORD [rax + _IMAGE_SECTION_HEADER_VirtualSize] ; size to alloc, decompressed data size
    mov ecx, [rax + _IMAGE_SECTION_HEADER_VirtualAddress]
    add rcx, [rbp-0x18]
    call aPsafe_get_orig_size
    mov rcx, rax
    mov [rbp-0x30], rcx
    call alloc_mem
    mov [rbp - 0x20], rax ; allocated memory address

    ;;;;;;;;;;;;;;;; depack mop1 to location of alloced buffer
    mov rax, [rbp - 0x28]; mop1 header addr
    mov ecx, DWORD [rax + _IMAGE_SECTION_HEADER_VirtualAddress] ; mop1 rva
    add rcx, [rbp - 0x18] ; rcx = mop1 virtual addr = src addr
    mov edx, DWORD [rax + _IMAGE_SECTION_HEADER_VirtualSize]; src len:
    mov r8,  [rbp - 0x20]; dst
    mov r9d,  [rbp - 0x30]; dst len
    sub rsp, 40
    call aPsafe_depack
    add rsp, 40

    ; get write permit to modify header
    mov rcx, [rbp - stack_imageBase]; rcx = start_addr
    mov rdx, 0x500; rdx = size
    mov r8, PAGE_READWRITE; r8  = new_protect
    mov r9, [rbp - stack_tmp]; r9  = ret_old_protect
    call get_permit

    mov rcx, [rbp - stack_imageBase]
    mov rdx, [rbp - stack_allocMemAddr] 
    call recover_header
    
    call recover_iat
    ; go to oep
    mov rcx, [rbp - stack_imageBase]
    mov eax, [rcx + _IMAGE_NT_HEADERS_OptionalHeader + _IMAGE_OPTIONAL_HEADER_AddressOfEntryPoint]
    add rax, rcx
    jmp rax

    ; add rsp, 0x58
    leave
    popfq
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax

; rcx = start_addr
; rdx = size
; r8  = new_protect
; r9  = ret_old_protect
get_permit:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20 

    mov [rbp - 0x8], rcx
    mov [rbp - 0x10], rdx
    mov [rbp - 0x18], r8
    mov [rbp - 0x20], r9

    call get_kernel32_dll_base
    mov rcx, rax      ; rcx: dll_base
    lea rdx, [.name]  ; rdx: target_name_address
    mov r8 , 15       ; r8: target_name_len
    call find_proc_addr

    mov rcx, [rbp - 0x8]
    mov rdx, [rbp - 0x10]
    mov r8, [rbp - 0x18]
    mov r9, [rbp - 0x20]
    call rax

    leave
    ret

  .name:
    db "VirtualProtect", 0

; rcx = imageBase
; rdx = decompressedAddr
recover_iat:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    ; -0x8 : cur import table addr
    ; -0x10: loadLibraryA addr
    ; -0x18: getProcAddress addr

    mov rbx, rcx                       ; pe image base
    movzx rax, WORD [rbx + lfanew]     ; nt header offset
    add rax, rbx                       ; nt header address
    mov eax, [rax + IMAGE_DIRECTORY_ENTRY_IMPORT + DIRECTORY_VirtualAddress]
    add rax, rbx                       ; import table addr
    mov [rbp-0x8], rax

    ; get loadLibrary func address
    call get_kernel32_dll_base
    mov rcx, rax          ; arg1 rcx: dll_base
    lea rdx, [.loadLibraryAName]  ; arg2 rdx: target_name_address
    mov r8, 13            ; arg3 r8: target_name_len
    call find_proc_addr
    mov [rbp - 0x10], rax

    ; get getProcAddress func address
    call get_kernel32_dll_base
    mov rcx, rax          ; arg1 rcx: dll_base
    lea rdx, [.getProcAddressName]  ; arg2 rdx: target_name_address
    mov r8, 15            ; arg3 r8: target_name_len
    call find_proc_addr
    mov [rbp - 0x18], rax

  .go_next_import_table:
    ; check import table not empty
    mov rcx, _IMAGE_IMPORT_DESCRIPTOR_size
    mov rax, [rbp - 0x8]

    .check_exit:
      dec rcx
      cmp BYTE [rax + rcx], 0                   ; import_table[rcx] == 0?
      jne .conti_make_iat
      cmp rcx, 0
      je .exit
      jmp .check_exit

    .conti_make_iat:      
      ; get dll handle
      mov rax, [rbp - 0x8]    ; cur import table addr
      mov ecx, [rax + _IMAGE_IMPORT_DESCRIPTOR_Name]
      add rcx, rbx            ; library name
      call QWORD [rbp - 0x10]       ; call loadLibraryA
        ; rax = library handle

      ; get func addr
      mov rcx, rax            ; getProcAddress arg1: dll handle
      mov rax, [rbp - 0x8]    ; cur import table
      mov r10, [rax + _IMAGE_IMPORT_DESCRIPTOR_FirstThunk]
      add r10, rbx            ; dll import name table addr's addr

      .find_func_addr:
        cmp QWORD [r10], 0
        je .dll_func_fin
        mov rdx, r10
        add rdx, 2              ; func name address (because first two bytes are Hint)
        call QWORD [rbp - 0x18]       ; call getProcAddress
        cmp rax, 0             
        jne .find_func_addr_success
        int 3                   ; find function error

        .find_func_addr_success:
          mov [r10], rax
          add r10, 8              ; go to next import name table addr's addr
          jmp .find_func_addr

      .dll_func_fin:
        add QWORD [rbp - 0x8], _IMAGE_IMPORT_DESCRIPTOR_size  ; get next import table addr
        jmp .go_next_import_table

  .exit:
    leave 
    ret

  .loadLibraryAName:
    db "LoadLibraryA", 0
  .getProcAddressName:
    db "getProcAddress", 0

; rcx = imageBase
; rdx = decompressedAddr
recover_header:
    push rbp
    mov rbp, rsp

    movzx rax, WORD [rcx + lfanew]     ; nt header offset
    add rcx, rax                       ; nt header address
    ; recover oep
    mov eax, [rdx + COMP_HDR_oep]
    mov DWORD [rcx + _IMAGE_NT_HEADERS_OptionalHeader + \
            _IMAGE_OPTIONAL_HEADER_AddressOfEntryPoint], eax
    ; recover import addr
    mov eax, [rdx + COMP_HDR_import_addr]
    mov DWORD [rcx + IMAGE_DIRECTORY_ENTRY_IMPORT + DIRECTORY_VirtualAddress], eax
    ; recover import size
    mov eax, [rdx + COMP_HDR_import_size]
    mov DWORD [rcx + IMAGE_DIRECTORY_ENTRY_IMPORT + DIRECTORY_Size], eax
    ; recover export addr
    mov eax, [rdx + COMP_HDR_export_addr]
    mov DWORD [rcx + IMAGE_DIRECTORY_ENTRY_EXPORT + DIRECTORY_VirtualAddress], eax
    ; recover export size
    mov eax, [rdx + COMP_HDR_export_size]
    mov DWORD [rcx + IMAGE_DIRECTORY_ENTRY_EXPORT + DIRECTORY_Size], eax
    ; recover IAT addr
    mov eax, [rdx + COMP_HDR_iat_addr]
    mov DWORD [rcx + IMAGE_DIRECTORY_ENTRY_IAT + DIRECTORY_VirtualAddress], eax
    ; recover IAT size
    mov eax, [rdx + COMP_HDR_iat_size]
    mov DWORD [rcx + IMAGE_DIRECTORY_ENTRY_IAT + DIRECTORY_Size], eax
    ; recover reloc addr
    mov eax, [rdx + COMP_HDR_reloc_addr]
    mov DWORD [rcx + IMAGE_DIRECTORY_ENTRY_BASERELOC + DIRECTORY_VirtualAddress], eax
    ; recover reloc size
    mov eax, [rdx + COMP_HDR_reloc_size]
    mov DWORD [rcx + IMAGE_DIRECTORY_ENTRY_BASERELOC + DIRECTORY_Size], eax

    leave
    ret


; rcx = string addr
; ret rax = string len
get_string_len:
    push rsi
    mov rsi, rcx
    mov rax, 0
  .comp:
    cmp BYTE [rsi + rax], 0
    je .fin
    inc rax
    jmp .comp
  .fin :
    pop rsi
    ret

; ret rax = sectionHeaderAddr
; ret rbx = sectionNums
; ret rcx = imageBase
get_sectionHeaderAddr_sectionNums_imageBase:
    push rbp
    mov rbp, rsp
    mov rax, QWORD [gs:0x60]  ; get peb addr
    mov rax, [rax + pebLdr] ; get ldr addr
    mov rax, [rax + ldrInLoadOrderModuleList] ; exe ldr table entry
    mov rcx, [rax + mlDllBase] ; get exe image base
    mov eax, DWORD [rcx + lfanew]    ; get nt header address
    add rax, rcx
    movzx rbx, WORD [rax + _IMAGE_NT_HEADERS_FileHeader + _IMAGE_FILE_HEADER_NumberOfSections] ; get number of sections
    movzx rdx, WORD [rax + _IMAGE_NT_HEADERS_FileHeader + _IMAGE_FILE_HEADER_SizeOfOptionalHeader] ; get size of optional header
    lea rax, [rax + _IMAGE_NT_HEADERS_OptionalHeader + rdx] ; get section header address
    leave 
    ret

; ret rax = kernel32 dll base
get_kernel32_dll_base:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10

    mov rax, qword [gs:60h]  ; get peb addr
    mov rax, [rax + pebLdr] ; get ldr addr
    mov rax, [rax + ldrInLoadOrderModuleList] ; exe ldr table entry
    mov rax, [rax] ; ntdll ldr table entry
    mov rax, [rax] ; kernel32 ldr table entry
    mov rax, [rax + mlDllBase] ; get dll base

    leave
    ret

; rcx: dll_base
; rdx: target_name_address
; r8: target_name_len
find_proc_addr:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10

    push rbx
    push rsi
    push rdi
    push r9

    mov r10, rcx ; target dll base
    mov rdi, rdx ; target_name_address
    mov ebx, DWORD [r10 + lfanew] ; nt header offset
    add rbx, r10                  ; nt header
    mov ebx, DWORD [rbx + IMAGE_DIRECTORY_ENTRY_EXPORT] ; export table rva
    add rbx, r10        ; export table address
    mov r9d, DWORD [rbx + _IMAGE_EXPORT_DIRECTORY_NumberOfNames] ; number of name
    xor rdx, rdx ; idx
    mov eax, [rbx + _IMAGE_EXPORT_DIRECTORY_AddressOfNames] ; get name arr rva
    add rax, r10                                            ; get name arr address
    dec rdx    
    push rdi     ; store old rdi

  .search:
    inc rdx ; idx++
    cmp rdx, r9 ; idx == arr len ?
    je .not_found
    mov esi, [rax + rdx*4] ; get name rva
    add rsi, r10
    mov rdi, [rsp]
    mov rcx, r8
    cld
    repe cmpsb
    jnz .search
    cmp rcx, 0
    jne .search
    
  .success:
    mov eax, [rbx + _IMAGE_EXPORT_DIRECTORY_AddressOfNameOrdinals] ; get name ordinal arr rva
    add rax, r10           ; get name ordinal arr address
    mov  dx, [rax + rdx*2] ; new idx for target func arr
    mov eax, [rbx + _IMAGE_EXPORT_DIRECTORY_AddressOfFunctions] ; get function arr rva
    add rax, r10           ; get function arr rva
    mov eax, [rax + rdx*4]
    add rax, r10
    jmp .exit

  .not_found: ; return null
    xor rax, rax

  .exit:
    sub rsp, 0x8
    pop r9
    pop rdi
    pop rsi
    pop rbx
    leave
    ret

; rcx = size
alloc_mem:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10
    mov [rbp-0x8], rcx
    call get_kernel32_dll_base
    mov rcx, rax
    lea rdx, [.name]
    mov r8,  13
    call find_proc_addr
    mov r10, rax ; virtualalloc func address
    ; call get_sectionHeaderAddr_and_sectionNums
    
    mov rcx, 0 ; virtualAlloc arg1 lpaddress
    ; movzx rdx, DWORD [rax + _IMAGE_SECTION_HEADER.shSizeOfRawData] ; vurtualAlloc arg2 dwsize (mop raw size)
    mov edx, [rbp-0x8]       ; vurtualAlloc arg2 dwsize
    ; lea r8, [MEM_COMMIT + MEM_RESERVE] ; []內會變成 imageBase + MEM_COMMIT + MEM_RESERVE
    mov r8, MEM_COMMIT
    or r8,  MEM_RESERVE ; vurtualAlloc arg3 flAllocationType
    mov r9, PAGE_READWRITE ; virtualAlloc arg4 flProtect
    call r10               ; call virtualAlloc

    leave
    ret

  .name: ; 函數名稱之後可以用 xor 簡單加密
    db "VirtualAlloc",0

; rcx = src_mem
; rdx = dst_mem
; r8  = len
copy_mem:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, r8
    cld           ; set DF=0
    rep movsb     ; copy from rsi to rdi
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, r8

    leave 
    ret

;;;;;;;;;;;;;;;;;;; aPLib ;;;;;;;;;;;;;;;;;;;

macro docrcM
{
    mov    r9, 0x000000ff
    and    r9, rax
    shr    eax, 8
    xor    eax, [r8+r9*4]
}

macro docrcbyteM
{
    xor    al, [rcx]
    add    rcx, 1
    docrcM
}

macro docrcdwordM
{
    xor    eax, [rcx]
    add    rcx, 4
    docrcM
    docrcM
    docrcM
    docrcM
}

; =============================================================

aP_crc32:
    ; aP_crc32(const void *source, unsigned int length)

    lea    r8, [aP_crctab]    ; r8 -> crctab

    sub    rax, rax

    test   rcx, rcx
    jz     .c_exit

    dec    rax

    test   rdx, rdx
    jz     .c_done

  .c_align_loop:
    test   rcx, 3
    jz     .c_aligned_now
    docrcbyteM
    add    rdx, -1
    jnz    .c_align_loop

  .c_aligned_now:
    mov    r10, rdx
    and    r10, 7
    shr    rdx, 3
    jz     .c_LT_eight

  .c_next_eight:
    docrcdwordM
    docrcdwordM
    add    rdx, -1
    jnz    .c_next_eight

  .c_LT_eight:
    mov    rdx, r10
    test   rdx, rdx
    jz     .c_done

  .c_last_loop:
    docrcbyteM
    add    rdx, -1
    jnz    .c_last_loop

  .c_done:
    not    eax

  .c_exit:
    ret

; =============================================================

aP_crctab  dd 000000000h, 077073096h, 0ee0e612ch, 0990951bah, 0076dc419h
           dd 0706af48fh, 0e963a535h, 09e6495a3h, 00edb8832h, 079dcb8a4h
           dd 0e0d5e91eh, 097d2d988h, 009b64c2bh, 07eb17cbdh, 0e7b82d07h
           dd 090bf1d91h, 01db71064h, 06ab020f2h, 0f3b97148h, 084be41deh
           dd 01adad47dh, 06ddde4ebh, 0f4d4b551h, 083d385c7h, 0136c9856h
           dd 0646ba8c0h, 0fd62f97ah, 08a65c9ech, 014015c4fh, 063066cd9h
           dd 0fa0f3d63h, 08d080df5h, 03b6e20c8h, 04c69105eh, 0d56041e4h
           dd 0a2677172h, 03c03e4d1h, 04b04d447h, 0d20d85fdh, 0a50ab56bh
           dd 035b5a8fah, 042b2986ch, 0dbbbc9d6h, 0acbcf940h, 032d86ce3h
           dd 045df5c75h, 0dcd60dcfh, 0abd13d59h, 026d930ach, 051de003ah
           dd 0c8d75180h, 0bfd06116h, 021b4f4b5h, 056b3c423h, 0cfba9599h
           dd 0b8bda50fh, 02802b89eh, 05f058808h, 0c60cd9b2h, 0b10be924h
           dd 02f6f7c87h, 058684c11h, 0c1611dabh, 0b6662d3dh, 076dc4190h
           dd 001db7106h, 098d220bch, 0efd5102ah, 071b18589h, 006b6b51fh
           dd 09fbfe4a5h, 0e8b8d433h, 07807c9a2h, 00f00f934h, 09609a88eh
           dd 0e10e9818h, 07f6a0dbbh, 0086d3d2dh, 091646c97h, 0e6635c01h
           dd 06b6b51f4h, 01c6c6162h, 0856530d8h, 0f262004eh, 06c0695edh
           dd 01b01a57bh, 08208f4c1h, 0f50fc457h, 065b0d9c6h, 012b7e950h
           dd 08bbeb8eah, 0fcb9887ch, 062dd1ddfh, 015da2d49h, 08cd37cf3h
           dd 0fbd44c65h, 04db26158h, 03ab551ceh, 0a3bc0074h, 0d4bb30e2h
           dd 04adfa541h, 03dd895d7h, 0a4d1c46dh, 0d3d6f4fbh, 04369e96ah
           dd 0346ed9fch, 0ad678846h, 0da60b8d0h, 044042d73h, 033031de5h
           dd 0aa0a4c5fh, 0dd0d7cc9h, 05005713ch, 0270241aah, 0be0b1010h
           dd 0c90c2086h, 05768b525h, 0206f85b3h, 0b966d409h, 0ce61e49fh
           dd 05edef90eh, 029d9c998h, 0b0d09822h, 0c7d7a8b4h, 059b33d17h
           dd 02eb40d81h, 0b7bd5c3bh, 0c0ba6cadh, 0edb88320h, 09abfb3b6h
           dd 003b6e20ch, 074b1d29ah, 0ead54739h, 09dd277afh, 004db2615h
           dd 073dc1683h, 0e3630b12h, 094643b84h, 00d6d6a3eh, 07a6a5aa8h
           dd 0e40ecf0bh, 09309ff9dh, 00a00ae27h, 07d079eb1h, 0f00f9344h
           dd 08708a3d2h, 01e01f268h, 06906c2feh, 0f762575dh, 0806567cbh
           dd 0196c3671h, 06e6b06e7h, 0fed41b76h, 089d32be0h, 010da7a5ah
           dd 067dd4acch, 0f9b9df6fh, 08ebeeff9h, 017b7be43h, 060b08ed5h
           dd 0d6d6a3e8h, 0a1d1937eh, 038d8c2c4h, 04fdff252h, 0d1bb67f1h
           dd 0a6bc5767h, 03fb506ddh, 048b2364bh, 0d80d2bdah, 0af0a1b4ch
           dd 036034af6h, 041047a60h, 0df60efc3h, 0a867df55h, 0316e8eefh
           dd 04669be79h, 0cb61b38ch, 0bc66831ah, 0256fd2a0h, 05268e236h
           dd 0cc0c7795h, 0bb0b4703h, 0220216b9h, 05505262fh, 0c5ba3bbeh
           dd 0b2bd0b28h, 02bb45a92h, 05cb36a04h, 0c2d7ffa7h, 0b5d0cf31h
           dd 02cd99e8bh, 05bdeae1dh, 09b64c2b0h, 0ec63f226h, 0756aa39ch
           dd 0026d930ah, 09c0906a9h, 0eb0e363fh, 072076785h, 005005713h
           dd 095bf4a82h, 0e2b87a14h, 07bb12baeh, 00cb61b38h, 092d28e9bh
           dd 0e5d5be0dh, 07cdcefb7h, 00bdbdf21h, 086d3d2d4h, 0f1d4e242h
           dd 068ddb3f8h, 01fda836eh, 081be16cdh, 0f6b9265bh, 06fb077e1h
           dd 018b74777h, 088085ae6h, 0ff0f6a70h, 066063bcah, 011010b5ch
           dd 08f659effh, 0f862ae69h, 0616bffd3h, 0166ccf45h, 0a00ae278h
           dd 0d70dd2eeh, 04e048354h, 03903b3c2h, 0a7672661h, 0d06016f7h
           dd 04969474dh, 03e6e77dbh, 0aed16a4ah, 0d9d65adch, 040df0b66h
           dd 037d83bf0h, 0a9bcae53h, 0debb9ec5h, 047b2cf7fh, 030b5ffe9h
           dd 0bdbdf21ch, 0cabac28ah, 053b39330h, 024b4a3a6h, 0bad03605h
           dd 0cdd70693h, 054de5729h, 023d967bfh, 0b3667a2eh, 0c4614ab8h
           dd 05d681b02h, 02a6f2b94h, 0b40bbe37h, 0c30c8ea1h, 05a05df1bh
           dd 02d02ef8dh

macro getbitM
{
    local .stillbitsleft

    add    dl, dl
    jnz    .stillbitsleft

    sub    r10, 1             ; read one byte from source
    jc     return_error       ;

    mov    dl, [rsi]
    add    rsi, 1

    add    dl, dl
    inc    dl
  .stillbitsleft:
}

macro domatchM reg
{
    local .more

    mov    r8, [rsp + 32]     ; r8 = dstlen
    sub    r8, r11            ; r8 = num written
    cmp    reg, r8
    ja     return_error

    sub    r11, rcx           ; write rcx bytes to destination
    jc     return_error       ;

    mov    r8, rdi
    sub    r8, reg

  .more:
    mov    al, [r8]
    add    r8, 1
    mov    [rdi], al
    add    rdi, 1
    sub    rcx, 1
    jnz    .more
}

macro getgammaM reg
{
    local .getmore
    mov    reg, 1
  .getmore:
    getbitM
    adc    reg, reg
    jc     return_error
    getbitM
    jc     .getmore
}


; =============================================================


aP_depack_asm_safe:
    ; aP_depack_asm_safe(const void *source,
    ;                    unsigned int srclen,
    ;                    void *destination,
    ;                    unsigned int dstlen)

    mov    [rsp + 8], r9
    mov    [rsp + 16], r8
    mov    [rsp + 24], rbp
    push   rbx
    push   rsi
    push   rdi

    mov    rsi, rcx
    mov    r10, rdx
    mov    rdi, r8
    mov    r11, r9

    test   rsi, rsi
    jz     return_error

    test   rdi, rdi
    jz     return_error

    or     rbp, -1

    cld
    xor    rdx, rdx

literal:
    sub    r10, 1             ; read one byte from source
    jc     return_error       ;

    mov    al, [rsi]
    add    rsi, 1

    sub    r11, 1             ; write one byte to destination
    jc     return_error       ;

    mov    [rdi], al
    add    rdi, 1

    mov    rbx, 2

nexttag:
    getbitM
    jnc    literal

    getbitM
    jnc    codepair

    xor    rax, rax

    getbitM
    jnc    shortmatch

    getbitM
    adc    rax, rax
    getbitM
    adc    rax, rax
    getbitM
    adc    rax, rax
    getbitM
    adc    rax, rax
    jz     .thewrite

    mov    r8, [rsp + 32]     ; r8 = dstlen
    sub    r8, r11            ; r8 = num written
    cmp    rax, r8
    ja     return_error

    mov    r8, rdi
    sub    r8, rax
    mov    al, [r8]

  .thewrite:
    sub    r11, 1             ; write one byte to destination
    jc     return_error       ;

    mov    [rdi], al
    add    rdi, 1

    mov    rbx, 2

    jmp    nexttag

codepair:
    getgammaM rax

    sub    rax, rbx

    mov    rbx, 1

    jnz    normalcodepair

    getgammaM rcx

    domatchM rbp

    jmp    nexttag

normalcodepair:
    add    rax, -1

    cmp    rax, 0x00fffffe
    ja     return_error

    shl    rax, 8

    sub    r10, 1             ; read one byte from source
    jc     return_error       ;

    mov    al, [rsi]
    add    rsi, 1

    mov    rbp, rax

    getgammaM ecx

    cmp    rax, 32000
    sbb    rcx, -1

    cmp    rax, 1280
    sbb    rcx, -1

    cmp    rax, 128
    adc    rcx, 0

    cmp    rax, 128
    adc    rcx, 0

    domatchM rax
    jmp    nexttag

shortmatch:
    sub    r10, 1             ; read one byte from source
    jc     return_error       ;

    mov    al, [rsi]
    add    rsi, 1

    xor    rcx, rcx
    db     0c0h, 0e8h, 001h
    jz     donedepacking

    adc    rcx, 2

    mov    rbp, rax

    domatchM rax

    mov    rbx, 1

    jmp    nexttag

return_error:
    or     rax, -1            ; return APLIB_ERROR in rax

    jmp    exit

donedepacking:
    mov    rax, rdi
    sub    rax, [rsp + 40]

exit:
    mov    rbp, [rsp + 48]
    pop    rdi
    pop    rsi
    pop    rbx

    ret

aPsafe_depack:
    ; aPsafe_depack(const void *source,
    ;               size_t srclen,
    ;               void *destination
    ;               size_t dstlen)

    mov    [rsp + 8], rcx
    mov    [rsp + 16], rdx
    mov    [rsp + 24], r8
    mov    [rsp + 32], r9
    push   rdi
    sub    rsp, 32

    mov    rdi, rcx           ; rdi -> source

    test   rcx, rcx
    jz     .return_error

    test   r8, r8
    jz     .return_error

    cmp    rdx, 24            ; check srclen >= 24
    jb     .return_error      ;

    mov    eax, [rdi]         ; eax = header.tag

    cmp    eax, 032335041h    ; check tag == 'AP32'
    jne    .return_error

    mov    eax, [rdi + 4]     ; rax = header.header_size
    cmp    eax, 24            ; check header_size >= 24
    jb     .return_error

    sub    rdx, rax           ; rdx = srclen without header
    jc     .return_error      ;

    cmp    [rdi + 8], edx     ; check header.packed_size is
    ja     .return_error      ; within remaining srclen

    add    rcx, rax           ; rcx -> packed data

    mov    edx, [rdi + 8]     ; rdx = header.packed_size

    call   aP_crc32

    cmp    eax, [rdi + 12]    ; check eax == header.packed_crc
    jne    .return_error

    mov    r9, [rsp + 72]     ; r9 = dstlen

    mov    edx, [rdi + 16]    ; rdx = header.orig_size
    cmp    rdx, r9            ; check header.orig_size is ok
    ja     .return_error

    mov    eax, [rdi + 4]     ; rax = header.header_size

    mov    rcx, [rsp + 48]    ; rcx -> source
    mov    edx, [rdi + 8]     ; rdx = header.packed_size
    mov    r8, [rsp + 64]     ; r8 -> destination

    add    rcx, rax           ; rcx -> compressed data

    call   aP_depack_asm_safe

    mov    edx, [rdi + 16]    ; rdx = header.orig_size

    cmp    rax, rdx           ; check rax == header.orig_size
    jne    .return_error

    mov    rcx, [rsp + 64]    ; rcx -> destination

    call   aP_crc32

    cmp    eax, [rdi + 20]    ; check eax = header.orig_crc

    mov    eax, [rdi + 16]    ; rax = header.orig_size

    je     .return_rax

  .return_error:
    or     rax, -1            ; rax = -1

  .return_rax:
    add    rsp, 32
    pop    rdi

    ret


aPsafe_get_orig_size:
    ; aPsafe_get_orig_size(const void *source)

    mov    edx, [rcx]         ; edx = header.tag

    or     rax, -1            ; rax = -1

    cmp    edx, 032335041h    ; check tag == 'AP32'
    jne    .return_rax

    mov    edx, [rcx + 4]     ; edx = header.header_size
    cmp    edx, 24            ; check header_size >= 24
    jb     .return_rax

    mov    eax, [rcx + 16]    ; rax = header.orig_size

  .return_rax:
    ret