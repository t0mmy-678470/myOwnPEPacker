%include "hldr.inc"

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
    pushfq
    sub rsp, 0x20
    ; +0x0:  exe section header address
    ; +0x8:  exe section header num
    ; +0x10: allocation memory addr 

    call get_sectionHeaderAddr_and_sectionNums
    mov [rsp], rax ; exe section header address
    mov [rsp+0x8], rbx ; exe section header num

    ; alloc memory to store compressed section
    movzx rcx, DWORD [rax + _IMAGE_SECTION_HEADER.shSizeOfRawData] ; size to alloc
    call alloc_mem
    mov [rsp+0x10], rax

    ; copy compressed section to tmp memory
    mov rcx = [rsp]
    mov rcx = DWORD PTR [rcx + _IMAGE_SECTION_HEADER.shVirtualAddress] ; src: location of compressed section
    mov rdx = rax; dst: tmp memory
    ; mov rbx, [rsp+0x8] ; exe section header num
    ; mov rax, _IMAGE_SECTION_HEADER_size ; section header size
    ; mul rbx            ; rax = section header total size 
    movzx r8, DWORD [rcx + _IMAGE_SECTION_HEADER.shSizeOfRawData] ; len to copy
    call copy_mem

    ; depack the tmp memory to location of compressed section
    mov rcx, rdx; src: tmp memory
    mov rdx, r8; src len: section raw data size
    mov r9,  [rsp]
    mov r8,  [r9 + _IMAGE_SECTION_HEADER.shVirtualAddress]; dst: location of compressed section
    mov r9,  [r9 + _IMAGE_SECTION_HEADER.shVirtualSize]; dst len: compressed section virtual size = decompressed section size
    sub rsp, 40
    call aPsafe_depack
    add rsp, 40

    ; go to oep

    popfq
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax

; ret rax = sectionHeaderAddr
; ret rbx = sectionNums
get_sectionHeaderAddr_and_sectionNums:
    push rbp
    mov rbp, rsp

    mov rax, gs:[0x60]  ; get peb addr
    mov rax, [rax + pebLdr] ; get ldr addr
    mov rax, [rax + ldrInLoadOrderModuleList] ; exe ldr table entry
    mov rbx, [rax + mlDllBase] ; get exe image base
    add rax, [rbx + lfanew] ; get nt header address
    movzx rbx, WORD PTR [rax + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhNumberOfSections] ; get number of sections
    movzx rcx, WORD PTR [rax + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhSizeOfOptionalHeader] ; get size of optional header
    mov rax, [rax + _IMAGE_NT_HEADERS.nthOptionalHeader + rcx] ; get section header address

    leave 
    ret


get_kernel32_dll_base:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10

    mov rax, gs:[0x60]  ; get peb addr
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
    push rbx
    push rsi
    push rdi
    push r9

    push rbp
    mov rbp, rsp
    sub rsp, 0x10

    mov rdi, rdx ; target_name_address
    lea rbx, [rcx + lfanew + IMAGE_DIRECTORY_ENTRY_EXPORT] ; export table address
    lea r9, DWORD [rbx + _IMAGE_EXPORT_DIRECTORY.edNumberOfNames] ; number of name
    xor rdx, rdx ; idx
    mov rax, [rbx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNames] ; get name arr address
    dec rdx    

  .search:
    inc rdx ; idx++
    cmp rdx, r9 ; idx == arr len ?
    je .not_found
    mov rsi, [rax + rdx*4] ; get name addr
    mov rcx, r8
    cld
    repe cmpsb
    jnz .search
    cmp rcx, 0
    jne .search
    
  .success:
    mov rax, [rbx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNameOrdinals] ; get name ordinal arr addr
    mov rdx, [rax + rdx*2] ; new idx for target func arr
    mov rax, [rbx + _IMAGE_EXPORT_DIRECTORY.edAddressOfFunctions] ; get function arr addr
    mov rax, [rax + rdx*4]
    jmp .exit

  .not_found: ; return null
    xor rax, rax

  .exit:
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
    mov [rsp], rcx
    call get_kernel32_dll_base
    mov rcx, rax
    lea rdx, [rel .name]
    mov r8,  13
    call find_proc_addr
    mov r10, rax ; virtualalloc func address
    ; call get_sectionHeaderAddr_and_sectionNums
    
    mov rcx, 0 ; virtualAlloc arg1 lpaddress
    ; movzx rdx, DWORD [rax + _IMAGE_SECTION_HEADER.shSizeOfRawData] ; vurtualAlloc arg2 dwsize (mop raw size)
    movzx rdx, [rsp]       ; vurtualAlloc arg2 dwsize
    lea r8, [MEM_COMMIT + MEM_RESERVE] ; vurtualAlloc arg3 flAllocationType
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


; aPsafe_depack(const void *source,
;               size_t srclen,
;               void *destination
;               size_t dstlen)
aPsafe_depack:

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

; =============================================================