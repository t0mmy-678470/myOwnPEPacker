#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MOP3_LEN 0x14    // 
#define ALIGNUP(target, align) ((target)+(align)-(target)%(align))

typedef struct{
    DWORD oep;
    DWORD import_addr;
    DWORD import_size;
    DWORD export_addr;
    DWORD export_size;
    DWORD iat_addr;
    DWORD iat_size;
    DWORD reloc_addr;
    DWORD reloc_size;
} COMP_HDR;

// void write_file(char* filename, unsigned char* pe, long pe_len);

char* load_file(char* filename, long* len){
    FILE* fp;
    if((fp = fopen(filename, "rb")) == NULL) return NULL;
    // fp = fopen(filename, "rb");
    // if(fp == NULL){
    //     return NULL;
    // }
    fseek(fp, 0, SEEK_END);
    *len = ftell(fp);
    // printf("Original file size = %d\n", *len);
    if(*len <= 0){
        printf("read file error\n");
        return NULL;
    }

    char* pe = (char*) malloc(sizeof(char)*(*len) + 3*sizeof(IMAGE_SECTION_HEADER)); // 預留加上三個 section 後的空間
    fseek(fp, 0, SEEK_SET);
    fread(pe, sizeof(char), *len, fp);
    fclose(fp);

    // ----------------------------------
    // printf("writing: \n");
    // printf("   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
    // for(int i=0;i<0x9;i++){
    //     printf("%02X ", i);
    //     for(int j=0;j<0x10;j++){
    //         printf("%02X ", (unsigned char)pe[i*0x10+j]);
    //     }
    //     printf("\n");
    // }
    // printf("\n");
    // write_file("test_load_file.exe", pe, *len);
    // ----------------------------------

    return pe;
}

void write_file(char* filename, unsigned char* pe, long pe_len){
    FILE* fp;
    if((fp = fopen(filename, "wb")) == NULL) return;
    
    // printf("writing: \n");
    // printf("   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
    // for(int i=0;i<0x9;i++){
        //     printf("%02X ", i);
        //     for(int j=0;j<0x10;j++){
            //         printf("%02X ", pe[i*0x10+j]);
            //     }
            //     printf("\n");
    // }
    // printf("\n");

    long write_len = fwrite(pe, sizeof(unsigned char), pe_len, fp);
    fclose(fp);
    if(write_len != pe_len){
        printf("write error");
    }
}
// unsigned char* cpySecHdr(unsigned char* pe, int* len){
//     IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*) pe;
//     IMAGE_NT_HEADERS* ntHdr;
//     DWORD nSections = ntHdr->FileHeader.NumberOfSections;
//     *len = nSections * sizeof(IMAGE_SECTION_HEADER);
//     unsigned char* secHdrs = (unsigned char*) malloc( sizeof(IMAGE_SECTION_HEADER) * nSections );
//     if(ntHdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386){
//         // x86 file
//         memcpy(secHdrs, ntHdr+sizeof(IMAGE_NT_HEADERS32), *len);
//     }
//     else if(ntHdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64){
//         // x64 file
//         memcpy(secHdrs, ntHdr+sizeof(IMAGE_NT_HEADERS), *len);
//     }
//     else{
//         printf("PE Architecture Error\n");
//         return NULL;
//     }
//     return secHdrs;
//     // IMAGE_SECTION_HEADER
// }

unsigned char* compress(unsigned char* data, int* len){
    HMODULE aplib_handle = LoadLibraryA("aplib.dll");
    // get process address
    unsigned int (*aP_workmem_size)(unsigned int inputsize) = \
        (unsigned int (*)(unsigned int))GetProcAddress(aplib_handle, "aP_workmem_size");

    unsigned int (*aP_max_packed_size)(unsigned int inputsize) = \
        (unsigned int (*)(unsigned int))GetProcAddress(aplib_handle, "aP_max_packed_size");
    
    unsigned int (*aPsafe_pack)(const void *source,void *destination,
        unsigned int length,void *workmem,
        int (*callback)(unsigned int, unsigned int, unsigned int, void *),void *cbparam) = \
        (unsigned int (*)(const void *,void *,unsigned int ,void *,int (*)(unsigned int, unsigned int, unsigned int, void *),void *))GetProcAddress(aplib_handle, "aPsafe_pack");
    
    unsigned int (*aPsafe_get_orig_size)(const void *source) = \
        (unsigned int (*)(const void *))GetProcAddress(aplib_handle, "aPsafe_get_orig_size");
    
    unsigned int (*aPsafe_depack)(const void *source,unsigned int srclen,
        void *destination,unsigned int dstlen) = \
        (unsigned int (*)(const void *,unsigned int,void *,unsigned int))GetProcAddress(aplib_handle, "aPsafe_depack");

    // compress data
    unsigned int maxPackedSize = aP_max_packed_size(*len);
    unsigned char* compData = (unsigned char*) malloc(sizeof(char) * maxPackedSize);
    unsigned int workMemSize = aP_workmem_size(*len);
    unsigned char* workMem = (unsigned char*) malloc( sizeof(char) * workMemSize );
    unsigned int compDataLen = aPsafe_pack(data, compData, *len, workMem, NULL, NULL);
    *len = compDataLen;
    return compData;
}


DWORD vir2raw(unsigned char* pe, DWORD virAddr){
    IMAGE_NT_HEADERS* ntHdr = (IMAGE_NT_HEADERS*)(pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew);
    IMAGE_SECTION_HEADER* secHdr = (IMAGE_SECTION_HEADER*)((char*)ntHdr + sizeof(IMAGE_NT_HEADERS));
    int sectionNums = ntHdr->FileHeader.NumberOfSections;
    for(int i=0;i<sectionNums;i++){
        if(secHdr[i].VirtualAddress <= virAddr && virAddr <= secHdr[i].VirtualAddress + secHdr[i].Misc.VirtualSize){
            return secHdr[i].PointerToRawData + virAddr - secHdr[i].VirtualAddress;
        }
    }

    printf("Invalid Virtual Address!\n");
    return 0;
}

COMP_HDR* init_compress_header(unsigned char* pe){
    COMP_HDR* comp_hdr = (COMP_HDR*) malloc(sizeof(COMP_HDR));
    IMAGE_NT_HEADERS* ntHdr = (IMAGE_NT_HEADERS*)(pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew);
    
    comp_hdr->oep = ntHdr->OptionalHeader.AddressOfEntryPoint;  // virtual address
    comp_hdr->import_addr = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    comp_hdr->import_size = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    comp_hdr->export_addr = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    comp_hdr->export_size = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    comp_hdr->iat_addr = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
    comp_hdr->iat_size = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
    comp_hdr->reloc_addr = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    comp_hdr->reloc_size = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    return comp_hdr;
}

// 修正、新增 section( header)s
void reBuildSections(unsigned char* pe, long* pe_len, unsigned char* stub, long stub_len){
    IMAGE_NT_HEADERS* ntHdr = (IMAGE_NT_HEADERS*)(pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew);
    IMAGE_FILE_HEADER* fileHdr = (IMAGE_FILE_HEADER*)((char*)ntHdr + sizeof(DWORD));
    // IMAGE_FILE_HEADER* fileHdr = (IMAGE_FILE_HEADER*)(ntHdr + ((LONGLONG)&(ntHdr->FileHeader) - (LONGLONG)ntHdr));
    // printf("fileHdr: %x %x\n", *((char*)fileHdr), *((char*)fileHdr+1));
    // printf("offset: %ld\n", ((LONGLONG)&(ntHdr->FileHeader) - (LONGLONG)ntHdr));
    // IMAGE_OPTIONAL_HEADER64 optHdr = (IMAGE_OPTIONAL_HEADER64)(ntHdr->OptionalHeader);
    IMAGE_SECTION_HEADER* const secHdr = (IMAGE_SECTION_HEADER*)((char*)ntHdr + sizeof(IMAGE_NT_HEADERS));
    // IMAGE_SECTION_HEADER* tmpsecHdr = secHdr;
    int sectionNums = fileHdr->NumberOfSections;
    int secHdrsLen    = sectionNums * sizeof(IMAGE_SECTION_HEADER);
    int fileAlign     = ntHdr->OptionalHeader.FileAlignment;
    int secAlign      = ntHdr->OptionalHeader.SectionAlignment;

    int secRawStart = secHdr->PointerToRawData;
    int secRawEnd   = secHdr[sectionNums-1].PointerToRawData + secHdr[sectionNums-1].SizeOfRawData;
    int secVirStart = secHdr->VirtualAddress;
    int secVirEnd   = secHdr[sectionNums-1].VirtualAddress + secHdr[sectionNums-1].Misc.VirtualSize;
    int totalSectionRawSize = secRawEnd - secRawStart;
    int totalSectionVirSize = secVirEnd - secVirStart;
    int accuVirAddr = ALIGNUP(secVirEnd, secAlign), accuRawAddr = secRawStart;

    // IMAGE_IMPORT_DESCRIPTOR* importTable = (IMAGE_IMPORT_DESCRIPTOR*)(pe + \
    //     vir2raw(pe, ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
    // IMAGE_IMPORT_DESCRIPTOR* tmpImpTable = importTable;
    // int importTableNum = 1;
    // while(1){
    //     if(memcpy(tmpImpTable, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof(IMAGE_IMPORT_DESCRIPTOR))){
    //         // tmpImpTable += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    //         tmpImpTable += 1;
    //         importTableNum++;
    //     }
    //     else{
    //         break;
    //     }
    // }

    //-------------------------  compress section headers and all sections together -------------------------
    // printf("compressing section headers and all sections together\n");
    COMP_HDR* comp_hdr = init_compress_header(pe);
    int main_len = sizeof(COMP_HDR) + secHdrsLen + totalSectionRawSize;
    unsigned char* main_data = (unsigned char*) malloc(sizeof(char) * main_len);
    memcpy(main_data, comp_hdr, sizeof(comp_hdr));
    memcpy(main_data+sizeof(comp_hdr), (char*)ntHdr+sizeof(IMAGE_NT_HEADERS), secHdrsLen);
    memcpy(main_data+sizeof(comp_hdr)+secHdrsLen, pe+secRawStart, totalSectionRawSize);
    unsigned char* compressed_data = compress(main_data, &main_len);
    
    // printf("main_len = %x\n", main_len);
    free(comp_hdr);
    comp_hdr = NULL;
    free(main_data);
    main_data = NULL;

    // give write permission to all section
    for(short i=0;i<sectionNums;i++){
        secHdr[i].Characteristics += IMAGE_SCN_MEM_WRITE;
        secHdr[i].SizeOfRawData = 0;
        secHdr[i].PointerToRawData = 0;
        // secHdr += sizeof(IMAGE_SECTION_HEADER);
    }
    
    //------------------------- append 3 section header -------------------------
    // printf("appending section header\n");
    // append first section header .mop1
    // store compressed data
    strcpy(secHdr[sectionNums].Name, ".mop1");
    secHdr[sectionNums].Characteristics = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;
    secHdr[sectionNums].Misc.VirtualSize = main_len;         // no need to align
    secHdr[sectionNums].VirtualAddress = accuVirAddr;
    accuVirAddr += ALIGNUP(main_len, secAlign);
    secHdr[sectionNums].PointerToRawData = secRawStart;
    accuRawAddr += ALIGNUP(main_len, fileAlign);
    secHdr[sectionNums].SizeOfRawData = ALIGNUP(main_len, fileAlign);

    memcpy( pe+secHdr[sectionNums].PointerToRawData, compressed_data, main_len );
    free(compressed_data);

    // append second section header .mop2
    // store stub
    strcpy(secHdr[sectionNums+1].Name, ".mop2");
    secHdr[sectionNums+1].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    secHdr[sectionNums+1].Misc.VirtualSize = stub_len;         // no need to align
    secHdr[sectionNums+1].VirtualAddress = accuVirAddr;
    accuVirAddr += ALIGNUP(stub_len, secAlign);
    secHdr[sectionNums+1].PointerToRawData = accuRawAddr;
    accuRawAddr += ALIGNUP(stub_len, fileAlign);
    secHdr[sectionNums+1].SizeOfRawData = ALIGNUP(stub_len, fileAlign);
    
    memcpy( pe+secHdr[sectionNums+1].PointerToRawData, stub, stub_len);

    // append third section header .mop3
    // store uncompressed data
    IMAGE_IMPORT_DESCRIPTOR imp_table;
    strcpy(secHdr[sectionNums+2].Name, ".mop3");
    secHdr[sectionNums+2].Characteristics = IMAGE_SCN_MEM_READ;
    secHdr[sectionNums+2].Misc.VirtualSize = MOP3_LEN;         // no need to align
    secHdr[sectionNums+2].VirtualAddress = accuVirAddr;
    accuVirAddr += ALIGNUP(MOP3_LEN, secAlign);
    secHdr[sectionNums+2].PointerToRawData = accuRawAddr;
    accuRawAddr += ALIGNUP(MOP3_LEN, fileAlign);
    secHdr[sectionNums+2].SizeOfRawData = ALIGNUP(MOP3_LEN, fileAlign);
    // copy empty import table
    // memcpy( pe+secHdr[sectionNums+2].PointerToRawData, &imp_table, sizeof(imp_table));
    // memcpy( pe+secHdr[sectionNums+2].PointerToRawData, "????????????????????", 20);
    memset(pe+secHdr[sectionNums+2].PointerToRawData, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    //------------------------- add offset to section raw data addr if needed -------------------------
    // printf("adding offset to section raw data addr if needed\n");
    int secHdrEndOff = ((IMAGE_DOS_HEADER*)pe)->e_lfanew + sizeof(IMAGE_NT_HEADERS) + \
                    sizeof(IMAGE_SECTION_HEADER) * sectionNums;
    if( ALIGNUP(secHdrEndOff, fileAlign) < ALIGNUP(secHdrEndOff+3*sizeof(IMAGE_SECTION_HEADER), fileAlign) ){
        secHdr[sectionNums+0].PointerToRawData += sizeof(fileAlign);
        secHdr[sectionNums+1].PointerToRawData += sizeof(fileAlign);
        secHdr[sectionNums+2].PointerToRawData += sizeof(fileAlign);
    }
    *pe_len = secHdr[sectionNums+2].PointerToRawData + secHdr[sectionNums+2].SizeOfRawData;

    //------------------------- modify headers -------------------------
    // printf("modifing headers\n");
    fileHdr->NumberOfSections += 3;
    sectionNums = fileHdr->NumberOfSections;
    ntHdr->OptionalHeader.AddressOfEntryPoint = secHdr[sectionNums-2].VirtualAddress;
    ntHdr->OptionalHeader.SizeOfImage = ALIGNUP(secHdr[sectionNums-1].VirtualAddress + secHdr[sectionNums-1].Misc.VirtualSize, secAlign);
    ntHdr->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    ntHdr->OptionalHeader.CheckSum = 0;
    for(int i=0;i<15;i++){
        ntHdr->OptionalHeader.DataDirectory[i].VirtualAddress=0;
        ntHdr->OptionalHeader.DataDirectory[i].Size=0;
    }
    ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = \
                                                            secHdr[sectionNums-1].VirtualAddress;
    ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(imp_table);
    // ntHdr->OptionalHeader.DataDirectory[2].VirtualAddress=0;
    // ntHdr->OptionalHeader.DataDirectory[2].Size=0;
    // ntHdr->OptionalHeader.DataDirectory[3].VirtualAddress=0;
    // ntHdr->OptionalHeader.DataDirectory[3].Size=0;

    //------------------------- copy content to sections -------------------------
    // printf("copying content to sections\n");

    // memcpy( )
}

// int stub_len = 276;
// unsigned char stub[] =
// "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
// "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
// "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
// "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
// "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
// "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
// "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
// "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
// "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
// "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
// "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
// "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
// "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
// "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
// "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
// "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
// "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
// "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
// "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
// "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


unsigned char* stub;

long stub_len;

void print_banner(){
    SetConsoleOutputCP(CP_UTF8);
    printf("                                    \n");
    Sleep(30);
    printf("    ███╗   ███╗ ██████╗ ██████╗     \n");
    Sleep(30);
    printf("    ████╗ ████║██╔═══██╗██╔══██╗    \n");
    Sleep(30);
    printf("    ██╔████╔██║██║   ██║██████╔╝    \n");
    Sleep(30);
    printf("    ██║╚██╔╝██║██║   ██║██╔═══╝     \n");
    Sleep(30);
    printf("    ██║ ╚═╝ ██║╚██████╔╝██║         \n");
    Sleep(30);
    printf("    ╚═╝     ╚═╝ ╚═════╝ ╚═╝         \n");
    Sleep(30);
    printf("                                    \n");
}

int main(int argc, char** argv){
    print_banner();

    if(argc != 2){
        printf("Usage: packer.exe [path to PE]\n");
        return 0;
    }
    if(strlen(argv[1])<4 || strncmp(argv[1]+strlen(argv[1])-4, ".exe", 4)){
        printf("not .exe format!\n");
        return 0;
    }
    // printf("start loading file\n");
    // load target pe file
    long pe_len, *section_len=0;
    unsigned char* pe = load_file(argv[1], &pe_len);
    if(pe == NULL){
        printf("file not found\n");
        return 0;
    }
    if(memcmp(pe, "MZ", 2)){
        printf("File doesn't in PE format\n");
        return 0;
    }
    // printf("check file finished\n");

    stub = load_file("./stub/stub.bin", &stub_len);
    reBuildSections(pe, &pe_len, stub, stub_len);

    char* out_filename = (char*) malloc(sizeof(char)*(strlen(argv[1])+8) );
    memcpy(out_filename, argv[1], strlen(argv[1])-4);
    memcpy(out_filename+strlen(argv[1])-4, "_packed.exe\x00", 12);
    write_file(out_filename, pe, pe_len);
    
    printf("successfully packed at %s\n", out_filename);

    // IMAGE_NT_HEADERS* dosHdr->e_lfanew
    // IMAGE_SCN_MEM_SHARED
    // memcpy()

    
    return 0;
}