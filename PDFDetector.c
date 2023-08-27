#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <getopt.h>
#include <byteswap.h>

#define n 0xFFFF

long mall_plt_offset = 0;
long free_plt_offset = 0;
long init_offset = 0;

long malloc_func = 0;
long free_func = 0;

long libc_base = 0;
long base_addr = 0;

long sym_malloc;
long sym_free;

long hash_table[0x10000];

struct user_regs_struct regs;
struct user_regs_struct save_regs;

struct chunk_list
{
  long chunk_addr;
  struct chunk_list *next;
  struct chunk_list *hist;
};


static int get_plt(char *head,char *malloc_func_name,char *free_func_name)
{
  Elf64_Ehdr *ehdr;
  Elf64_Shdr *shdr, *shstr, *str, *dynstr, *sym, *rel, *rela_plt, *rela_plt_addr;
  Elf64_Phdr *phdr;
  Elf64_Sym *symp;
  Elf64_Rel *relp;
  Elf64_Dyn *dyn;
  int i, j, size;
  char *sname;
  

  ehdr = (Elf64_Ehdr *)head;

  shstr = (Elf64_Shdr *) (head + ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shstrndx);

  for ( i = 0; i < ehdr->e_shnum; i++){
    shdr = (Elf64_Shdr *)(head + ehdr->e_shoff + ehdr->e_shentsize * i);
    sname = (char *)(head + shstr ->sh_offset + shdr->sh_name);
    if (!strcmp(sname, ".strtab")){
      str = shdr;
    }
    if (strcmp(sname, ".dynstr") == 0){
      dynstr = shdr;
    }  
    if (strcmp(sname, ".rela.plt") == 0){
      rela_plt = shdr;
      rela_plt_addr = shdr->sh_addr;
    }  
  }

  printf("Symbols:\n");
  for (i = 0; i < ehdr->e_shnum; i++){
    shdr = (Elf64_Shdr *)(head + ehdr->e_shoff + ehdr->e_shentsize * i);
    if (shdr->sh_type != SHT_SYMTAB){
      continue;
    }
    sym = shdr;
    for (j = 0; j < sym->sh_size / sym->sh_entsize; j++){
      symp = (Elf64_Sym *)(head + sym->sh_offset + sym->sh_entsize * j);
      if (!symp->st_name){
        continue;
      }
      printf("\t[%d]\t%lx\t%d\t%s\n ",j,(long *)(symp->st_value),symp->st_size,(char *)(head + str->sh_offset + symp->st_name));
      if (strcmp((char *)(head + str->sh_offset + symp->st_name) ,"_init") == 0){
	init_offset = (long *)symp->st_value;
	printf("0x%lx\n",init_offset);
      }
    }
  }
  
  printf("Dynamic Symbols:\n");
  for (i = 0; i < ehdr->e_shnum; i++){
    shdr = (Elf64_Shdr *)(head + ehdr->e_shoff + ehdr->e_shentsize * i);
    if (shdr->sh_type != SHT_DYNSYM){
      continue;
    }
    sym = shdr;
    for (j = 0; j < sym->sh_size / sym->sh_entsize; j++){
      symp = (Elf64_Sym *)(head + sym->sh_offset + sym->sh_entsize * j);
      if (!symp->st_name){
        continue;
      } 
      printf("\t[%d]\t%lx\t%d\t%s\n ",j,(long *)(symp->st_value),symp->st_size,(char *)(head + dynstr->sh_offset + symp->st_name));
      
    }
  }
  
  printf("Relocations:\n");
  for (i = 0; i < ehdr->e_shnum; i++) { 
    shdr = (Elf64_Shdr *)(head + ehdr->e_shoff + ehdr->e_shentsize * i);
    dyn = (Elf64_Dyn *)(head + ehdr->e_shoff + ehdr->e_shentsize * i);
    if ((shdr->sh_type != SHT_REL) && (shdr->sh_type != SHT_RELA) ){
      continue;
    }
    if ((long *)shdr->sh_offset != rela_plt_addr){
      continue;
    }
    rel = shdr;
    for (j = 0; j < rel->sh_size / rel->sh_entsize; j++) {
      relp = (Elf64_Rel *)(head + rel->sh_offset + rel->sh_entsize * j);
      symp = (Elf64_Sym *)(head + sym->sh_offset + (sym->sh_entsize * ELF64_R_SYM(relp->r_info)));
      if (!symp->st_name){
        continue;
      }  
      
      if (strcmp((char *)(head + dynstr->sh_offset + symp->st_name) ,malloc_func_name) == 0){
        printf("\t[%d]\t%lx\t%s\n",j, (long *)(symp->st_value),(char *)(head + dynstr->sh_offset + symp->st_name));
	mall_plt_offset = (long *)relp->r_offset;
	printf("0x%lx\n",mall_plt_offset);
      }
      if (strcmp((char *)(head + dynstr->sh_offset + symp->st_name) ,free_func_name) == 0){
        printf("\t[%d]\t%d\t%s\n",j, ELF64_R_SYM(relp->r_info),(char *)(head + dynstr->sh_offset + symp->st_name));
	free_plt_offset = (long *)relp->r_offset;
	printf("0x%lx\n",free_plt_offset);
      }
    }
  } 
   
  return (0);
}

static int get_symbols(char *head,char *malloc_func_name,char *free_func_name)
{
  Elf64_Ehdr *ehdr;
  Elf64_Shdr *shdr, *shstr, *str, *sym;
  Elf64_Sym *symp;
  int i, j, size;
  char *sname;
  

  ehdr = (Elf64_Ehdr *)head;

  shstr = (Elf64_Shdr *) (head + ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shstrndx);

  for ( i = 0; i < ehdr->e_shnum; i++){
    shdr = (Elf64_Shdr *)(head + ehdr->e_shoff + ehdr->e_shentsize * i);
    sname = (char *)(head + shstr ->sh_offset + shdr->sh_name);
    if (!strcmp(sname, ".strtab")){
      str = shdr;
    }
  }

  printf("Symbols:\n");
  for (i = 0; i < ehdr->e_shnum; i++){
    shdr = (Elf64_Shdr *)(head + ehdr->e_shoff + ehdr->e_shentsize * i);
    if (shdr->sh_type != SHT_SYMTAB){
      continue;
    }
    sym = shdr;
    for (j = 0; j < sym->sh_size / sym->sh_entsize; j++){
      symp = (Elf64_Sym *)(head + sym->sh_offset + sym->sh_entsize * j);
      if (!symp->st_name){
        continue;
      }
      printf("\t[%d]\t%lx\t%d\t%s\n ",j,(long *)(symp->st_value),symp->st_size,(char *)(head + str->sh_offset + symp->st_name));
      if (strcmp((char *)(head + str->sh_offset + symp->st_name) ,malloc_func_name) == 0){
	sym_malloc = (long *)symp->st_value;
	printf("0x%lx\n",sym_malloc);
      }
      if (strcmp((char *)(head + str->sh_offset + symp->st_name) ,free_func_name) == 0){
	sym_free = (long *)symp->st_value;
	printf("0x%lx\n",sym_free);
      }
    }
  }
  return;
}

struct chunk_list  *chunk_list_create(struct chunk_list* chunk_list,long chunk_addr)
{
  struct chunk_list* new_list = (struct chunk_list*)malloc(sizeof(struct chunk_list));
  struct chunk_list* new_hist = (struct chunk_list*)malloc(sizeof(struct chunk_list));
  
  long hash_addr = chunk_addr & n;
  
  struct chunk_list* p = chunk_list;
  struct chunk_list* hist_p = chunk_list;
  
  new_hist->chunk_addr = chunk_addr;
  new_hist->next = NULL;
  
  new_list->chunk_addr = chunk_addr;
  new_list->hist = new_hist;
  new_list->next = NULL;

  if (chunk_list == NULL){
    struct chunk_list* dummy_list = (struct chunk_list*)malloc(sizeof(struct chunk_list));
    
    dummy_list->chunk_addr = 0;
    dummy_list->hist = new_hist;
    dummy_list->next = new_list;
    
    hash_table[hash_addr] = dummy_list;
    
    return dummy_list;
  }else{    
    hist_p = chunk_list->hist;    
    while (p->next != NULL) {     
      p = p->next;
    }
    while (hist_p->next != NULL) {
      if(hist_p->chunk_addr == chunk_addr){
        hist_p->next = NULL;
        p->next = new_list;
        hash_table[hash_addr] = chunk_list;
        return chunk_list;
      }     
      hist_p = hist_p->next;      
    }
    hist_p->next = new_hist;
    p->next = new_list;    
    hash_table[hash_addr] = chunk_list;
    return chunk_list;
  }
}  
    
struct chunk_list  *chunk_list_delete(struct chunk_list** chunk_list,long chunk_addr)
{
  struct chunk_list *free_pointer; 
  struct chunk_list **pointer = chunk_list;
  struct chunk_list **hist_pointer = chunk_list;
  struct chunk_list **prev_pointer = chunk_list; 
  
  while (*pointer != NULL){
    if ((*pointer)->chunk_addr != chunk_addr){
      prev_pointer = pointer;
    }else if ((*pointer)->chunk_addr == chunk_addr){
      free_pointer = *pointer;
      if ((*pointer)->next == NULL){
        (*prev_pointer)->next = NULL;
        return 2;
      }else{
        (*prev_pointer)->next = (*pointer)->next; 
        free(free_pointer);
        return 2;
      }
    }
    pointer = &(*pointer)->next;
  }
  if((*hist_pointer)->hist != NULL){
    hist_pointer = &(*hist_pointer)->hist;
    while (*hist_pointer != NULL){
      if ((*hist_pointer)->chunk_addr == chunk_addr){
        return 1;
      }
      hist_pointer = &(*hist_pointer)->next;
    }
  }
  return 2;
}

struct chunk_list  *chunk_list_print(struct chunk_list* chunk_list,long chunk_addr)
{
  struct chunk_list *next_pointer; 
  struct chunk_list *pointer = chunk_list;
  pointer->next;
  while (pointer !=NULL){
    next_pointer = pointer->next;
      
    pointer = next_pointer;
  }
}


void breakpoint_delete(int pid,long data,long addr)
{ 
  ptrace(PTRACE_POKETEXT, pid, addr, data);
}

long breakpoint_set(int pid,long addr)
{ 
  long data = ptrace(PTRACE_PEEKDATA,pid,addr,NULL);
  ptrace(PTRACE_POKETEXT, pid,addr, ((data & 0xFFFFFFFFFFFFFF00) | 0xCC));

  return data;
}


void ptrace_continue(int pid,int status)
{
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  if (waitpid(pid, &status, 0) == -1){
    exit(0);
  }
}

long vmmap(int pid,char *file[],int status)
{
  char proc_maps[32];
  int fd, count = 0;
  char *result = NULL;
  FILE *fp = NULL;
  char *text_only = "r-xp";
  long file_addr;
  size_t size = 0;
  
  snprintf(proc_maps,sizeof(proc_maps),"/proc/%d/maps",pid);
  printf("%s\n",proc_maps);
  fp = fopen(proc_maps, "r");
  while(getline(&result,&size,fp) != -1){
    printf("%s\n",result);
    if (strstr(result,file) != NULL && strstr(result,text_only) == NULL && count == 0){
      file_addr = strtol(result,NULL,16);
      printf("0x%lx\n",file_addr);
      return file_addr;
    }
  }
}



long call_got_plt(int pid,int status, long start_addr)
{
  long mall_got_plt = base_addr + mall_plt_offset; 
  long free_got_plt = base_addr + free_plt_offset; 
  long init = init_offset + base_addr; 
  long next_opcode;
  long libc_data = 0;
  long target = 0;
  long data = 0;
  long call_opcode = 0;
  long check = 0;
  long libc_init = 0;
  long malloc = 0;
  long free = 0;
  
  ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
  waitpid(pid, &status, 0);
  
  libc_data = ptrace(PTRACE_PEEKDATA,pid,init,NULL);
  ptrace(PTRACE_POKETEXT, pid,init, ((libc_data & 0xFFFFFFFFFFFFFF00) | 0xCC)); //set breakpoint in init 

  ptrace_continue(pid,status);
  breakpoint_delete(pid,libc_data,init);
  
  malloc_func = ptrace(PTRACE_PEEKDATA,pid,mall_got_plt,NULL); //get malloc()
  free_func = ptrace(PTRACE_PEEKDATA,pid,free_got_plt,NULL); //get malloc()
  
}

long get_options(int argc,char *argv[],int pid,int status)
{
  struct stat sb;
  char *file = argv[2];
  int fd,opt;
  char *head;
  long start_addr = 0;
  const char *optstring = "ds:" ;
  const char *char_malloc = "malloc";
  const char *char_free = "free";
  
  fd = open(argv[2], O_RDONLY);
  if (fd < 0) exit(1);
  fstat(fd,&sb);
  head = mmap(NULL,sb.st_size,PROT_READ,MAP_SHARED,fd,0);
  

  //get options
  while((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
    case 's':  //static library 
      if(argc <= 3){
        get_symbols(head,char_malloc,char_free);
      }else{    
        get_symbols(head,argv[3],argv[4]);
      }
      base_addr = vmmap(pid,file,status);
      malloc_func = sym_malloc;
      free_func = sym_free;
      break;
    case 'd': //dynamic library
      if(argc <= 3){
        get_plt(head,char_malloc,char_free);
      }else{    
        get_plt(head,argv[3],argv[4]);
      }
      
      base_addr  = vmmap(pid,file,status);
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
      printf("entry point 0x%lx\n",base_addr);
  
      start_addr = regs.rip;
      call_got_plt(pid,status,start_addr);
      break;
    default:
      break;
    }
  }
  munmap(head,sb.st_size);
  close(fd);
  return;
}

struct chunk_list *list = NULL;

int main(int argc, char *argv[],char **envp)
{
  //long *mmap_pointer = mmap(0, 0x10000000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
  //long *mmap_pointer = mmap(0, 0x10*0x3, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
  
  //struct hash_table* hashtable = (struct hash_table*)malloc(sizeof(struct hash_table));
  
  
  
  int status , count,pid;
  char proc_maps[32];
  long malloc_data = 0;
  long free_data = 0;
  long stack_pointer = 0;
  long return_addr = 0;
  long ret_opcode = 0;
  
  pid = fork();
  if (!pid) { 
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execve(argv[2], argv + 1, envp); 
  }
  
  waitpid(pid, &status, 0);
  
  printf("%s\n","wait pid");
  
  get_options(argc,argv,pid,status);

  if((malloc_data = breakpoint_set(pid,malloc_func)) == 0xffffffffffffffff){
    printf("%lx\n",malloc_data);
    kill(pid, SIGINT);
    exit(0);
  }
  if((free_data = breakpoint_set(pid,free_func)) == 0xffffffffffffffff){
    printf("%lx\n",free_data);
    kill(pid, SIGINT);
    exit(0);
  }
  
  printf("malloc 0x%lx\n",malloc_func);
  printf("free 0x%lx\n",free_func);
  
  ptrace_continue(pid,status);

  while (1) {
    
     if (WIFEXITED(status)) {
      break;
    } else {
      
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);

      breakpoint_delete(pid,malloc_data,malloc_func);
      breakpoint_delete(pid,free_data,free_func);

      if (regs.rip == malloc_func+1){

        stack_pointer = regs.rsp; //get return address
        return_addr = ptrace(PTRACE_PEEKDATA,pid,stack_pointer,NULL);
        ret_opcode = breakpoint_set(pid,return_addr);
        
        ptrace_continue(pid,status);
        
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        breakpoint_delete(pid,ret_opcode,return_addr);

        long chunk_addr = regs.rax;
        
        long hash_addr = chunk_addr & n;

        
        if(hash_table[hash_addr] == 0){
          struct chunk_list *list = NULL;
          chunk_list_create(list,chunk_addr);

        }else{
          struct chunk_list *list = hash_table[hash_addr];        
          chunk_list_create(list,chunk_addr);

        }

        regs.rip = return_addr;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        waitpid(pid, &status, 0);

      }else if (regs.rip == free_func + 1){
        
        regs.rip = free_func;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);

        long hash_addr = regs.rax & n;
       
        long chunk_addr = regs.rax;
        
        list = hash_table[hash_addr];

        if(regs.rax == 0 || hash_table[hash_addr] == NULL ){
        }else if(chunk_list_delete(&list,chunk_addr) == 1){  
          long stack_pointer = regs.rsp; //get return address
          long return_addr = ptrace(PTRACE_PEEKDATA,pid,stack_pointer,NULL);
          chunk_list_print(list,chunk_addr);
          regs.rip = free_func;
          ptrace(PTRACE_SETREGS, pid, 0, &regs);          
          ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
          ptrace(PTRACE_GETREGS, pid, NULL, &regs); 
          
          kill(pid, SIGINT);
          printf("0x%lx(Free Function) : DoubleFree Detected\n",return_addr-5);
          exit(0);
        }else{ 
          chunk_list_print(list,chunk_addr);
        } 
    
      } 
      ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
      
      waitpid(pid, &status, 0);
      
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
      if((malloc_data = breakpoint_set(pid,malloc_func)) == 0xffffffffffffffff){
        printf("%lx\n",malloc_data);
        kill(pid, SIGINT);
        exit(0);
      }
      if((free_data = breakpoint_set(pid,free_func)) == 0xffffffffffffffff){
        printf("%lx\n",free_data);
        kill(pid, SIGINT);
        exit(0);
      } 
      ptrace_continue(pid,status);
    }
  }
  return 0;
}
