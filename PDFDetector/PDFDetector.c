#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <bfd.h>
#include <unistd.h>
#include <sys/mman.h>

static bfd *ELF_abfd;
static bfd *libc_abfd;
static asymbol **symbols;
static int nsymbols;

long long libc_addr = 0x0;

struct user_regs_struct regs;

struct chunk_list
{
  long long chunk_addr;
  struct chunk_list *next;
};

struct chunk_list  *chunk_list_create(struct chunk_list* chunk_list,long long *mmap_pointer,long long chunk_addr)
{
  struct chunk_list* new_list = (struct chunk_list*)malloc(sizeof(struct chunk_list));
  
  long long hash_addr = chunk_addr % 0x10000;
  
  struct chunk_list* p = chunk_list;
  
  new_list->chunk_addr = chunk_addr;
  new_list->next = NULL;
  if (chunk_list == NULL){
    struct chunk_list* dummy_list = (struct chunk_list*)malloc(sizeof(struct chunk_list));
    
    dummy_list->chunk_addr = 0;
    dummy_list->next = new_list;
    
    mmap_pointer[hash_addr] = dummy_list;
    return dummy_list;
  }else{
    while (p->next != NULL) {     
      p = p->next;
    }
    
    p->next = new_list;
    
    mmap_pointer[hash_addr] = chunk_list;
    return chunk_list;
  }
}  
    
struct chunk_list  *chunk_list_delete(struct chunk_list* chunk_list,long long chunk_addr)
{
  struct chunk_list *next_pointer; 
  struct chunk_list *pointer = chunk_list;
  
  while (pointer->next !=NULL){
      
    next_pointer = pointer->next;
      
    if (next_pointer->chunk_addr == chunk_addr){
      pointer->next = next_pointer->next; 
      return 1;
    }
    pointer = next_pointer;
  }
  return 2;
}

struct chunk_list  *chunk_list_print(struct chunk_list* chunk_list,long long chunk_addr)
{
  struct chunk_list *next_pointer; 
  struct chunk_list *pointer = chunk_list;
  printf("|*|print_chunk_list -> 0x%lx\n",pointer->chunk_addr);
  
  while (pointer->next !=NULL){
    next_pointer = pointer->next;
    if (next_pointer == NULL){
      return;
    }    
    printf("|*|chunk_list -> 0x%lx\n",next_pointer->chunk_addr);
      
    pointer = next_pointer;
  }
}

void malloc_delete(int pid,long malloc_data,long long malloc_addr)
{
  
  ptrace(PTRACE_POKETEXT, pid, malloc_addr, malloc_data);
}

void free_delete(int pid,long free_data,long long free_addr)
{
  
  ptrace(PTRACE_POKETEXT, pid, free_addr, free_data);
}

long malloc_break(int pid,long long malloc_addr)
{
 
  long long malloc_data,after_malloc_data;
  malloc_data = ptrace(PTRACE_PEEKDATA,pid,malloc_addr,NULL);
  ptrace(PTRACE_POKETEXT, pid, malloc_addr, ((malloc_data & 0xFFFFFFFFFFFFFF00) | 0xCC));
  
  return malloc_data;
}

long free_break(int pid,long long free_addr)
{ 
  long long free_data,after_free_data;
  free_data = ptrace(PTRACE_PEEKDATA,pid,free_addr,NULL);
  ptrace(PTRACE_POKETEXT, pid, free_addr, ((free_data & 0xFFFFFFFFFFFFFF00) | 0xCC));

  return free_data;
}


void ptrace_continue(int pid,int status)
{
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  if (waitpid(pid, &status, 0) == -1){
    exit(0);
  }
}

long get_malloc_addr()
{
  size_t nsyms;
  asection *text;
  long long malloc_offset;
  long long malloc_addr;
  int ret;
    
  void *char_malloc = "malloc";
  
  ret = bfd_check_format(libc_abfd, bfd_object);
  if (ret == NULL) {
      printf("%s\n", bfd_errmsg(bfd_get_error()));
      return 1;
  }
  text = bfd_get_section_by_name(libc_abfd, ".text");

  symbols = malloc(bfd_get_symtab_upper_bound(libc_abfd));
  if (symbols == NULL) {
      printf("%s\n", bfd_errmsg(bfd_get_error()));
      return 1;
  }
  nsyms = bfd_canonicalize_symtab(libc_abfd, symbols);
  for (int i = 0; i < nsyms; i++) {
    if (!strcmp(symbols[i]->name, char_malloc)) {
      malloc_offset = symbols[i]->value + text->vma;
      malloc_addr = libc_addr + malloc_offset;
      break;
    }
  }
  
  free(symbols);

  return malloc_offset;
}

long get_free_addr()
{
  size_t nsyms;
  asection *text;
  long long free_offset;
  long long free_addr;
  int ret;
    
  void *char_free = "free";
  
  ret = bfd_check_format(libc_abfd, bfd_object);
  if (ret == NULL) {
      printf("%s\n", bfd_errmsg(bfd_get_error()));
      return 1;
  }
  text = bfd_get_section_by_name(libc_abfd, ".text");

  symbols = malloc(bfd_get_symtab_upper_bound(libc_abfd));
  if (symbols == NULL) {
      printf("%s\n", bfd_errmsg(bfd_get_error()));
      return 1;
  }
  nsyms = bfd_canonicalize_symtab(libc_abfd, symbols);
  for (int i = 0; i < nsyms; i++) {
    if (!strcmp(symbols[i]->name, char_free)) {
      free_offset = symbols[i]->value + text->vma;
      free_addr = libc_addr + free_offset;
      break;
    }
  }
  
  free(symbols);

  return free_offset;
}


long get_malloc_ret(int pid,long long malloc_func)
{
  long long malloc_addr;
  char temp[18];
  malloc_addr = malloc_func + libc_addr;
  long long rip_opecode = ptrace(PTRACE_PEEKDATA,pid,malloc_addr,NULL);
  long long i = 0;
  const char* opecode_ret = "c3c9";
  char *find;
  
  
  snprintf(temp, 17, "%lx", rip_opecode);
  while(strncmp(temp,opecode_ret,4) != 0){
    rip_opecode = ptrace(PTRACE_PEEKDATA,pid,malloc_addr + i,NULL);
    snprintf(temp, 17, "%lx", rip_opecode);
    i+=1;
    
  }
  
  long long result = malloc_addr + i+6;
  
  return result;
} 

long get_free_ret(int pid,long long free_func)
{
  long long free_addr;
  char temp[18];
  free_addr = free_func + libc_addr;
  long long rip_opecode = ptrace(PTRACE_PEEKDATA,pid,free_addr,NULL);
  long long i = 0;
  const char* opecode_ret = "c3c9";
  char *find;
  
  snprintf(temp, 17, "%lx", rip_opecode);
  while(strncmp(temp,opecode_ret,4) != 0){
    rip_opecode = ptrace(PTRACE_PEEKDATA,pid,free_addr + i,NULL);
    snprintf(temp, 17, "%lx", rip_opecode);
    i+=1;
  }
  
  long long result = free_addr + i+6;
  
  return result;
} 

struct chunk_list *list = NULL;

int main(int argc, char *argv[],char **envp)
{
  long long *mmap_pointer = mmap(0, 0x10000000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
  int status , count,pid;

  pid = fork();
  if (!pid) { 
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execve(argv[2], argv + 1, envp); 
  }
  waitpid(pid, &status, 0);


  bfd_init();
  libc_abfd = bfd_openr(argv[1], NULL);
  if (libc_abfd == NULL) {
      printf("%s\n", bfd_errmsg(bfd_get_error()));
      return 1;
  }

  long long malloc_func = get_malloc_addr();
  long long free_func = get_free_addr();

  long long malloc_addr = get_malloc_ret(pid,malloc_func);
  long long free_addr = get_free_ret(pid,free_func);

  bfd_close(libc_abfd);

  long long malloc_data = malloc_break(pid,malloc_addr);
  long long free_data = free_break(pid,free_func);
  
  ptrace_continue(pid,status);

  while (1) {
    
     if (WIFEXITED(status)) {
      break;
    } else {

      ptrace(PTRACE_GETREGS, pid, NULL, &regs);

      malloc_delete(pid,malloc_data,malloc_addr);
      free_delete(pid,free_data,free_func);

      if (regs.rip == malloc_addr+1){
        long long  chunk_addr = regs.rax;
        
        long long hash_addr = chunk_addr % 0x10000;
        
        if(mmap_pointer[hash_addr] == 0){
          struct chunk_list *list = NULL;
          chunk_list_create(list,mmap_pointer,chunk_addr);
        }else{
          struct chunk_list *list = mmap_pointer[hash_addr];
          
          chunk_list_create(list,mmap_pointer,chunk_addr);
        }

        regs.rip = malloc_addr;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);

      }else if (regs.rip == free_func + 1){

        regs.rip = free_func;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
        
        long long hash_addr = regs.rax % 0x10000;
        
        long long chunk_addr = regs.rax;
                
        list = mmap_pointer[hash_addr];

        if(regs.rax == 0){
        }else if(chunk_list_delete(list,chunk_addr) == 2){  
          regs.rip = free_addr;
          ptrace(PTRACE_SETREGS, pid, 0, &regs);          
          ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
          ptrace(PTRACE_GETREGS, pid, NULL, &regs);
          printf("0x%lx(Free Function) : DoubleFree Detected\n",regs.rip);
          kill(pid, SIGINT);
          exit(0);
        }else{ 
          chunk_list_print(list,chunk_addr);

        } 
        
      } 

      ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
       
      waitpid(pid, &status, 0);
      
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            
      long long malloc_data = malloc_break(pid,malloc_addr);
      long long free_data = free_break(pid,free_func);
      
      ptrace_continue(pid,status);

    }
  }

  return 0;
}
