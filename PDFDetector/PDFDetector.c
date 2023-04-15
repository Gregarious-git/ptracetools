#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <bfd.h>
#include <unistd.h>
#include <sys/mman.h>

#define n 0x10000

static bfd *ELF_abfd;
static bfd *libc_abfd;
static asymbol **symbols;
static int nsymbols;


struct user_regs_struct regs;

struct chunk_list
{
  long chunk_addr;
  struct chunk_list *next;
  struct chunk_list *hist;
};

struct chunk_list  *chunk_list_create(struct chunk_list* chunk_list,long *mmap_pointer,long chunk_addr)
{
  struct chunk_list* new_list = (struct chunk_list*)malloc(sizeof(struct chunk_list));
  struct chunk_list* new_hist = (struct chunk_list*)malloc(sizeof(struct chunk_list));
  
  long hash_addr = chunk_addr % n;
  
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
    
    mmap_pointer[hash_addr] = dummy_list;
    
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
        mmap_pointer[hash_addr] = chunk_list;
        return chunk_list;
      }     
      hist_p = hist_p->next;      
    }
    hist_p->next = new_hist;
    p->next = new_list;    
    mmap_pointer[hash_addr] = chunk_list;
    return chunk_list;
  }
}  
    
struct chunk_list  *chunk_list_delete(struct chunk_list** chunk_list,long chunk_addr)
{
  struct chunk_list *free_pointer; 
  struct chunk_list **pointer = chunk_list;
  struct chunk_list **hist_pointer = chunk_list;
  struct chunk_list *prev_pointer = NULL; 
  
  while (*pointer != NULL){
    if ((*pointer)->chunk_addr != chunk_addr){
      prev_pointer = *pointer;
    }else if ((*pointer)->chunk_addr == chunk_addr){
      free_pointer = *pointer;
      if ((*pointer)->next == NULL){
        prev_pointer->next = NULL; 
        free(free_pointer);
        return 1;
      }else{
        prev_pointer->next = (*pointer)->next; 
        free(free_pointer);
        return 1;
      }
    }
    pointer = &(*pointer)->next;
  }
  if((*hist_pointer)->hist != NULL){
    hist_pointer = &(*hist_pointer)->hist;
    while (*hist_pointer != NULL){
      if ((*hist_pointer)->chunk_addr == chunk_addr){
        return 2;
      }
      hist_pointer = &(*hist_pointer)->next;
    }
  }
  return 1;
}

struct chunk_list  *chunk_list_print(struct chunk_list* chunk_list,long chunk_addr)
{
  struct chunk_list *next_pointer; 
  struct chunk_list *pointer = chunk_list;
  
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
  long data;
  data = ptrace(PTRACE_PEEKDATA,pid,addr,NULL);
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



long get_symb_addr(void *target)
{
  size_t nsyms;
  asection *text;
  long addr;
  
  int ret;
  
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
    
    if (!strcmp(symbols[i]->name, target)) {
      addr = symbols[i]->value + text->vma;
      break;
    }

  }
  
  free(symbols);

  return addr;
}

long get_func_ret(int pid,long func_addr)
{
  char temp[18];
  long rip_opecode = ptrace(PTRACE_PEEKDATA,pid,func_addr,NULL);
  long i = 0;
  const char* opecode_ret = "c3c9";
  char *find;
  
  
  snprintf(temp, 17, "%lx", rip_opecode);
  while(strncmp(temp,opecode_ret,4) != 0){
    rip_opecode = ptrace(PTRACE_PEEKDATA,pid,func_addr + i,NULL);
    snprintf(temp, 17, "%lx", rip_opecode);
    i+=1;  
  }
  
  long result = func_addr + i+6;
  
  return result;
} 

long get_malloc_addr()
{ 
  long result;
  void *symbol = "malloc";
  result = get_symb_addr(symbol);
  return(result);
}

long get_free_addr()
{ 
  long result;
  void *symbol = "free";
  result = get_symb_addr(symbol);
  return(result);
}

struct chunk_list *list = NULL;

int main(int argc, char *argv[],char **envp)
{
  long *mmap_pointer = mmap(0, 0x10000000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
  int status , count,pid;

  pid = fork();
  if (!pid) { 
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execve(argv[1], argv + 1, envp); 
  }
  
  waitpid(pid, &status, 0);

  bfd_init();
  libc_abfd = bfd_openr(argv[1], NULL);
  if (libc_abfd == NULL) {
      printf("%s\n", bfd_errmsg(bfd_get_error()));
      return 1;
  }

  long malloc_func = get_malloc_addr();
  long free_func = get_free_addr();

  long malloc_addr = get_func_ret(pid,malloc_func);
  long free_addr = get_func_ret(pid,free_func);

  bfd_close(libc_abfd);

  long malloc_data = breakpoint_set(pid,malloc_addr);
  long free_data = breakpoint_set(pid,free_func);
  
  ptrace_continue(pid,status);

  while (1) {
    
     if (WIFEXITED(status)) {
      break;
    } else {

      ptrace(PTRACE_GETREGS, pid, NULL, &regs);

      breakpoint_delete(pid,malloc_data,malloc_addr);
      breakpoint_delete(pid,free_data,free_func);

      if (regs.rip == malloc_addr+1){
        long chunk_addr = regs.rax;
        
        long hash_addr = chunk_addr % n;
        
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
        
        long hash_addr = regs.rax % n;
        
        long chunk_addr = regs.rax;
                
        list = mmap_pointer[hash_addr];
        if(regs.rax == 0 || mmap_pointer[hash_addr] == NULL ){
        }else if(chunk_list_delete(&list,chunk_addr) == 2){  
          regs.rip = free_addr;
          ptrace(PTRACE_SETREGS, pid, 0, &regs);          
          ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
          ptrace(PTRACE_GETREGS, pid, NULL, &regs); 
          kill(pid, SIGINT);
          printf("0x%lx(Free Function) : DoubleFree Detected\n",regs.rip);
          exit(0);
        }else{ 
          chunk_list_print(list,chunk_addr);
        } 
    
      } 
      ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
       
      waitpid(pid, &status, 0);
      
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            
      long malloc_data = breakpoint_set(pid,malloc_addr);
      long free_data = breakpoint_set(pid,free_func);
      
      ptrace_continue(pid,status);
    }
  }
  return 0;
}
