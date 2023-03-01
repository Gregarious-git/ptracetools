#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <byteswap.h>
#include <jansson.h>

const char *systemcall[] = {
  "read",
  "write",
  "open",
  "close",
  "stat",
  "fstat",
  "lstat",
  "poll",
  "lseek",
  "mmap",
  "mprotect",
  "munmap",
  "brk",
  "rt_sigaction",
  "rt_sigprocmask",
  "rt_sigreturn",
  "ioctl",
  "pread",
  "pwrite",
  "readv",
  "writev",
  "access",
  "pipe",
  "select",
  "sched_yield",
  "mremap",
  "msync",
  "mincore",
  "madvise",
  "shmget",
  "shmat",
  "shmctl",
  "dup",
  "dup2",
  "pause",
  "nanosleep",
  "getitimer",
  "alarm",
  "setitimer",
  "getpid",
  "sendfile",
  "socket",
  "connect",
  "accept",
  "sendto",
  "recvfrom",
  "sendmsg",
  "recvmsg",
  "shutdown",
  "bind",
  "listen",
  "getsockname",
  "getpeername",
  "socketpair",
  "setsockopt",
  "getsockopt",
  "clone",
  "fork",
  "vfork",
  "execve",
  "exit",
  "wait4",
  "kill",
  "uname",
  "semget",
  "semop",
  "semctl",
  "shmdt",
  "msgget",
  "msgsnd",
  "msgrcv",
  "msgctl",
  "fcntl",
  "flock",
  "fsync",
  "fdatasync",
  "truncate",
  "ftruncate",
  "getdents",
  "getcwd",
  "chdir",
  "fchdir",
  "rename",
  "mkdir",
  "rmdir",
  "creat",
  "link",
  "unlink",
  "symlink",
  "readlink",
  "chmod",
  "fchmod",
  "chown",
  "fchown",
  "lchown",
  "umask",
  "gettimeofday",
  "getrlimit",
  "getrusage",
  "sysinfo",
  "times",
  "ptrace",
  "getuid",
  "syslog",
  "getgid",
  "setuid",
  "setgid",
  "geteuid",
  "getegid",
  "setpgid",
  "getppid",
  "getpgrp",
  "setsid",
  "setreuid",
  "setregid",
  "getgroups",
  "setgroups",
  "setresuid",
  "getresuid",
  "setresgid",
  "getresgid",
  "getpgid",
  "setfsuid",
  "setfsgid",
  "getsid",
  "capget",
  "capset",
  "rt_sigpending",
  "rt_sigtimedwait",
  "rt_sigqueueinfo",
  "rt_sigsuspend",
  "sigaltstack",
  "utime",
  "mknod",
  "uselib",
  "personality",
  "ustat",
  "statfs",
  "fstatfs",
  "sysfs",
  "getpriority",
  "setpriority",
  "sched_setparam",
  "sched_getparam",
  "sched_setscheduler",
  "sched_getscheduler",
  "sched_get_priority_max",
  "sched_get_priority_min",
  "sched_rr_get_interval",
  "mlock",
  "munlock",
  "mlockall",
  "munlockall",
  "vhangup",
  "modify_ldt",
  "pivot_root",
  "_sysctl",
  "prctl",
  "arch_prctl",
  "adjtimex",
  "setrlimit",
  "chroot",
  "sync",
  "acct",
  "settimeofday",
  "mount",
  "umount2",
  "swapon",
  "swapoff",
  "reboot",
  "sethostname",
  "setdomainname",
  "iopl",
  "ioperm",
  "create_module",
  "init_module",
  "delete_module",
  "get_kernel_syms",
  "query_module",
  "quotactl",
  "nfsservctl",
  "getpmsg",
  "putpmsg",
  "afs_syscall",
  "tuxcall",
  "security",
  "gettid",
  "readahead",
  "setxattr",
  "lsetxattr",
  "fsetxattr",
  "getxattr",
  "lgetxattr",
  "fgetxattr",
  "listxattr",
  "llistxattr",
  "flistxattr",
  "removexattr",
  "lremovexattr",
  "fremovexattr",
  "tkill",
  "time",
  "futex",
  "sched_setaffinity",
  "sched_getaffinity",
  "set_thread_area",
  "io_setup",
  "io_destroy",
  "io_getevents",
  "io_submit",
  "io_cancel",
  "get_thread_area",
  "lookup_dcookie",
  "epoll_create",
  "epoll_ctl_old",
  "epoll_wait_old",
  "remap_file_pages",
  "getdents64",
  "set_tid_address",
  "restart_syscall",
  "semtimedop",
  "fadvise64",
  "timer_create",
  "timer_settime",
  "timer_gettime",
  "timer_getoverrun",
  "timer_delete",
  "clock_settime",
  "clock_gettime",
  "clock_getres",
  "clock_nanosleep",
  "exit_group",
  "epoll_wait",
  "epoll_ctl",
  "tgkill",
  "utimes",
  "vserver",
  "mbind",
  "set_mempolicy",
  "get_mempolicy",
  "mq_open",
  "mq_unlink",
  "mq_timedsend",
  "mq_timedreceive",
  "mq_notify",
  "mq_getsetattr",
  "kexec_load",
  "waitid",
  "add_key",
  "request_key",
  "keyctl",
  "ioprio_set",
  "ioprio_get",
  "inotify_init",
  "inotify_add_watch",
  "inotify_rm_watch",
  "migrate_pages",
  "openat",
  "mkdirat",
  "mknodat",
  "fchownat",
  "futimesat",
  "newfstatat",
  "unlinkat",
  "renameat",
  "linkat",
  "symlinkat",
  "readlinkat",
  "fchmodat",
  "faccessat",
  "pselect6",
  "ppoll",
  "unshare",
  "set_robust_list",
  "get_robust_list",
  "splice",
  "tee",
  "sync_file_range",
  "vmsplice",
  "move_pages",
  "utimensat",
  "epoll_pwait",
  "signalfd",
  "timerfd",
  "eventfd",
  "fallocate",
  "timerfd_settime",
  "timerfd_gettime",
  "accept4",
  "signalfd4",
  "eventfd2",
  "epoll_create1",
  "dup3",
  "pipe2",
  "inotify_init1",
  "preadv",
  "pwritev",
  "rt_tgsigqueueinfo",
  "perf_event_open",
  "recvmmsg",
  "fanotify_init",
  "fanotify_mark",
  "prlimit64",
  "name_to_handle_at",
  "open_by_handle_at",
  "clock_adjtime",
  "syncfs",
  "sendmmsg",
  "setns",
  "getcpu",
  "process_vm_readv",
  "process_vm_writev",
  "kcmp",
  "finit_module",
  "sched_setattr",
  "sched_getattr",
  "renameat2",
  "seccomp",
  "getrandom",
  "memfd_create",
  "kexec_file_load",
  "bpf",
  "execveat"
};

int config_type;

FILE * fp = NULL;

struct user_regs_struct regs;

struct sys_list *list = NULL;
struct path_list *path_list = NULL;

typedef struct sys_list
{
  int systemcall_number;
  int option_number;
  struct sys_filter *next;
};

typedef struct path_list
{
  char path_name[1026];
  struct sys_filter *next;
};

struct path_list  *path_list_create(struct path_list* path_list,char save_path[])
{
  struct path_list* new_list = (struct path_list*)malloc(sizeof(struct path_list));
  strcpy(new_list->path_name,save_path);
  new_list->next = NULL;
     
  if (path_list == NULL) {
    return new_list;
  }else{
    struct path_list* p = path_list;
    while (p->next != NULL) {
      p = p->next;
    }
    p->next = new_list;
    return path_list;
  }
}


struct sys_list  *list_create(struct sys_list* list,int save_rax,int option)
{
  struct sys_list* new_list = (struct sys_list*)malloc(sizeof(struct sys_list));
  new_list->systemcall_number = save_rax;
  new_list->option_number = option;
  new_list->next = NULL;
    
  if (list == NULL) {
    return new_list;
  }else{
    struct sys_list* p = list;
    while (p->next != NULL) {
      p = p->next;
    }
    p->next = new_list;
    return list;
  }
}

struct path_list  *check_path_list(struct path_list* path_list,char char_path[],int pid)
{
  int secure_path = 0;
  struct path_list *pointer = path_list;
  if (strncmp(pointer->path_name,char_path,strlen(pointer->path_name)-1) == 0){
    secure_path = 1;
      
  }else{
    while (pointer->next !=NULL){
      pointer = pointer->next;
      if (strncmp(pointer->path_name,char_path,strlen(pointer->path_name)-1) == 0){
        secure_path = 1;
        break;
      }
    }
    if (secure_path == 0){
      printf("%s %s\n",char_path ,"is not secure");
      kill(pid, SIGINT);
      fclose(fp);
      exit(0);
    }
  }
}

struct sys_list  *check_list(struct sys_list* list,long long int int_orig_rax,int pid,FILE** fp)
{
  struct sys_list *pointer = list;
  if (pointer->systemcall_number == int_orig_rax){
    if (pointer->option_number == 1){
      printf("%s %s\n",systemcall[int_orig_rax] ,"was called");
      printf("[*] %s\n" ,"process killed");
      kill(pid, SIGINT);
      fclose(fp);
      exit(0);
    }else if(pointer->option_number == 2){
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
      fprintf(fp,"%s 0x%lx 0x%lx 0x%lx 0x%lx\n",systemcall[int_orig_rax] ,regs.rip,regs.rax,regs.rdi,regs.rsi);
    }
    
  }else{
    while (pointer->next !=NULL){
      pointer = pointer->next;
      if (pointer->systemcall_number == int_orig_rax){
        if (pointer->option_number == 1){
          printf("%s %s\n",systemcall[int_orig_rax] ,"was called");
          printf("[*] %s\n" ,"process killed");
          kill(pid, SIGINT);
          fclose(fp);
          exit(0);
        }else if(pointer->option_number == 2){
          ptrace(PTRACE_GETREGS, pid, NULL, &regs);
          fprintf(fp,"%s 0x%lx 0x%lx 0x%lx 0x%lx\n",systemcall[int_orig_rax] ,regs.rip,regs.rax,regs.rdi,regs.rsi);
          break;
        }
      }
    }
  }
}

struct sys_list  *whitelist_check_list(struct sys_list* list,long long int int_orig_rax,int pid)
{
  struct sys_list *pointer = list;
  if (pointer->systemcall_number == int_orig_rax){
    return;
  }else{
    while (pointer->next !=NULL){
      if (pointer->systemcall_number == int_orig_rax){
        return;
      }else{
        pointer = pointer->next;
      }
    }
    printf("%s %s\n",systemcall[int_orig_rax] ,"is not secure");
    printf("[*] %s\n" ,"process killed");
    kill(pid, SIGINT);
    fclose(fp);
    exit(0);
  }
}



void get_path(int pid,char char_path[],long long int regs_path)
{
  const char* NULL_ascii = "00";

  char *find;
  char temp_path[1024];
  char temp_ascii[300];
  char ascii_data[1024];
  char temp_data[1024];
  
  
  uint64_t temp , swaptemp , swappath ;
  

  memset(char_path, 0, sizeof(char) * 1024 );
  memset(temp_path, 0, sizeof(char) * 1024 );
  
  
  temp = ptrace(PTRACE_PEEKDATA, pid, regs_path, NULL);
  swappath= bswap_64(temp);
  
  snprintf(ascii_data, 17, "%lx", swappath);

  for(int i = 0; i < 128; i++){
    if ((find = strstr(ascii_data,NULL_ascii)) != NULL) {
      long find_pattern;
      find_pattern = find - ascii_data;
      strncpy(temp_path, ascii_data, find_pattern);
      char ascii_path[3];
      int path_len = (int)strlen(temp_path) / 2;
      int count = 0;
      int a[300];
      while (count < path_len){
        sscanf(&temp_path[count*2], "%2s", ascii_path);
        a[count] = strtoul(ascii_path, NULL, 16);
        snprintf(temp_ascii, 17, "%c", a[count]);
        strcat(char_path, temp_ascii);
        count++;
      }
      printf("file = %s\n",char_path);
      break;
    }
    regs_path = regs_path+8;
    temp = ptrace(PTRACE_PEEKDATA, pid, regs_path, NULL);
    swaptemp = bswap_64(temp);
    snprintf(temp_data, 17, "%lx", swaptemp);
    strcat(ascii_data, temp_data);          
  } 
  return char_path;
}

void syscall_filter(char *setread,int *syscall_number,char *option){
  char savedata[50];
  char *find;
  const char* option_kill = "kill";
  const char* option_alert = "alert";
  const char* sys_write = "write";
  const char* sys_read = "read";
  const char* sys_openat = "openat";
  const char* sys_execve = "execve";
  const char* sys_close = "close";
  strncpy(savedata,setread,strlen(setread));
  if(strstr(savedata, sys_read) != NULL){
    syscall_number[0] = 1;
    if(strstr(option, option_kill) != NULL){
      list = list_create(list,0,1);
    }else if(strstr(option, option_alert) != NULL){
      list = list_create(list,0,2);
    }
  }
  if(strstr(savedata, sys_write) != NULL){
    syscall_number[1] = 1;
    if(strstr(option, option_kill) != NULL){
      list = list_create(list,1,1);
    }else if(strstr(option, option_alert) != NULL){
      list = list_create(list,1,2);
    }
  }
  if(strstr(savedata, sys_openat) != NULL){
    syscall_number[257] = 1;
    if(strstr(option, option_kill) != NULL){
      list = list_create(list,257,1);
    }else if(strstr(option, option_alert) != NULL){
      list = list_create(list,257,2);
    }
  }
  if(strstr(savedata, sys_execve) != NULL){
    syscall_number[59] = 1;
    if(strstr(option, option_kill) != NULL){
      list = list_create(list,59,1);
    }else if(strstr(option, option_alert) != NULL){
      list = list_create(list,59,2);
    }
  }
  if(strstr(savedata, sys_close) != NULL){
    syscall_number[3] = 1;
    if(strstr(option, option_kill) != NULL){
      list = list_create(list,3,1);
    }else if(strstr(option, option_alert) != NULL){
      list = list_create(list,3,2);
    }
  }
  else{
    return;
  }  
}


void readfile(int *syscall_number){
  json_error_t error;
  
  json_t *get_config_type;
   
  json_t *get_syscall;
  json_t *syscall_array;
  json_t *syscall_object;
   
  json_t *get_path;
  json_t *path_array;
  json_t *path_object;
   
  char setread[1024];
  int i;
  const char *syscall_name;
  const char *syscall_option;
  const char *str_config_type;
   
  const char *whitelist_path;
   
  const char* type_blacklist = "blacklist";
  const char* type_whitelist = "whitelist";
   
  json_t *json_file; 
  json_file = json_load_file("config.json",0,&error);
   
  if (!json_file) {
    fprintf(stderr, "%s", error.text);
    exit(1);
  }
   
  get_config_type = json_object_get(json_file, "config");
   
  str_config_type = json_string_value(json_object_get(get_config_type, "type"));
   
  if (str_config_type == NULL){
    printf("error");
    exit(0);
  }
   
  if (strstr(str_config_type,type_whitelist) != NULL){
    config_type = 1;
    printf("%s %d\n",str_config_type,config_type); 
  }else if (strstr(str_config_type,type_blacklist) != NULL){
    config_type = 2;
    printf("%s %d\n",str_config_type,config_type); 
  }
   
  get_syscall = json_object_get(json_file, "systemcall");
  get_path = json_object_get(json_file, "path");
  
  json_array_foreach(get_syscall,i,syscall_array){
    syscall_option = json_string_value(json_object_get(syscall_array, "option"));   
    syscall_name = json_string_value(json_object_get(syscall_array, "systemcall_name"));
    syscall_filter(syscall_name,syscall_number,syscall_option);
  }
   
  json_array_foreach(get_path,i,path_array){
    whitelist_path = json_string_value(path_array);
    path_list = path_list_create(path_list,whitelist_path);
  }
}

void func_path_check(int pid,char char_path[])
{  
  char checkpath[1024];
  int secure_path = 0;
  if (path_list != NULL){ 
    check_path_list(path_list,char_path,pid);
  }
  return;      
}

void file_create()
{ 
  fp = fopen("syscall.log", "w");
}



int main(int argc, char *argv[], char *envp[])
{
  file_create();
  
  int syscall_number[322];
  
  
  int pid, status, syscall_count, call_count;
  char char_path[1024];

  long long regs_path,int_orig_rax,data,next_data,call_execve = 0;
  
  long long prev_orig_rax = -1;
  long long prev_rdi = -1;
  long long prev_rsi = -1;
  
  readfile(syscall_number);

  
  pid = fork();
  if (!pid) { 
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execve(argv[1], argv + 1, envp); 
  }
  ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEFORK|PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK);

  while (1) { 
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)){
      break;
    }else if (WIFSTOPPED(status)) {
    
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
      if (prev_orig_rax != regs.orig_rax && prev_rdi != regs.rdi && prev_rsi != regs.rsi && call_execve != 0) {
        int_orig_rax = regs.orig_rax;
        printf("%s %lld 0x%lx 0x%lx\n", systemcall[regs.orig_rax],regs.orig_rax, regs.rdi , regs.rsi);
        if (syscall_number[regs.orig_rax] == 1 && config_type == 2){        
          check_list(list,int_orig_rax,pid,fp);
           
        }else if (config_type == 1){
          whitelist_check_list(list,int_orig_rax,pid);
        }
        if (regs.orig_rax == 257){
          if (call_count == 0){ 
            call_count = 1;
            regs_path = regs.rsi;
            get_path(pid,char_path,regs_path);
            func_path_check(pid,char_path);
          }else{
            call_count = 0;
          }
        }
        if (regs.orig_rax == 59){
          if (call_count == 0 && regs.rdi != 0){ 
            call_count = 1;
            regs_path = regs.rdi;
            get_path(pid,char_path,regs_path);
            func_path_check(pid,char_path);
          }else{
            call_count = 0;
          }
        }
      }else if(regs.orig_rax == 59 && call_execve == 0) {
        call_execve = 1;
      }
      
      prev_orig_rax = regs.orig_rax;
      prev_rdi = regs.orig_rax;
      prev_rsi = regs.orig_rax;
   
    }
    
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  }
  fclose(fp);
  exit(0);
}