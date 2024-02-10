#include<stdio.h>
#include<sys/ptrace.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<unistd.h>
#include<sys/user.h>
#include<sys/reg.h>
#include<string.h>
#include<errno.h>
#include<sys/syscall.h>
#include<stdlib.h>
#include<signal.h>
#include<sys/stat.h>
void getdata(pid_t pid, unsigned long address,char *str,int len){
	int i = 0;
	long val;
	while(i < len - 1){
		val = ptrace(PTRACE_PEEKDATA,pid,address + i, NULL);

		memcpy(str + i,&val,sizeof(val));

		if(memchr(&val,0,sizeof(val)) != NULL){
			break;
		}
		i += sizeof(val);
	}
	str[len - 1] = '\0';
}
void set_number(int argc,char *str,int insyscall,struct user_regs_struct regs){
	if(argc > 2 && (strcmp(str,"-n") == 0) && insyscall == 0){
		printf("[%llu] ",regs.orig_rax);
	}	
}
	
void syscalls_counter(int *systemcalls_counting,struct user_regs_struct regs){
	int i;
	for(i = 0; i < 314; i++){
		if(i == regs.orig_rax){
			systemcalls_counting[i] += 1;
			break;
		}
	}	

}
int main(int argc, char *argv[]){


	int insyscall = 0;
	pid_t pid;
	char buf[256];
	int syscalls_counting[314];
	int i;
	for(i = 0; i < 314; i++){
		syscalls_counting[i] = 0;
	}
	char syscalls[315][40] = {
    "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap",
    "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite(64)",
    "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat",
    "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect",
    "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
    "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop",
    "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate",
    "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink",
    "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getusage",
    "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid",
    "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setrespid",
    "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait",
    "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs",
    "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
    "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall",
    "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit",
    "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname",
    "setdomainname", "iopl","ioperm","create_module", "init_module", "delete_module", "get_kernel_syms", "query_module",
    "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr",
    "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxatrr", "listxattr", "llistxattr", "flistxattr",
    "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity",
    "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area",
    "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64",
    "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "time_gettime",
    "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep",
    "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy",
    "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid",
    "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "iontify_init", "inotify_add_watch", "inotify_rm_watch",
    "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat",
    "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list",
    "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait",
    "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4",
    "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
    "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at",
    "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "proccess_vm_readv", "proccess_vm_writev", "kcmp", "finit_module", {'\0'}
};
	if (argc < 2){
		printf("Uzycie: %s <program>\n",argv[0]);	
	}
	else{
		if((pid = fork()) < 0 ){
			perror("Blad:\n");
		}
		
		if(pid == 0){
			ptrace(PTRACE_TRACEME,0, NULL, NULL);
			if(argc == 2){		
				execl(argv[1], argv[1],NULL);
			}
			else if(argc == 3){
				execl(argv[2],argv[1],NULL);
			}
		}
		else{
			int status;
			wait(&status);
			struct user_regs_struct regs;
			if (WIFSTOPPED(status)){
				ptrace(PTRACE_SYSCALL,pid,NULL,NULL);
			}
			while(1){
				wait(&status);
				if(WIFEXITED(status)){
					if(argc > 2 && (strcmp(argv[1],"-c") == 0)){
						printf("Liczba poszczegolnych wywolwan:\n");
						for(i = 0; i < 314; i++){
							if(syscalls_counting[i] > 0){
								printf("%s: %d\n",syscalls[i],syscalls_counting[i]);
							}
						}
					}
					break;
				}
				ptrace(PTRACE_GETREGS,pid,NULL,&regs);
				if(argc > 2 &&(strcmp(argv[1],"-c") == 0)){
					if(insyscall == 0){
						syscalls_counter(syscalls_counting,regs);
						insyscall = 1;
					}
					else{
						insyscall = 0;
					}
					ptrace(PTRACE_SYSCALL,pid,NULL,NULL);
				}
				else{
					if( regs.orig_rax < 314  && regs.orig_rax != 0 && regs.orig_rax != 1 && regs.orig_rax != 3 && regs.orig_rax != 58 && regs.orig_rax != 257 && regs.orig_rax != 262 && regs.orig_rax != 60 && regs.orig_rax != 12 && regs.orig_rax != 231 ){
						if(insyscall == 0){
							set_number(argc,argv[1],insyscall,regs);		
							printf("%s\n",syscalls[regs.orig_rax]);
						}
					}
				if(regs.orig_rax == 0){
					if(insyscall == 0){
						set_number(argc,argv[1],insyscall,regs);
						insyscall = 1;
					}
					else{
						unsigned long long int filename = regs.rsi;
						getdata(pid,filename,buf,sizeof(buf));
						printf("read(%lld,\"%s\",%lld)   =",regs.rdi,buf,regs.rdx);
						printf("%lld\n",regs.rax);
						insyscall = 0;
					}
				}
				if(regs.orig_rax == 1){
					if(insyscall == 0){
						set_number(argc,argv[1],insyscall,regs);
						insyscall = 1;
					getdata(pid,regs.rsi,buf,regs.rdx);
					printf("write(%lld,\"%s\",%lld)   =",regs.rdi,buf,regs.rdx);
					
					}
					else{
						printf("%lld\n",regs.rax);
						insyscall = 0;
					}	
				}
				if(regs.orig_rax == 3){
					if(insyscall == 0){
						set_number(argc,argv[1],insyscall,regs);
						insyscall = 1;
					printf("close(%lld)   =",regs.rdi);
					}
					else{
						printf("%lld\n",regs.rax);
						insyscall = 0;
					}
				}	
				if(regs.orig_rax == 59){
					if(insyscall == 0){
						set_number(argc,argv[1],insyscall,regs);
						insyscall = 1;
						unsigned long long int filename = regs.rdi;
						unsigned long long int argument = regs.rsi;
						getdata(pid,filename,buf,sizeof(buf));
						printf("execve(\"%s\"",buf);
						getdata(pid,argument,buf,sizeof(buf));
						printf("[\"%s\"])   =",buf);
					}
					else{
						int result = regs.rax;
						if(result < 0){
							int error_code = (-1)*result;
							printf("-1 [%s]\n",strerror(error_code));
						}
						else{		
							printf("%d\n",result);
						}
						insyscall = 0;
					}

				}
				if(regs.orig_rax == 257){
					if(insyscall == 0){
						set_number(argc,argv[1],insyscall,regs);
						unsigned long long int filename = regs.rsi;
						getdata(pid,filename,buf,sizeof(buf));
						insyscall = 1;
						printf("openat(\"%s\")   =",buf);
					}
					else{
						int result = regs.rax;
						if(result < 0){
							int error_code = (-1)*result;
							printf("-1 [%s]\n",strerror(error_code));
						}
						else{		
							printf("%d\n",result);
						}
						insyscall = 0;
					}
				}
				if(regs.orig_rax == 262){
					if(insyscall == 0){
						set_number(argc,argv[1],insyscall,regs);
						insyscall = 1;
						unsigned long long int dfd = regs.rdi;
						unsigned long long int filename = regs.rsi;
						struct stat statbuf;
						getdata(pid,filename,buf,sizeof(buf));
						if(strcmp(buf,"") == 0){	
							fstat(dfd,&statbuf);
						}
						else{
							stat(buf,&statbuf);
						}
						printf("newfstatat(\"%s\",{st_mode:%o})   =",buf,statbuf.st_mode);
					}
					else{
						int result = regs.rax;
						if(result < 0){
							int error_code = (-1)*result;
							printf("-1 [%s]\n",strerror(error_code));
						}
						else{		
							printf("%d\n",result);
						}
						insyscall = 0;
					}

				}	
				if(regs.orig_rax == 60){
					if(insyscall == 0){
						set_number(argc,argv[1],insyscall,regs);
						insyscall = 1;
						printf("exit(%lld)   =",regs.rdi);
						printf("\n");
					}
					else{
						printf("%lld\n",regs.rax);
						insyscall = 0;
					}
				}
				if(regs.orig_rax == 12){
					if(insyscall == 0){
						set_number(argc,argv[1],insyscall,regs);
						insyscall = 1;
						if(regs.rdi == 0){
							printf("brk(NULL)   =");
						}
						else{
							printf("brk(0x%llX)   =",regs.rdi);
						}
					}
					else{
						printf("0x%llX\n",regs.rax);
						insyscall = 0;
					}
				}
				if(regs.orig_rax == 231){
					if(insyscall == 0){
						set_number(argc,argv[1],insyscall,regs);
						printf("exit_group(%lld)   =?",regs.rdi);
						printf("\n");
					}
				}
				ptrace(PTRACE_SYSCALL,pid,NULL,NULL);	
				}
			}	

		}
	}
	return 0;
}
