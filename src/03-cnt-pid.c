#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <getopt.h>
#include <sched.h>
#include <sys/utsname.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <zconf.h>
#include <memory.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <linux/capability.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/stat.h>


#define STACK_SIZE (1024 * 1024)  // Stack size of child process.

/**
 * Struct with configuration for child process run by main process.
 */
struct proc_info {
    int argc;        // Number of args for child process.
    char **argv;     // Args for child process.
    char *hostname;  // Hostname of child process.
    char *mount_dir; // Filesystem where containers should be mounted.
};

bool choose_hostname(char *hostname, size_t i);

int drop_capabilities() {
    fprintf(stderr, "=> setting up process capabilities...");
    int caps_list[] = {
            CAP_SYS_ADMIN
    };
    /* Calculate number of capabilities flags. sizeof(caps) equals size of all elements,
     * while sizeof(*caps) equals size of type of array. */
    size_t num_caps = sizeof(caps_list) / sizeof(*caps_list);
    fprintf(stderr, "bounding...");
    /* prctl allows to perform operations on a process according to first argument describing what to do.
     * PR_CAPBSET_DROP sets capabilities specified in caps array. */
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, caps_list[i], 0, 0, 0)) {
            fprintf(stderr, "prctl failed: %m\n");
            return 1;
        }
    }
    fprintf(stderr, "inheritable...");
    cap_t caps = NULL;
    if (!(caps = cap_get_proc())
        || cap_set_flag(caps, CAP_INHERITABLE, num_caps, caps_list, CAP_CLEAR)
        || cap_set_proc(caps)) {
        fprintf(stderr, "failed: %m\n");
        if (caps) cap_free(caps);
        return 1;
    }
    cap_free(caps);
    fprintf(stderr, "done.\n");
    return 0;

}

int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

int prepare_procfs()
{
    // Firstly, remove /proc if already exists.
    if (rmdir("/proc")) {
        fprintf(stderr, "rmdir /proc failed! %m\n");
        return -1;
    }
    // Create /proc directory
    if (mkdir("/proc", 0555)) {
        fprintf(stderr, "Failed to mkdir /proc! \n");
        return -1;
    }

    // Mount proc to newly created /proc
    if (mount("proc", "/proc", "proc", 0, "")) {
        fprintf(stderr, "Failed to mount proc! \n");
        return -1;
    }

    return 0;
}

/**
 * This function creates MNT namespace for container. It unmounts global filesystem, mounts local plus external
 * mount given by user and prepares the container filesystem.
 * @param info the child process info
 * @return status code
 */
int setmountns(struct proc_info *info)
{
    fprintf(stderr, "=> mounting MNT namespace to %s\n", info->mount_dir);

    fprintf(stderr, "=> remounting everything with MS_PRIVATE...");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
        fprintf(stderr, "failed! %m\n");
        return -1;
    }
    fprintf(stderr, "remounted.\n");

    fprintf(stderr, "=> making a temp directory and a bind mount there...");
    char mount_dir[] = "/tmp/tmp.XXXXXX";
    if (!mkdtemp(mount_dir)) {
        fprintf(stderr, "failed making a directory!\n");
        return -1;
    }

    if (mount(info->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
        fprintf(stderr, "bind mount failed!\n");
        return -1;
    }

    char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
    if (!mkdtemp(inner_mount_dir)) {
        fprintf(stderr, "failed making the inner directory!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    fprintf(stderr, "=> pivoting root...");
    if (pivot_root(mount_dir, inner_mount_dir)) {
        fprintf(stderr, "failed!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    char *old_root_dir = basename(inner_mount_dir);
    char old_root[sizeof(inner_mount_dir) + 1] = { "/" };
    strcpy(&old_root[1], old_root_dir);

    /**
     * To isolate process IDs we need set up the proc filesystem.
     * See http://ifeanyi.co/posts/linux-namespaces-part-3/#pid-namespaces for details.
     */
    if(prepare_procfs()) {
        fprintf(stderr, "Preparing procfs failed! %m\n");
        return -1;
    }

    fprintf(stderr, "=> unmounting %s...", old_root);
    if (chdir("/")) {
        fprintf(stderr, "chdir failed! %m\n");
        return -1;
    }
    if (umount2(old_root, MNT_DETACH)) {
        fprintf(stderr, "umount failed! %m\n");
        return -1;
    }
    if (rmdir(old_root)) {
        fprintf(stderr, "rmdir failed! %m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    return 0;
}


/**
 * Entry point for child process.
 * @param arg
 * @return Status.
 */
static int childFunc(void *arg)
{
    struct proc_info *info = arg;

    /* Change hostname in UTS namespace of child */
    if (sethostname(info->hostname, strlen(info->hostname))
        || setmountns(info))
        return -1;

    struct utsname uts;
    if (uname(&uts) == -1)
        return -1;

    /* Apply capabilities for child process. */
    drop_capabilities();

    if (execve(info->argv[0], info->argv, NULL)) {
        fprintf(stderr, "execve failed! %m.\n");
        return -1;
    }
    fprintf(stdout, "Child process started. Hostname: %s", uts.nodename);

    sleep(10);

    return 0;           /* Child terminates now */
}

int create_child_process(int flags, struct proc_info *config)
{
    int err = 0;
    char *stack;                    /* Start of stack buffer */
    char *stackTop;                 /* End of stack buffer */
    pid_t pid;                      /* Identifier of child process */

    /* Allocate stack for child process */
    if (!(stack = malloc(STACK_SIZE))) {
        fprintf(stderr, "=> malloc failed, out of memory?\n");
        return -1;
    }

    stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

    /* Create child that has its own namespace;
     * child commences execution in childFunc();
     * For clone() prototype refer to http://man7.org/linux/man-pages/man2/clone.2.html */
    pid = clone(childFunc, stackTop, flags | SIGCHLD, config);
    if (pid == -1) {
        fprintf(stderr, "=> child clone failed.\n");
        return -1;
    }
    fprintf(stdout, "=> child process created with PID %d\n", pid);

    int child_status = 0;
    waitpid(pid, &child_status, 0);
    err |= WEXITSTATUS(child_status);
    fprintf(stdout, "=> child exited with %d\n", WEXITSTATUS(child_status));

    free(stack);

    return err;
}

/**
 * Entry point for cnt.c program.
 * It runs the process from executable given by user in separated, isolated environment (container).
 */
int main(int argc, char **argv) {

    /* Store proc info */
    struct proc_info config = {0};

    /* Error code to return from main program */
    int err = 0;
    /* Used to store flag given by user. */
    int option = 0;

    int lastopt = 0;
    while ((option = getopt(argc, argv, "c:m:"))) {
        switch (option) {
            // -c <process-to-be-run> (e.g. -c /bin/sh)
            case 'c':
                config.argc = argc - lastopt - 1;
                config.argv = &argv[argc - 1];
                goto finish_config;
            case 'm':
                config.mount_dir = optarg;
                break;
            default:
                goto usage;
        }
    }

finish_config:

    if (!config.argc) goto usage;
    if (!config.mount_dir) goto usage;

    /* Choosing hostname for container. */
    fprintf(stdout, "=> choosing hostname for container..\n");
    char hostname[10] = {0};
    if (choose_hostname(hostname, sizeof(hostname)))
        goto err;
    config.hostname = hostname;
    fprintf(stdout, "=> Hostname: %s\n", config.hostname);


    /* Create (fork) child process, which will run executable.*/
    if(create_child_process(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS, &config) == -1) {
        fprintf(stderr, "=> create child process failed! %m\n");
        goto err;
    }

    goto cleanup;

usage:
    fprintf(stderr, "Usage: %s -m <mount-dir> -c /bin/sh ~\n", argv[0]);
err:
    err = 1;
cleanup:
    fprintf(stdout, "Done.\n");
    return err;
}

/**
 * Generates hostname for container.
 * @param buff
 * @param len
 * @return Success.
 */
bool choose_hostname(char *buff, size_t len) {
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    snprintf(buff, len, "%s-%05lx", "cnt", now.tv_sec);
    return 0;
}