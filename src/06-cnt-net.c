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
#include <fcntl.h>
#include <unistd.h>
#include <grp.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "lib/netns.h"

#define STACK_SIZE (1024 * 1024)  // Stack size of child process.

/* USER namespace offset and count. See https://lwn.net/Articles/532593 for details. */
#define USERNS_OFFSET 1000
#define USERNS_COUNT 1

/* Macros defining names of veth interfaces. */
#define VETH_INTF "veth0"
#define VETH_VPEER "veth1"

/**
 * Struct with configuration for child process run by main process.
 */
struct proc_info {
    int argc;        // Number of args for child process.
    char **argv;     // Args for child process.
    char *hostname;  // Hostname of child process.
    char *mount_dir; // Filesystem where containers should be mounted.
    int pipe_fd[2];  // Pipe used to synchronize parent and child.
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

    /**
     * Changing owner (to root) of /proc after remounting.
     */
    if (chown("/proc", (uid_t) 0, (gid_t) 0) == -1) {
        fprintf(stderr, "chown failed! %m\n");
        return -1;
    }

    fprintf(stderr, "done.\n");

    return 0;
}

/**
 * This function is used by the child process to configure USER namespace. It first sends a signal to a parent process
 * to start configuration process for USER namespace. Then, when parent finishes the job, this function completes the
 * process by configuring User and Group IDs (equal to 0) from within the child process.
 * @param info
 * @return Status.
 */
int setuserns(struct proc_info *info)
{
    fprintf(stderr, "=> creating a user namespace.. ");

    /* Signal START to the parent. */
    if (write(info->pipe_fd[1], & (int) { 0 }, sizeof(int)) != sizeof(int)) {
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }

    /* Waiting for the parent to configure user/group ID mappings. If data received, move on. */
    int result = 0;
    if (read(info->pipe_fd[0], &result, sizeof(result)) != sizeof(result)) {
        fprintf(stderr, "couldn't read: %m\n");
        return -1;
    }

    if (result) {
        fprintf(stderr, "Configuration of UID/GID mapping failed.\n");
        return -1;
    }

    /* Switch to UID=0, GID=0. Become root within container. */
    fprintf(stderr, "=> switching to uid %d / gid %d.. .", 0, 0);
    if (setgroups(1, & (gid_t) { 0 }) ||
        setresgid(0, 0, 0) ||
        setresuid(0, 0, 0)) {
        fprintf(stderr, "%m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");


    fprintf(stderr, "=> creating a user namespace finished. eUID = %ld;  eGID = %ld; \n",
            (long) geteuid(), (long) getegid());

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
        || setuserns(info)
        || setmountns(info))
        return -1;

    struct utsname uts;
    if (uname(&uts) == -1)
        return -1;

    /* Drop capabilities for child process. */
    drop_capabilities();

    if (execve(info->argv[0], info->argv, NULL)) {
        fprintf(stderr, "execve failed! %m.\n");
        return -1;
    }
    fprintf(stdout, "Child process started. Hostname: %s", uts.nodename);

    sleep(10);

    return 0;           /* Child terminates now */
}

/**
 * This functions is invoked by parent to configure user/group ID mappings. It is synchronized with setuserns()
 * invoked from a child as the user/group ID mappings have to be configured before a child will run the executable.
 * @param child_pid
 * @param pipe_fd
 * @return Success status.
 */
int configure_child_uid_gid_mapping(pid_t child_pid, int pipe_fd[])
{
    fprintf(stderr, "=> configuring User/Group ID mappings.. ");
    int uid_map = 0;

    char path[PATH_MAX] = {0};
    for (char **file = (char *[]) { "uid_map", "gid_map", 0 }; *file; file++) {
        if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file)
            > sizeof(path)) {
            fprintf(stderr, "snprintf too big? %m\n");
            return -1;
        }
        fprintf(stderr, "writing %s...", path);
        if ((uid_map = open(path, O_WRONLY)) == -1) {
            fprintf(stderr, "open failed: %m\n");
            return -1;
        }
        if (dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
            fprintf(stderr, "dprintf failed: %m\n");
            close(uid_map);
            return -1;
        }
        close(uid_map);
    }


    return 0;
}

/// NET NAMESPACE ///

/**
 * This functions configured veth pairs for a container.
 * Implementation based on https://github.com/iffyio/isolate/blob/part-4/isolate.c.
 * @return
 */
int configure_network(pid_t pid)
{
//    char *veth = "veth0";
//    char *vpeer = "veth1";

    char *veth_addr = "10.1.1.1";
    char *vpeer_addr = "10.1.1.2";

    char *netmask = "255.255.255.0";

    /* Open a NETLINK socket */
    int sock_fd = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock_fd < 0) {
        fprintf(stderr, "cannot open socket: %m\n");
        return -1;
    }

    /* Create veth interfaces in Linux */
    create_veth_pair(sock_fd, VETH_INTF, VETH_VPEER);

    /* Activate vEth interface of a container */
    if (if_up(VETH_INTF, veth_addr, netmask)) {
        fprintf(stderr, "cannot activate veth interface: %m\n");
        return -1;
    }

    /* Get child namespace and move veth interface to a container's namespace. */
    int child_netns = get_netns_fd(pid);
    int parent_netns = get_netns_fd(getpid());
    move_if_to_pid_netns(sock_fd, VETH_VPEER, child_netns);

    /* Switch to child namespace to activate the veth interface there */
    if (setns(child_netns, CLONE_NEWNET)) {
        fprintf(stderr, "Cannot switch child process to the namespace: %m\n");
        return -1;
    }

    fprintf(stdout, "=> Current PID is %d\n", getpid());

    /* Activate veth interface from within a child process */
    if (if_up(VETH_VPEER, vpeer_addr, netmask)) {
        fprintf(stderr, "cannot activate veth peer interface: %m\n");
        return -1;
    }

    /* Restore the the previous (parent) namespace */
    if (setns(parent_netns, CLONE_NEWNET)) {
        fprintf(stderr, "Cannot restore to the previous namespace: %m\n");
        return -1;
    }

    /* Close NETLINK socket. */
    close(sock_fd);
    return 0;
}

int delete_network()
{
    /* Open a NETLINK socket */
    int sock_fd = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock_fd < 0) {
        fprintf(stderr, "cannot open socket: %m\n");
        return -1;
    }

    delete_veth_pair(sock_fd, VETH_INTF, VETH_VPEER);

    /* Close NETLINK socket */
    close(sock_fd);
    return 0;
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
        free(stack);
        return -1;
    }
    fprintf(stdout, "=> child process created with PID %d\n", pid);

    /* Wait for signal from a child. */
    int signal = -1;
    if (read(config->pipe_fd[0], &signal, sizeof(signal)) != sizeof(signal)) {
        fprintf(stderr, "couldn't read from child!\n");
        return -1;
    }

    int result = -1;
    /* Update the UID and GID maps in the child */
    result = configure_child_uid_gid_mapping(pid, config->pipe_fd);
    if (result) {
        if (pid) kill(pid, SIGKILL);
        free(stack);
        return -1;
    }

    /* Configure network interfaces. */
    result = configure_network(pid);
    if (result) {
        if (pid) kill(pid, SIGKILL);
        free(stack);
        return -1;
    }

    /* Send signal (configuration done) to a child. */
    if (write(config->pipe_fd[1], & (int) { result }, sizeof(int)) != sizeof(int)) {
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }

    close(config->pipe_fd[1]);

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

    /* Initialize Pipe. */
    if (pipe(config.pipe_fd) == -1)
        goto err;

    /* Create (fork) child process, which will run executable.*/
    if (create_child_process(CLONE_NEWNET
                             | CLONE_NEWUSER
                             | CLONE_NEWNS
                             | CLONE_NEWPID
                             | CLONE_NEWIPC
                             | CLONE_NEWUTS, &config) == -1) {
        fprintf(stderr, "=> create child process failed! %m\n");
        goto err;
    }

    goto cleanup;

usage:
    fprintf(stderr, "Usage: %s -m <mount-dir> -c /bin/sh ~\n", argv[0]);
err:
    err = 1;
cleanup:
    fprintf(stdout, "Cleaning up.. ");
    if (config.pipe_fd[0]) close(config.pipe_fd[0]);
    if (config.pipe_fd[1]) close(config.pipe_fd[1]);
    delete_network();
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