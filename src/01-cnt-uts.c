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


#define STACK_SIZE (1024 * 1024)  // Stack size of child process.

/**
 * Struct with configuration for child process run by main process.
 */
struct proc_info {
    int argc;       // Number of args for child process.
    char **argv;    // Args for child process.
    char *hostname; // Hostname of child process.
};

bool choose_hostname(char *hostname, size_t i);

/**
 * Entry point for child process.
 * @param arg
 * @return Status.
 */
static int childFunc(void *arg)
{
    struct proc_info *info = arg;

    /* Change hostname in UTS namespace of child */
    if (sethostname(info->hostname, strlen(info->hostname)))
        return -1;

    struct utsname uts;
    if (uname(&uts) == -1)
        return -1;

    if (execve(info->argv[0], info->argv, NULL)) {
        fprintf(stderr, "execve failed! %m.\n");
        return -1;
    }
    fprintf(stdout, "Child process started. Hostname: %s", uts.nodename);

    sleep(5);

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
    while ((option = getopt(argc, argv, "c:"))) {
        switch (option) {
            // -c <process-to-be-run> (e.g. -c /bin/sh)
            case 'c':
                config.argc = argc - lastopt - 1;
                config.argv = &argv[argc - 1];
                goto finish_config;
            default:
                goto usage;
        }
    }

finish_config:

    if (!config.argc) goto usage;

    /* Choosing hostname for container. */
    fprintf(stdout, "=> choosing hostname for container..\n");
    char hostname[10] = {0};
    if (choose_hostname(hostname, sizeof(hostname)))
        goto err;
    config.hostname = hostname;
    fprintf(stdout, "=> Hostname: %s\n", config.hostname);


    /* Create (fork) child process, which will run executable.*/
    if(create_child_process(CLONE_NEWUTS, &config) == -1) {
        fprintf(stderr, "=> create child process failed! %m\n");
        goto err;
    }

    goto cleanup;

usage:
    fprintf(stderr, "Usage: %s -c /bin/sh ~\n", argv[0]);
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