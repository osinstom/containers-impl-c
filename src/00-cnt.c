#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <getopt.h>

/**
 * Struct with configuration for child process run by main process.
 */
struct proc_info {
    int argc;       // Number of args for child process.
    char **argv;    // Args for child process.
    char *hostname; // Hostname of child process.
};

bool choose_hostname(char hostname[256], size_t i);

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
                config.argv = &argv[argc - config.argc];
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