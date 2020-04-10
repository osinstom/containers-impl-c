The goal of this stage is to run in namespaces.

This directory contains several C programs, each implementing one namespace incrementally in the following order
(any subsequent program is built on top of the previous one):
* UTS namespace (`cnt-uts.c`)
* PID namespace (`cnt-pid.c`)
* MNT namespace (`cnt-mnt.c`)
* IPC namespace (`cnt-ipc.c`)
* USER namespace (`cnt-user.c`)

Below I describe how to compile, run & test each program.



### PID namespace

What we changed here?
* Pass CLONE_NEWPID flag to clone() function, but it does not isolate processes. We still see global process list, because
the child process still sees `/proc` filepath.
* Umount the /proc and mount it again. To do this we need to pass CAP_SYS_ADMIN privileges. This is done inside `drop_capabilities()`
function.
  * Note! You need to install `libcap-dev`.

Compile:

`gcc -Wall cnt-pid.c -o cnt -lcap`


