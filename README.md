I've created this repository to better understand internals of Linux containers technology. 

This is based on [Linux containers in 500 lines of code](https://blog.lizzie.io/linux-containers-in-500-loc.html)

Note that the below description does not contain a complete (step-by-step) guide to implement a container runtime. This tutorial should be rather used
as a reference to follow when implementing container on your own. So, I encourage everyone to treat this tutorial as some kind of a lab and try
to implement your own container based on hints and code templates from this repository. The C programs in the `src/` directory contains solutions
for every step towards an implementation of the container technology.

The C code can have some implementation gaps.

## Materials

[Whitepaper - Understanding and hardening Linux Containers](https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/2016/april/ncc_group_understanding_hardening_linux_containers-1-1.pdf)

[Introducing Linux Network Namespaces](https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/)

[Creating containers](http://crosbymichael.com/creating-containers-part-1.html)

[A deep dive into Linux namespaces, part 3](http://ifeanyi.co/posts/linux-namespaces-part-3/)

[Mount namespaces and shared subtrees - LWN article](https://lwn.net/Articles/689856/)

## Introduction to container technology

In general, a container is lightweight virtualization that, among others, allows to:
* run a process in separate, isolated sandbox (environment)
* have a separate filesystem mounted to a container
* isolate a container from the security perspective (allow/disallow system calls)
* limit the privileges of the process run in a container
* limit resources allocated for a container

Containers are based on following concepts:

* `namespaces` - Linux (or kernel) namespaces allows to create a new logical instances of an operating system's subsystems. Other definition says that "Linux namespace is a scoped view of your underlying Linux system".
As a result, the new instances are isolated from the OS they are running on and from the instances running in other namespaces.
There are following namespaces in Linux:
  * **UTS namespace** is about isolating hostnames. This namespace allows to set a different hostname for a container.
  * **MNT namespace** allows to mount a separate file system for a container.
  * **PID namespace** gives a container an isolated view on currently running Linux processes. As a result, a container will see only its own processes (processes of host OS will not be visible).
  * **IPC namespace** isolates an inter-process communication. It prevents processes in different namespaces from establishing a shared memory to communicate with each other.
  * **USER namespace** allows to create a separate, (usually) privileged user (technically it's a logical mapping of a user created in host OS, I will explain it later) within the namespace. Users configured in a host OS are not visible from a container.
  * **NET namespace** creates a logical instance of a Linux network stack. A container has its own list of network interfaces, routing table and iptables rules.
* `cgroups` and `setrlimit` - these both mechanisms are used to limit usage of resources (e.g. memory, disk I/O, CPU time) for a container.
* `root capabilities` - capabilities limits the privileges of root user of container.
* `Pivot_root` - the mechanism to change the root file system for a container.

Technically, a container is just a separate process, which is isolated from the host OS by using the concept of Linux namespaces.
Moreover, resources and privileges of this process are limited. All together creates the abstraction of a container.

## Tutorial

I've splitted this tutorial into several parts and I have implemented a container incrementally (step by step).

I started from implementing support for `namespaces`, then added support for `cgroups`, `root capabilities`, `pivot_root`, security isolation and network isolation.

Each implementation step I put into separated directories:

* [Basic structure](./src/00-cnt.c) - this file contains the basic template for the app. It can be used as a starting point (app skeleton).
* [src](./src/)
  ** This directory contains several C programs, each implementing one feature incrementally in the following order
     (any subsequent program is built on top of the previous one):
     * UTS namespace (`01-cnt-uts.c`)
     * MNT namespace (`02-cnt-mnt.c`)
     * PID namespace (`03-cnt-pid.c`)
     * IPC namespace (`04-cnt-ipc.c`)
     * USER namespace (`05-cnt-user.c`)
     * NETWORK namespace (`06-cnt-net.c`)
     * Resource limitation (`07-cnt-cgroups.c`)
     * Security isolation (`08-cnt-sec.c`)

Below I describe the C code needed to implement specific features. I also show how to compile, run & test each program.

I was testing whether namespace isolation is applied using following commands:
```
# NET namespace
$ ip a
$ ip route
$ ifconfig

# PID namespace
$ ps aux

# MNT namespace
$ mount

# IPC namespace
# Create message queue first on host by ipcmk -Q
$ ipcs -q

# USER namespace
$ ls -la
$ id -u
$ id -g

# UTS namespace
$ hostname
```

### UTS namespace

[01-cnt-uts.c](./src/01-cnt-uts.c) contains the code implementing container isolated in only UTS namespace.

In case of UTS namespace it's all about passing a CLONE_NEWUTS to `clone()` function and invoking `sethostname()` from within a child process.

The result can be tested by using `hostname` command from the container and outside the container:

Compile:

`gcc -Wall 01-cnt-uts.c -o cnt`

Run and test hostname (it's isolated):

```bash
$ sudo ./cnt -c /bin/sh
  => choosing hostname for container..
  => Hostname: cnt-02919
  => child process created with PID 8485
  # hostname
  cnt-02919
  #
```

However, any other resource (PID, Network, MNT, IPC, USER) are not isolated (we see global resources).

### Capabilities

Before implementing MNT namespace I describe the process of applying a root capabilities for a user in container.
Capabilities limit the privileges of a child process.


### MNT namespace

[02-cnt-mnt.c](./src/02-cnt-mnt.c) contains the code implementing container isolated in UTS and MNT namespace.

Isolating container in the MNT namespace is a little bit more complex. First of all, we need to provide a new **filesystem** for the container.
I recommend to use Alpine miniroot filesystem:

```bash
$ wget http://dl-cdn.alpinelinux.org/alpine/v3.10/releases/x86_64/alpine-minirootfs-3.10.1-x86_64.tar.gz
$ mkdir rootfs
$ tar -xzf alpine-minirootfs-3.10.1-x86_64.tar.gz -C rootfs
$ ls rootfs
```

We will use `rootfs/` as a mount directory for the container.

Next, in the C code I add `-m <mount-dir>` option, which is used to provide a mount point for the MNT namespace of the container.

In a child process the `setmountns()` function is called. This function is responsbile for mounting `<mount-dir>` as a root filesystem for the container. In particular,
it does following operations:

1. remounts current root filesystem with MS_PRIVATE
2. creates temporary directory, where the old root will be stored
3. pivots root (swaps the mount at `/` with another (the `<mount-dir>` in this case).
4. removes the old root

The implementation can be tested using `mount` command. From within the container it should show no mounts.

### PID namespace

The extension implementing PID namespace is located in the `cnt-pid.c` file. It is built on top of the `cnt-mnt.c`.

If we would run `cnt-mnt.c` and invoke `ps aux` command we would see:

```
/ # ps aux
PID   USER     TIME  COMMAND
# empty!!!
```

This is because we have mounted a new file system with an empty `/proc` directory. Linux uses `/proc` directory to store
information about all processes running in the system. As the `/proc` is empty, we cannot see any process.

To fix that, we need to prepare `/proc` filesystem before running the process inside the container.

In `cnt-pid/c` I first create a new (PID) namespace by passing additional flag (`CLONE_NEWPID`) to the `clone()` function.

Then, the `/proc` file system needs to be prepared for a child process. This is done in `prepare_procfs()` function. This function
creates a new `/proc` directory in the container's file system, which has just been mounted. Additionally, it mounts the `proc` mount
of a parent process to the `/proc` of the container. The `proc` mount exists on the list returned by `mount` command invoked from a host system:
```
...
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
...
```

As the container is running inside a PID namespace, it will have an access only to processes belonging to it. Now, the output of `ps aux` from
within a container looks as follows:
```bash
/ # ps aux
PID   USER     TIME  COMMAND
    1 root      0:00 /bin/sh
    2 root      0:00 ps aux
```

### IPC namespace

Adding the IPC namespace is as simple as appending the new flag (`CLONE_NEWIPC`) to the `clone()` function.

To verify whether container has been isolated in the IPC namespace run following commands:

```
# From a host OS
$ dev@dev:~/workspace/containers-impl-c/namespaces$ ipcmk -Q
  Message queue id: 0
$ dev@dev:~/workspace/containers-impl-c/namespaces$ ipcs -q
------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages
0xe22a5010 0          dev        644        0            0
# Enter container and run:
$ / # ipcs -q

  ------ Message Queues --------
  key        msqid      owner      perms      used-bytes   messages

```

As you can see, `ipcs -q` returns no message queues even if we created before entering the container.

### USER namespace

USER namespaces are a little bit more complex than the previous namespaces I've implemented.
Hence, I encourage every reader to familiarize themselves with following two articles about USER namespaces:

https://lwn.net/Articles/532593/

https://lwn.net/Articles/540087/

In general, USER namespace allows to map a process's user and group IDs within the namespace with its IDS outside the namespace.
Thus, a process can be privileged to make some operations inside the namespace, but it would not be allowed to perform the same operations
outside the namespace.

To isolate a container (process) in a USER namespace properly there need to be a mapping from the user IDs (and group IDs also)
inside a USER namespace to a corresponding set of user IDs outside the namespace. Otherwise, the system calls returning user and group IDs
(wrapped by `getuid()` and `getgid()`) return the value defined in the file `/proc/sys/kernel/overflowuid` for user ID and
`/proc/sys/kernel/overflowgid` for group ID (normally these values equal to 65534).

Note that in my example if I've passed a CLONE_NEWUSER flag to `clone()` the mount process failed with a message `failed making the inner directory!`!
It's because the user with ID 65534 is not allowed to create an inner directory.

To make things working a `uid` and `gid` mapping has to be configured.

Every process stores a `uid` and `gid` mapping information in the file `/proc/PID/uid_map` and `/proc/PID/gid_map`, respectively.

These files must be properly configured to provide a mapping. As these files are owned by the user ID that created the namespace, it is
the only user (except for root), who is allowed to write to these files. Therefore, it requires communication between a child and parent process.
I decided to implement the communication channel between them using Linux pipes [1].

The whole process of isolating a process in a USER namespace must be synchronized and should look as follows:

1. A parent opens a communication channel and forks a child process.
2. A child process informs the parent to start configuring user and group ID for the child process.
3. The parent waits for signal from the child and, if received, it configures user and group IDs by appending
new line to the files storing mapping information. Then, it notifies the child that the job is completed.
4. The child process waits for signal from the parent and, then, it invokes `setgroups`, `setresgid` and `setresuid` to complete the process of configuring
user and group IDs. Finally, the child process executes the main command (e.g. `/bin/sh`).

My solution for a USER namespace can be found in `05-cnt-user.c`.

To compile run:

`gcc -Wall 05-cnt-user.c -o cnt -lcap`

To verify proper behaviour:

```bash
# From a host OS
$ dev@dev:~/workspace/containers-impl-c/namespaces$ id -u
1000
$ dev@dev:~/workspace/containers-impl-c/namespaces$ id -g
1000

# From a container
$ / # id -u
0
$ / # id -g
0
```

### NET namespace

NET namespace simply creates a new, logical instance of a network stack for a container. It's worth to
outline that network namespace does not create a separate Linux network stack! It just creates a new partition (subset) of
network resources within a single kernel instance.

Before going further let's take a look at these two articles describing basics of network namespaces:

- https://lwn.net/Articles/580893/

- https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/

In this tutorial, my goal is to isolate a container within a network namespace, run a simple HTTP server inside a container and, then,
interact with the server from outside of the container.

There are a few comments on how we will use NET namespace:

* Once created, a network namespace contains only `loopback` interface. However, this interface has to be configured (activated) before
using it.
* To communicate with outside world (Host OS) there must be some additional interface configured. In this example, I will use a
commonly used virtual Ethernet (`veth`) device.

First step to initialize a network namespace is to pass `CLONE_NEWNET` to `clone()`. As a result, after this simple
modification we can see only the `loopback` interface and empty routing tables from a container.

We would stop at this stage, but the goal is to provide a communication channel with the outside world. In `configure_network()`
I implementated the logic to create `veth` interface. I use `Netlink` sockets to communicate with Linux kernel and request
it to setup `veth` virtual devices. This will be done by the parent process, just after configuring a USER namespace. It means that
there is not additional action required from within a child process. `delete_network()` removes `veth` interfaces and their configuration,
when a container is stopped.



To compile run:

`gcc -I. -o cnt -Wall 06-cnt-net.c lib/netns.c -lcap`




## Concluding remarks

First of all, the process of implementing a container was a big fun for me!

Additionally, I've learned a lot of new concepts and mechanisms, learning and fun is perfect combo :)

Moreover, I have some thoughts, which may be nice summary of this tutorial:

* Implementing a simple container is all about handy usage of underlying Linux mechanisms.
* Saying "handy" I meant that we need to use these mechanisms in the proper order as one kind of a namespace can impact
  the others.

## References

[1] https://linux.die.net/man/2/pipe
