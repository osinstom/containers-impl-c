#include <stdio.h>
#include <string.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "netns.h"


static void addattr_l(
        struct nlmsghdr *n, int maxlen, __u16 type,
        const void *data, __u16 datalen)
{
    __u16 attr_len = RTA_LENGTH(datalen);

    __u32 newlen = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(attr_len);
    if (newlen > maxlen)
        return;

    struct rtattr *rta;
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = attr_len;
    if (datalen)
        memcpy(RTA_DATA(rta), data, datalen);

    n->nlmsg_len = newlen;
}

static struct rtattr *addattr_nest(
        struct nlmsghdr *n, int maxlen, __u16 type)
{
    struct rtattr *nest = NLMSG_TAIL(n);

    addattr_l(n, maxlen, type, NULL, 0);
    return nest;
}

static void addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
    nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
}

static ssize_t read_response(
        int fd, struct msghdr *msg, char **response)
{
    struct iovec *iov = msg->msg_iov;
    iov->iov_base = *response;
    iov->iov_len = MAX_PAYLOAD;

    ssize_t resp_len = recvmsg(fd, msg, 0);

    if (resp_len == 0)
        return -1;

    if (resp_len < 0)
        return -1;

    return resp_len;
}

static void check_response(int sock_fd)
{
    struct iovec iov;
    struct msghdr msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1
    };
    char *resp = malloc(MAX_PAYLOAD);

    ssize_t resp_len = read_response(sock_fd, &msg, &resp);

    struct nlmsghdr *hdr = (struct nlmsghdr *) resp;
    int nlmsglen = hdr->nlmsg_len;
    int datalen = nlmsglen - sizeof(*hdr);

    // Did we read all data?
    if (datalen < 0 || nlmsglen > resp_len) {
        if (msg.msg_flags & MSG_TRUNC)
            return;

        return;
    }

    // Was there an error?
    if (hdr->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(hdr);

        if (datalen < sizeof(struct nlmsgerr))
            fprintf(stderr, "ERROR truncated!\n");

        if(err->error) {
            return;
        }
    }

    free(resp);
}

int create_socket(int domain, int type, int protocol)
{
    int sock_fd = socket(domain, type, protocol);
    if (sock_fd < 0)
        return -1;

    return sock_fd;
}

static void send_nlmsg(int sock_fd, struct nlmsghdr *n)
{
    struct iovec iov = {
            .iov_base = n,
            .iov_len = n->nlmsg_len
    };

    struct msghdr msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1
    };

    n->nlmsg_seq++;

    ssize_t status = sendmsg(sock_fd, &msg, 0);
    if (status < 0)
        return;

    check_response(sock_fd);
}

int get_netns_fd(int pid)
{
    char path[256];
    sprintf(path, "/proc/%d/ns/net", pid);

    int fd = open(path, O_RDONLY);

    if (fd < 0)
        return -1;

    return fd;
}

int if_up(
        char *ifname, char *ip, char *netmask)
{
    int sock_fd = create_socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, strlen(ifname));

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = 0;

    char *p = (char *) &saddr;

    saddr.sin_addr.s_addr = inet_addr(ip);
    memcpy(((char *)&(ifr.ifr_addr)), p, sizeof(struct sockaddr));
    if (ioctl(sock_fd, SIOCSIFADDR, &ifr)) {
        close(sock_fd);
        return -1;
    }

    saddr.sin_addr.s_addr = inet_addr(netmask);
    memcpy(((char *)&(ifr.ifr_addr)), p, sizeof(struct sockaddr));
    if (ioctl(sock_fd, SIOCSIFNETMASK, &ifr)) {
        close(sock_fd);
        return -1;
    }

    ifr.ifr_flags |= IFF_UP | IFF_BROADCAST |
                     IFF_RUNNING | IFF_MULTICAST;
    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr)) {
        close(sock_fd);
        return -1;
    }

    close(sock_fd);
    return 0;
}

int create_veth_pair(int sock_fd, char *ifname, char *peername)
{
    // ip link add veth0 type veth peer name veth1
    __u16 flags =
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    struct nl_req req = {
            .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .n.nlmsg_flags = flags,
            .n.nlmsg_type = RTM_NEWLINK,
            .i.ifi_family = PF_NETLINK,
    };
    struct nlmsghdr *n = &req.n;
    int maxlen = sizeof(req);

    addattr_l(n, maxlen, IFLA_IFNAME, ifname, strlen(ifname) + 1);

    struct rtattr *linfo =
            addattr_nest(n, maxlen, IFLA_LINKINFO);
    addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, "veth", 5);

    struct rtattr *linfodata =
            addattr_nest(n, maxlen, IFLA_INFO_DATA);

    struct rtattr *peerinfo =
            addattr_nest(n, maxlen, VETH_INFO_PEER);
    n->nlmsg_len += sizeof(struct ifinfomsg);
    addattr_l(n, maxlen, IFLA_IFNAME, peername, strlen(peername) + 1);
    addattr_nest_end(n, peerinfo);

    addattr_nest_end(n, linfodata);
    addattr_nest_end(n, linfo);

    send_nlmsg(sock_fd, n);

    return 0;
}

int delete_veth_pair(int sock_fd, char *ifname, char *peername)
{
    __u16 flags =
            NLM_F_REQUEST | NLM_F_ACK;

    struct nl_req req = {
            .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .n.nlmsg_flags = flags,
            .n.nlmsg_type = RTM_DELLINK,
            .i.ifi_family = PF_NETLINK,
    };

    struct nlmsghdr *n = &req.n;
    int maxlen = sizeof(req);

    addattr_l(n, maxlen, IFLA_IFNAME, ifname, strlen(ifname) + 1);

    struct rtattr *linfo =
            addattr_nest(n, maxlen, IFLA_LINKINFO);
    addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, "veth", 5);

    struct rtattr *linfodata =
            addattr_nest(n, maxlen, IFLA_INFO_DATA);

    struct rtattr *peerinfo =
            addattr_nest(n, maxlen, VETH_INFO_PEER);
    n->nlmsg_len += sizeof(struct ifinfomsg);
    addattr_l(n, maxlen, IFLA_IFNAME, peername, strlen(peername) + 1);
    addattr_nest_end(n, peerinfo);

    addattr_nest_end(n, linfodata);
    addattr_nest_end(n, linfo);

    send_nlmsg(sock_fd, n);

    return 0;
}


void move_if_to_pid_netns(int sock_fd, char *ifname, int netns)
{
    // ip link set veth1 netns coke
    struct nl_req req = {
            .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
            .n.nlmsg_type = RTM_NEWLINK,
            .i.ifi_family = PF_NETLINK,
    };

    addattr_l(&req.n, sizeof(req), IFLA_NET_NS_FD, &netns, 4);
    addattr_l(&req.n, sizeof(req), IFLA_IFNAME,
              ifname, strlen(ifname) + 1);
    send_nlmsg(sock_fd, &req.n);
}
