#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>

#define COUNT(x) (sizeof(x) / sizeof((x)[0]))

volatile sig_atomic_t fwp_quit;

struct fwp_addr {
    unsigned char ll[ETH_ALEN];
    unsigned char ip[4];
};

union fwp_pkt {
    struct {
        struct ethhdr eth;
        struct arphdr arp;
        struct fwp_addr s, t;
    } x;
    unsigned char buf[1UL << 16];
};

struct fwp {
    int fd;
    struct fwp_addr addr;
    unsigned index;
    unsigned op;
};

static void
fwp_sa_handler()
{
    fwp_quit = 1;
}

static int
fwp_init(struct fwp *fwp, char *name, unsigned op)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

    fwp->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (fwp->fd == -1) {
        perror("socket");
        return 1;
    }

    if (ioctl(fwp->fd, SIOCGIFINDEX, &ifr) || ifr.ifr_ifindex <= 0) {
        fprintf(stderr, "No interface %s found!\n", ifr.ifr_name);
        return 1;
    }

    fwp->index = ifr.ifr_ifindex;

    if (ioctl(fwp->fd, SIOCGIFHWADDR, &ifr)) {
        fprintf(stderr, "Unable to find the hwaddr of %s\n", ifr.ifr_name);
        return 1;
    }

    memcpy(&fwp->addr.ll,
           &ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (ioctl(fwp->fd, SIOCGIFADDR, &ifr)) {
        fprintf(stderr, "Unable to find the addr of %s\n", ifr.ifr_name);
        return 1;
    }

    memcpy(&fwp->addr.ip,
           &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);

    fwp->op = op;
    return 0;
}

static int
fwp_listen(struct fwp *fwp)
{
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = fwp->index,
    };

    if (bind(fwp->fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("bind");
        return 1;
    }

    struct sock_filter filter[] = {
        {0x28, 0, 0, 0x0000000c},
        {0x15, 0, 3, 0x00000806},
        {0x28, 0, 0, 0x00000014},
        {0x15, 0, 1, fwp->op   },
        {0x06, 0, 0, 0x00040000},
        {0x06, 0, 0, 0x00000000},
    };

    struct sock_fprog bpf = {
        .len = COUNT(filter),
        .filter = filter,
    };

    if (setsockopt(fwp->fd, SOL_SOCKET, SO_ATTACH_FILTER,
                   &bpf, sizeof(bpf)) == -1) {
        perror("setsockopt(SO_ATTACH_FILTER)");
        return 1;
    }

    return 0;
}

static int
fwp_recv(struct fwp *fwp, union fwp_pkt *pkt)
{
    ssize_t r = recv(fwp->fd, pkt, sizeof(*pkt), 0);

    if (r < (ssize_t)sizeof(pkt->x)) {
        if (r == (ssize_t)-1)
            perror("recv");
        return -1;
    }

    if ((pkt->x.arp.ar_op != htons(fwp->op)) ||
        (pkt->x.arp.ar_hln != sizeof(pkt->x.s.ll)) ||
        (pkt->x.arp.ar_pln != sizeof(pkt->x.s.ip)))
        return -1;

    return 0;
}

static void
fwp_attr(struct nlmsghdr *n, int type, const void *data, unsigned size)
{
    struct rtattr *rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    unsigned len = RTA_LENGTH(size);

    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, size);

    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
}

static int
fwp_neigh(int ifindex, struct fwp_addr *addr)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (fd == -1) {
        perror("socket(netlink)");
        return 1;
    }

    struct {
        struct nlmsghdr nh;
        struct ndmsg ndm;
        unsigned char buf[256];
    } req = {
        .nh = {
            .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
            .nlmsg_type = RTM_NEWNEIGH,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
            .nlmsg_pid = getpid(),
        },
        .ndm = {
            .ndm_family = AF_INET,
            .ndm_state = NUD_REACHABLE,
            .ndm_ifindex = ifindex,
        },
    };

    fwp_attr(&req.nh, NDA_DST, addr->ip, sizeof(addr->ip));
    fwp_attr(&req.nh, NDA_LLADDR, addr->ll, sizeof(addr->ll));

    struct sockaddr_nl snl = {
        .nl_family = AF_NETLINK,
    };

    if (sendto(fd, &req, req.nh.nlmsg_len, 0,
               (struct sockaddr *)&snl, sizeof(snl)) == -1)
        perror("send(netlink)");

    close(fd);
    return 0;
}

static void
fwp_set_signal(void)
{
    struct sigaction sa = {
        .sa_flags = 0,
    };

    sigemptyset(&sa.sa_mask);

    sa.sa_handler = fwp_sa_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
}

int
main(int argc, char **argv)
{
    fwp_set_signal();

    if (argc != 3) {
        printf("usage: %s IFSRC IFDST\n", argv[0]);
        return 1;
    }

    enum {src, dst, count};
    struct fwp fwp[count];

    if (fwp_init(&fwp[src], argv[1], ARPOP_REQUEST) ||
        fwp_init(&fwp[dst], argv[2], ARPOP_REPLY))
        return 1;

    printf("Start forwarding ARP Request:\n"
           " src %02x:%02x:%02x:%02x:%02x:%02x ip %d.%d.%d.%d\n"
           " dst %02x:%02x:%02x:%02x:%02x:%02x ip %d.%d.%d.%d\n",
           fwp[src].addr.ll[0], fwp[src].addr.ll[1],
           fwp[src].addr.ll[2], fwp[src].addr.ll[3],
           fwp[src].addr.ll[4], fwp[src].addr.ll[5],
           fwp[src].addr.ip[0], fwp[src].addr.ip[1],
           fwp[src].addr.ip[2], fwp[src].addr.ip[3],
           fwp[dst].addr.ll[0], fwp[dst].addr.ll[1],
           fwp[dst].addr.ll[2], fwp[dst].addr.ll[3],
           fwp[dst].addr.ll[4], fwp[dst].addr.ll[5],
           fwp[dst].addr.ip[0], fwp[dst].addr.ip[1],
           fwp[dst].addr.ip[2], fwp[dst].addr.ip[3]);

    if (fwp_listen(&fwp[0]) || fwp_listen(&fwp[1]))
        return 1;

    union fwp_pkt pkt;

    struct pollfd fds[] = {
        {.fd = fwp[src].fd, .events = POLLIN},
        {.fd = fwp[dst].fd, .events = POLLIN},
    };

    while (!fwp_quit) {
        int p = poll(fds, COUNT(fds), -1);

        if (p <= 0) {
            if (p == -1 && errno != EINTR) {
                perror("poll");
                return 1;
            }
            continue;
        }

        if ((fds[src].revents & POLLIN) && !fwp_recv(&fwp[src], &pkt) &&
            (!memcmp(pkt.x.s.ll, fwp[src].addr.ll, ETH_ALEN))) {
            fprintf(stderr, "Forward ARP Request %d.%d.%d.%d\n",
                    pkt.x.t.ip[0], pkt.x.t.ip[1], pkt.x.t.ip[2], pkt.x.t.ip[3]);

            memcpy(pkt.x.eth.h_source, fwp[dst].addr.ll, sizeof(fwp[dst].addr.ll));
            memcpy(pkt.x.s.ll, fwp[dst].addr.ll, sizeof(pkt.x.s.ll));
            memcpy(pkt.x.s.ip, fwp[dst].addr.ip, sizeof(pkt.x.s.ip));

            if (send(fwp[dst].fd, &pkt.x, sizeof(pkt.x), 0) == -1) {
                switch (errno) {
                case EINTR:
                case EAGAIN:
                case ENETDOWN:
                    break;
                default:
                    perror("send(packet)");
                    return 1;
                }
            }
        }

        if ((fds[dst].revents & POLLIN) && !fwp_recv(&fwp[dst], &pkt)) {
            fprintf(stderr, "Add neigh %02x:%02x:%02x:%02x:%02x:%02x"
                            " as %d.%d.%d.%d\n",
                    pkt.x.s.ll[0], pkt.x.s.ll[1], pkt.x.s.ll[2],
                    pkt.x.s.ll[3], pkt.x.s.ll[4], pkt.x.s.ll[5],
                    pkt.x.s.ip[0], pkt.x.s.ip[1], pkt.x.s.ip[2], pkt.x.s.ip[3]);

            fwp_neigh(fwp[src].index, &pkt.x.s);
        }
    }

    return 0;
}
