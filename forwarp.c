#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
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
fwp_neigh(int ifindex, struct fwp_addr *addr, int nud_state)
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
            .ndm_state = nud_state,
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

static uint32_t
ipmask(unsigned char a[4], uint32_t mask)
{
    uint32_t tmp;
    memcpy(&tmp, a, 4);
    return tmp & mask;
}

static const char *
uparse(const char *s, unsigned *ret, unsigned n)
{
    int i = 0;
    unsigned v = 0;

    for (i = 0; v <= n && s[i] >= '0' && s[i] <= '9'; i++)
        v = 10 * v + s[i] - '0';

    if (i && v <= n)
        *ret = v;

    return s + i;
}

static const char *
cparse(const char *s, char c)
{
    return s + (s[0] == c);
}

static const char *
ipparse(const char *s, uint32_t *ret)
{
    unsigned i0 = 256, i1 = 256, i2 = 256, i3 = 256;

    s = cparse(uparse(s, &i0, 255), '.');
    s = cparse(uparse(s, &i1, 255), '.');
    s = cparse(uparse(s, &i2, 255), '.');
    s = uparse(s, &i3, 255);

    if (i0 < 256 && i1 < 256 && i2 < 256 && i3 < 256)
        *ret = i3 << 24 | i2 << 16 | i1 << 8 | i0;

    return s;
}

int
main(int argc, char **argv)
{
    fwp_set_signal();

    if (argc < 3 || argc > 5) {
        printf("usage: %s IFSRC IFDST { IP[/CIDR] | IP [MASK] }\n", argv[0]);
        return 1;
    }
    uint32_t ip = 0;
    unsigned cidr = 0;
    uint32_t mask = 0;
    const int nud_state = NUD_REACHABLE;

    enum {src, dst, count};
    struct fwp fwp[count] = {0};

    if (argc >= 4) {
        const char *s = ipparse(argv[3], &ip);
        int have_cidr = s[0] == '/';

        if (!ip || (s[0] && !have_cidr)) {
            fprintf(stderr, "Unable to parse ip %s\n", argv[3]);
            return 1;
        }
        if (have_cidr && (uparse(s + 1, &cidr, 32)[0] || !cidr)) {
            fprintf(stderr, "Unable to parse CIDR %s\n", s);
            return 1;
        }
        if (argc == 5) {
            if (have_cidr) {
                fprintf(stderr, "Mask, or CIDR, that is the question...\n");
                return 1;
            }
            if (ipparse(argv[4], &mask)[0] || !mask) {
                fprintf(stderr, "Unable to parse mask %s\n", argv[4]);
                return 1;
            }
        }
        if (!mask) {
            mask = UINT32_MAX;
            if (cidr > 0 && cidr < 32)
                mask = htonl(mask << (32 - cidr));
        }
        ip &= mask;
    }
    if (fwp_init(&fwp[src], argv[1], ARPOP_REQUEST) ||
        fwp_init(&fwp[dst], argv[2], ARPOP_REPLY))
        return 1;

    printf("Start forwarding ARP Request:\n"
           " src %02x:%02x:%02x:%02x:%02x:%02x\n"
           " dst %02x:%02x:%02x:%02x:%02x:%02x\n",
           fwp[src].addr.ll[0], fwp[src].addr.ll[1],
           fwp[src].addr.ll[2], fwp[src].addr.ll[3],
           fwp[src].addr.ll[4], fwp[src].addr.ll[5],
           fwp[dst].addr.ll[0], fwp[dst].addr.ll[1],
           fwp[dst].addr.ll[2], fwp[dst].addr.ll[3],
           fwp[dst].addr.ll[4], fwp[dst].addr.ll[5]);

    if (fwp_listen(&fwp[src]) || fwp_listen(&fwp[dst]))
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
        if ((fds[src].revents & POLLIN) && !fwp_recv(&fwp[src], &pkt)) {
            if (!memcmp(pkt.x.s.ll, fwp[src].addr.ll, sizeof(pkt.x.s.ll))) {
                memcpy(pkt.x.eth.h_source, fwp[dst].addr.ll, sizeof(pkt.x.eth.h_source));
                memcpy(&pkt.x.s, &fwp[dst].addr, sizeof(pkt.x.s));

                if (send(fwp[dst].fd, &pkt.x, sizeof(pkt.x), 0) == -1) {
                    switch (errno) {
                    case EINTR:     /* FALLTHRU */
                    case EAGAIN:    /* FALLTHRU */
                    case ENETDOWN:
                        break;
                    default:
                        perror("send(packet)");
                        return 1;
                    }
                }
            } else if (ip && (ipmask(pkt.x.t.ip, mask) == ip)) {
                unsigned char tmp[4];
                memcpy(&tmp, &pkt.x.t.ip, sizeof(tmp));
                memcpy(&pkt.x.t, &pkt.x.s, sizeof(pkt.x.t));
                memcpy(&pkt.x.s.ll, &fwp[src].addr.ll, sizeof(pkt.x.s.ll));
                memcpy(&pkt.x.s.ip, &tmp, sizeof(pkt.x.s.ip));
                memcpy(pkt.x.eth.h_dest, pkt.x.eth.h_source, sizeof(pkt.x.eth.h_dest));
                memcpy(pkt.x.eth.h_source, &fwp[src].addr.ll, sizeof(pkt.x.eth.h_source));
                pkt.x.arp.ar_op = htons(ARPOP_REPLY);

                if (send(fwp[src].fd, &pkt.x, sizeof(pkt.x), 0) == -1) {
                    switch (errno) {
                    case EINTR:     /* FALLTHRU */
                    case EAGAIN:    /* FALLTHRU */
                    case ENETDOWN:
                        break;
                    default:
                        perror("send");
                        return 1;
                    }
                }
            }
        }
        if ((fds[dst].revents & POLLIN) && !fwp_recv(&fwp[dst], &pkt))
            fwp_neigh(fwp[src].index, &pkt.x.s, nud_state);
    }
}
