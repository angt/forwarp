#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <linux/rtnetlink.h>

#define FWP_PATH "/run/forwarp"
#define COUNT(x) (sizeof(x) / sizeof((x)[0]))

volatile sig_atomic_t fwp_quit;

struct fwp_b2 { unsigned char b[2]; };
struct fwp_b4 { unsigned char b[4]; };
struct fwp_b6 { unsigned char b[6]; };

const struct fwp_b2 proto_vlan = {.b = {129}};
const struct fwp_b2 proto_arp  = {.b = {8, 6}};
const struct fwp_b6 arp_hdr    = {.b = {0, 1, 8, 0, 6, 4}};

struct fwp_addr {
    struct fwp_b6 ll;
    struct fwp_b4 ip;
};

struct fwp_arp {
    struct fwp_b6 hdr;
    struct fwp_b2 op;
    struct fwp_addr s, t;
};

struct fwp_pkt {
    struct fwp_b6 t, s;
    struct fwp_b2 proto;
    union {
        struct {
            struct fwp_b2 id;
            struct fwp_b2 proto;
            struct fwp_arp arp;
        } vlan;
        struct fwp_arp arp;
    };
};

struct fwp_reply {
    unsigned index;
    uint32_t ip;
    uint32_t mask;
};

struct fwp_vlan {
    unsigned index;
    unsigned vid;
};

struct fwp_msg {
    unsigned char op;
    unsigned vlan;
    struct fwp_reply reply;
};

struct fwp {
    int fd;
    struct fwp_addr addr;
    unsigned index;
    unsigned op;
    struct {
        size_t size;
        size_t count;
    } block, frame;
    unsigned n;
    unsigned char *map;
    size_t map_size;
};

union fwp_sun {
    struct sockaddr sa;
    struct sockaddr_un sun;
};

struct fwp_ctl {
    int fd;
    union fwp_sun sock;
    union fwp_sun del;
};

static void
fwp_sa_handler()
{
    fwp_quit = 1;
}

static int
fwp_init_map(struct fwp *fwp)
{
    int v3 = TPACKET_V3;

    if (setsockopt(fwp->fd, SOL_PACKET, PACKET_VERSION,
                   &v3, sizeof(v3)) == -1) {
        perror("sso(PACKET_VERSION)");
        return 1;
    }
    fwp->block.size  = 16 * 4096;
    fwp->block.count = 2;
    fwp->map_size    = fwp->block.size * fwp->block.count;

    fwp->frame.size  = 8 * 16;
    fwp->frame.count = fwp->map_size / fwp->frame.size;
    fwp->n           = 0;

    struct tpacket_req3 req = {
        .tp_block_size      = fwp->block.size,
        .tp_block_nr        = fwp->block.count,
        .tp_frame_size      = fwp->frame.size,
        .tp_frame_nr        = fwp->frame.count,
        .tp_retire_blk_tov  = 60,
    };
    if (setsockopt(fwp->fd, SOL_PACKET, PACKET_RX_RING,
                   &req, sizeof(req)) == -1) {
        perror("sso(PACKET_RX_RING)");
        return 1;
    }
    fwp->map = mmap(NULL, fwp->map_size,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_LOCKED, fwp->fd, 0);

    if (fwp->map == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    return 0;
}

static int
fwp_init(struct fwp *fwp, const char *name, unsigned op)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

    fwp->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (fwp->fd == -1) {
        perror("socket(AF_PACKET)");
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
    memcpy(&fwp->addr.ll.b, &ifr.ifr_hwaddr.sa_data, sizeof(fwp->addr.ll.b));

    fprintf(stderr, "Found %s: %02x:%02x:%02x:%02x:%02x:%02x\n", name,
           fwp->addr.ll.b[0], fwp->addr.ll.b[1], fwp->addr.ll.b[2],
           fwp->addr.ll.b[3], fwp->addr.ll.b[4], fwp->addr.ll.b[5]);

    fwp->op = op;
    return 0;
}

static int
fwp_bind(struct fwp *fwp)
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
    struct sock_filter filter0[] = {
        {0x06, 0, 0, 0x00000000},
    };
    struct sock_fprog bpf0 = {
        .len = 1,
        .filter = filter0,
    };
    if (setsockopt(fwp->fd, SOL_SOCKET, SO_ATTACH_FILTER,
                   &bpf0, sizeof(bpf0)) == -1) {
        perror("setsockopt(SO_ATTACH_FILTER)");
        return 1;
    }
    char tmp[1];
    while (recv(fwp->fd, tmp, sizeof(tmp), MSG_TRUNC | MSG_DONTWAIT) >= 0)
        ;
    struct sock_filter filter[] = {
        {0x00,  0,  0, 0x00000000},
        {0x02,  0,  0, 0x00000000},
        {0x28,  0,  0, 0x0000000c},
        {0x15,  0,  1, 0x00000806},
        {0x15, 10, 28, 0x00000806},
        {0x00,  0,  0, 0x00000004},
        {0x02,  0,  0, 0x00000000},
        {0x28,  0,  0, 0x0000000c},
        {0x15,  4,  0, 0x00008100},
        {0x15,  3,  0, 0x000088a8},
        {0x15,  2,  0, 0x00009100},
        {0x30,  0,  0, 0xfffff030},
        {0x15,  0, 20, 0x00000001},
        {0x28,  0,  0, 0x00000010},
        {0x15,  0, 18, 0x00000806},
        {0x00,  0,  0, 0x00000006},
        {0x61,  0,  0, 0x00000000},
        {0x0c,  0,  0, 0x00000000},
        {0x07,  0,  0, 0x00000000},
        {0x48,  0,  0, 0x0000000e},
        {0x15,  0, 12, fwp->op   },
        {0x61,  0,  0, 0x00000000},
        {0x87,  0,  0, 0x00000000},
        {0x07,  0,  0, 0x00000000},
        {0x40,  0,  0, 0x0000000e},
        {0x15,  0,  7, 0x00010800},
        {0x00,  0,  0, 0x00000004},
        {0x61,  0,  0, 0x00000000},
        {0x0c,  0,  0, 0x00000000},
        {0x07,  0,  0, 0x00000000},
        {0x48,  0,  0, 0x0000000e},
        {0x15,  0,  1, 0x00000604},
        {0x06,  0,  0, 0x00040000},
        {0x06,  0,  0, 0x00000000},
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
        perror("socket(AF_NETLINK)");
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
    fwp_attr(&req.nh, NDA_DST, addr->ip.b, sizeof(addr->ip));
    fwp_attr(&req.nh, NDA_LLADDR, addr->ll.b, sizeof(addr->ll));

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
ipmask(struct fwp_b4 ip, uint32_t mask)
{
    uint32_t tmp;
    memcpy(&tmp, &ip, 4);
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

static int
fwp_ctl_init(struct fwp_ctl *ctl, const char *id, int client)
{
    union fwp_sun sock = {
        .sun.sun_family = AF_UNIX,
    };
    if (mkdir(FWP_PATH, 0700) == -1 && errno != EEXIST)
        return -1;

    int ret = snprintf(sock.sun.sun_path, sizeof(sock.sun.sun_path),
                       "%s/%s", FWP_PATH, id);

    if (ret <= 0 || (size_t)ret >= sizeof(sock.sun.sun_path)) {
        errno = EINVAL;
        return -1;
    }
    ctl->sock = sock;

    if (client) {
        ret = snprintf(sock.sun.sun_path, sizeof(sock.sun.sun_path),
                       "%s/.%d", FWP_PATH, getpid());

        if (ret <= 0 || (size_t)ret >= sizeof(sock.sun.sun_path)) {
            errno = EINVAL;
            return -1;
        }
    }
    ctl->del = sock;

    if (unlink(sock.sun.sun_path) && errno != ENOENT)
        return -1;

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (fd == -1)
        return -1;

    if (bind(fd, &sock.sa, sizeof(sock))) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    ctl->fd = fd;
    return 0;
}

static void
fwp_ctl_close(struct fwp_ctl *ctl)
{
    if (ctl->fd >= 0) {
        close(ctl->fd);
        ctl->fd = -1;
    }
    unlink(ctl->del.sun.sun_path);
}

static int
fwp_run(const char *id, const char *ifsrc, const char *ifdst)
{
    enum {src, dst, count};
    struct fwp fwp[count] = {0};
    struct fwp_ctl ctl = {.fd = -1};

    if (fwp_ctl_init(&ctl, id, 0)) {
        perror("fwp_ctl_init");
        return 1;
    }
    if (fwp_init(&fwp[src], ifsrc, ARPOP_REQUEST) ||
        fwp_init(&fwp[dst], ifdst, ARPOP_REPLY))
        return 1;

    if (fwp_bind(&fwp[src]) ||
        fwp_bind(&fwp[dst]))
        return 1;

    if (fwp_init_map(&fwp[src]) ||
        fwp_init_map(&fwp[dst]))
        return 1;

    fprintf(stderr, "Listening...\n");

    struct fwp_msg msg;
    struct fwp_reply replies[4096] = {0};

    struct pollfd fds[] = {
        [src] = {.fd = fwp[src].fd, .events = POLLIN},
        [dst] = {.fd = fwp[dst].fd, .events = POLLIN},
        [  2] = {.fd = ctl.fd,      .events = POLLIN}, // TODO
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
        if (fds[src].revents & POLLIN) { // TODO
            struct fwp *f = &fwp[src];

            struct tpacket_block_desc *desc = (struct tpacket_block_desc *)
                &f->map[f->block.size * f->n];

            if (desc->hdr.bh1.block_status & TP_STATUS_USER) {
                const unsigned num_pkts = desc->hdr.bh1.num_pkts;

                struct tpacket3_hdr *ppd = (struct tpacket3_hdr *)
                    ((uint8_t *)desc + desc->hdr.bh1.offset_to_first_pkt);

                for (unsigned i = 0; i < num_pkts; i++) {
                    uint8_t *buf = ((uint8_t *) ppd + ppd->tp_mac);
                    unsigned vlan = 4095;
                    struct fwp_pkt *pkt = (struct fwp_pkt *)buf;
                    struct fwp_arp *arp = &pkt->arp;

                    int fd = -1;
                    struct fwp_pkt rep;
                    size_t rep_size = sizeof(rep);

                    if (!memcmp(&pkt->proto, &proto_vlan, 2)) {
                        vlan = pkt->vlan.id.b[0] & 15;
                        vlan = (vlan << 8) | pkt->vlan.id.b[1];
                        arp = &pkt->vlan.arp;
                    }
                    if (ppd->tp_status & TP_STATUS_VLAN_VALID)
                        vlan = ppd->hv1.tp_vlan_tci & 0xFFF;

                    if (vlan == 4095)
                        rep_size -= 4;

                    struct fwp_reply reply = replies[vlan];

                    if (!memcmp(&arp->s.ll, &fwp[src].addr.ll, sizeof(pkt->arp.s.ll))) {
                        if (vlan == 4095) {
                            rep = (struct fwp_pkt) {
                                .t = pkt->t,
                                .s = fwp[dst].addr.ll,
                                .proto = proto_arp,
                                .arp = {
                                    .hdr = arp_hdr,
                                    .op = arp->op,
                                    .s = fwp[dst].addr,
                                    .t = arp->t,
                                },
                            };
                        } else {
                            rep = (struct fwp_pkt) {
                                .t = pkt->t,
                                .s = fwp[dst].addr.ll,
                                .proto = proto_vlan,
                                .vlan = {
                                    .id.b = {(vlan >> 8) & 15, vlan & 255},
                                    .proto = proto_arp,
                                    .arp = {
                                        .hdr = arp_hdr,
                                        .op = arp->op,
                                        .s = fwp[dst].addr,
                                        .t = arp->t,
                                    },
                                },
                            };
                        }
                        fd = fwp[dst].fd;
                    } else if (reply.ip && (ipmask(arp->t.ip, reply.mask) == reply.ip)) {
                        if (vlan == 4095) {
                            rep = (struct fwp_pkt) {
                                .t = pkt->s,
                                .s = fwp[src].addr.ll,
                                .proto = proto_arp,
                                .arp = {
                                    .hdr = arp_hdr,
                                    .op.b[1] = ARPOP_REPLY,
                                    .s.ll = fwp[src].addr.ll,
                                    .s.ip = arp->t.ip,
                                    .t = arp->s,
                                },
                            };
                        } else {
                            rep = (struct fwp_pkt) {
                                .t = pkt->s,
                                .s = fwp[src].addr.ll,
                                .proto = proto_vlan,
                                .vlan = {
                                    .id.b = {(vlan >> 8) & 15, vlan & 255},
                                    .proto = proto_arp,
                                    .arp = {
                                        .hdr = arp_hdr,
                                        .op.b[1] = ARPOP_REPLY,
                                        .s.ll = fwp[src].addr.ll,
                                        .s.ip = arp->t.ip,
                                        .t = arp->s,
                                    },
                                },
                            };
                        }
                        fd = fwp[src].fd;
                    }
                    if (fd >= 0 && send(fd, &rep, rep_size, 0) == -1) {
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
                    ppd = (struct tpacket3_hdr *)
                        ((uint8_t *) ppd + ppd->tp_next_offset);
                }
                desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
                f->n = (f->n + 1) % f->block.count;
            }
        }
        if ((fds[dst].revents & POLLIN)) {
            struct fwp *f = &fwp[dst];

            struct tpacket_block_desc *desc = (struct tpacket_block_desc *)
                &f->map[f->block.size * f->n];

            if (desc->hdr.bh1.block_status & TP_STATUS_USER) {
                const unsigned num_pkts = desc->hdr.bh1.num_pkts;

                struct tpacket3_hdr *ppd = (struct tpacket3_hdr *)
                    ((uint8_t *)desc + desc->hdr.bh1.offset_to_first_pkt);

                for (unsigned i = 0; i < num_pkts; i++) {
                    uint8_t *buf = ((uint8_t *) ppd + ppd->tp_mac);
                    unsigned vlan = 4095;
                    struct fwp_pkt *pkt = (struct fwp_pkt *)buf;

                    if (!memcmp(&pkt->proto, &proto_vlan, 2)) {
                        vlan = pkt->vlan.id.b[0] & 15;
                        vlan = (vlan << 8) | pkt->vlan.id.b[1];
                    }
                    if (ppd->tp_status & TP_STATUS_VLAN_VALID)
                        vlan = ppd->hv1.tp_vlan_tci & 0xFFF;

                    fwp_neigh(replies[vlan].index, &pkt->arp.s, NUD_REACHABLE);

                    ppd = (struct tpacket3_hdr *)
                        ((uint8_t *) ppd + ppd->tp_next_offset);
                }
                desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
                f->n = (f->n + 1) % f->block.count;
            }
        }
        if (fds[2].revents & POLLIN) {
            ssize_t r = recv(ctl.fd, &msg, sizeof(msg), 0);

            if (r < (ssize_t)sizeof(msg)) {
                if (r == (ssize_t)-1)
                    perror("recv");
                continue;
            }
            if (msg.vlan == 0xFFF) // TODO
                msg.reply.index = fwp[src].index;

            if (msg.vlan <= 0xFFF) {
                fprintf(stderr, "New rule: vlan %u index %u ip %d.%d.%d.%d mask %d.%d.%d.%d\n",
                        msg.vlan,
                        msg.reply.index,
                        (msg.reply.ip        ) & 255,
                        (msg.reply.ip   >>  8) & 255,
                        (msg.reply.ip   >> 16) & 255,
                        (msg.reply.ip   >> 24) & 255,
                        (msg.reply.mask      ) & 255,
                        (msg.reply.mask >>  8) & 255,
                        (msg.reply.mask >> 16) & 255,
                        (msg.reply.mask >> 24) & 255);
                replies[msg.vlan] = msg.reply;
            }
        }
    }
    return 0;
}

static int
fwp_vlan_init(struct fwp_vlan *v, const char *name)
{
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

    int fd = socket(AF_PACKET, SOCK_RAW, 0);

    if (fd == -1)
        return 1;

    if (ioctl(fd, SIOCGIFINDEX, &ifr) || ifr.ifr_ifindex <= 0) {
        close(fd);
        return 1;
    }
    unsigned index = ifr.ifr_ifindex;

    struct vlan_ioctl_args ifv = {
        .cmd = GET_VLAN_VID_CMD,
    };
    strncpy(ifv.device1, name, sizeof(ifv.device1) - 1);

    if (ioctl(fd, SIOCGIFVLAN, &ifv)) {
        close(fd);
        return 1;
    }
    v->index = index;
    v->vid = ifv.u.VID;
    return 0;
}

static int
fwp_set(const char *id, const char *ip, const char *name)
{
    struct fwp_msg msg = {
        .op = 1,
        .vlan = -1,
        .reply.mask = UINT32_MAX,
    };
    unsigned cidr = 0;
    const char *s = ipparse(ip, &msg.reply.ip);

    if (!msg.reply.ip) {
        fprintf(stderr, "Unable to parse IP %s\n", ip);
        return 1;
    }
    if (s[0] != '/' || uparse(s + 1, &cidr, 32)[0] || !cidr) {
        fprintf(stderr, "Unable to parse CIDR %s\n", s);
        return 1;
    }
    if (cidr > 0 && cidr < 32)
        msg.reply.mask = htonl(msg.reply.mask << (32 - cidr));

    msg.reply.ip &= msg.reply.mask;

    if (name) {
        struct fwp_vlan vlan;
        if (fwp_vlan_init(&vlan, name)) {
            fprintf(stderr, "Unable to get VID of %s\n", name);
            return 1;
        }
        msg.reply.index = vlan.index;
        msg.vlan = vlan.vid;
    } else {
        msg.vlan = 0xFFF;
    }
    struct fwp_ctl ctl;

    if (fwp_ctl_init(&ctl, id, 1))
        return 1;

    if (connect(ctl.fd, &ctl.sock.sa, sizeof(ctl.sock))) {
        perror("connect");
        fwp_ctl_close(&ctl);
        return 1;
    }
    if (send(ctl.fd, &msg, sizeof(msg), 0) == -1) {
        switch (errno) {
        case EINTR:     /* FALLTHRU */
        case EAGAIN:    /* FALLTHRU */
        case ENETDOWN:
            break;
        default:
            perror("send");
            fwp_ctl_close(&ctl);
            return 1;
        }
    }
    fwp_ctl_close(&ctl);

    return 0;
}

int
main(int argc, char **argv)
{
    fwp_set_signal();

    if (argc >= 2 && !strcmp(argv[1], "run")) {
        if (argc != 5) {
            printf("usage: %s run ID IFSRC IFDST\n", argv[0]);
            return 1;
        }
        return fwp_run(argv[2], argv[3], argv[4]);
    }
    if (argc >= 2 && !strcmp(argv[1], "set")) {
        if (argc != 4 && argc != 5) {
            printf("usage: %s set ID CIDR [IFVLAN]\n", argv[0]);
            return 1;
        }
        return fwp_set(argv[2], argv[3], argv[4]);
    }
    printf("usage: %s { run | set }\n", argv[0]);
    return 1;
}
