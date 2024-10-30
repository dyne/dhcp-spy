/* DHCP discover-only client
 * This program checks for the presence of a DHCP server on the network,
 * and prints the information it receives from the server.
 *
 * (c) 2024 Dyne.org - Licensed under the GPLv3 - see license for details
 *
 * Authors: Daniele Lacamera and Denis Roio
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <time.h>
#include <poll.h>
#include <signal.h>

#include <sys/random.h>

#define DEFAULT_TIMEOUT 5 /* seconds */

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
/* Globals to keep track of the original MAC address */

static uint8_t original_mac[6] = {0};
static int custom_mac = 0;
static char devname[IFNAMSIZ] = "";


static int set_macaddr(const char *dev, uint8_t *mac)
{
    struct ifreq ifr;
    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    int ret = 0;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
    if (ret == 0) { 
        ifr.ifr_flags &= ~IFF_UP;
        ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
    }
    if (ret == 0) {
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
        ret = ioctl(sock, SIOCSIFHWADDR, &ifr);
    }
    if (ret == 0) {
        ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
    }
    if (ret == 0) {
        ifr.ifr_flags |= IFF_UP;
        ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
    }
    if (ret == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
    }
    return ret;
}


/* atexit() handler to restore the original MAC address */
static void restore_mac(void)
{
    if (custom_mac) {
        int sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
        struct ifreq ifr;
        custom_mac = 0;
        if (sock < 0) {
            fprintf(stderr,"socket() error: %s\n", strerror(errno));
            exit(1);
        }
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);
        memcpy(ifr.ifr_hwaddr.sa_data, original_mac, 6);
        if (set_macaddr(devname, original_mac) < 0) {
            fprintf(stderr, "Cannot restore the original mac address on device %s\n", devname);
            exit(1);
        } else {
            fprintf(stderr, "Restored original mac address on device %s\n", devname);
            close(sock);
        }
    }
}

static void sighandler(int signum)
{
    (void)signum;
    restore_mac();
    exit(0);
}


struct __attribute__((packed)) udp_hdr {
    uint16_t sport, dport, len, sum;
};

struct __attribute__((packed)) dhcp_msg {
    struct ethhdr eth;
    struct iphdr ip;
    struct udp_hdr udp;
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t magic;
    uint8_t options[312];
};

struct __attribute__((packed)) dhcp_option {
    uint8_t code;
    uint8_t len;
    uint8_t data[0];
};

/* For Checksums */
union transport_pseudo_header {
    struct __attribute__((packed)) ph {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } ph;
    uint16_t buf[6];
};

static uint16_t ip_checksum(void *data)
{
    uint16_t *buf = (uint16_t *)data;
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i < 10; i++) {
        sum += ntohs(buf[i]);
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t transport_checksum(union transport_pseudo_header *ph, void *_data)
{
    uint32_t sum = 0;
    uint32_t i = 0;
    uint16_t *ptr = (uint16_t *)ph->buf;
    uint16_t *data = (uint16_t *)_data;
    uint8_t *data8 = (uint8_t *)_data;
    uint16_t len = ntohs(ph->ph.len);
    for (i = 0; i < 6; i++) {
        sum += htons(ptr[i]);
    }
    for (i = 0; i < (len / 2); i++) {
        sum += htons(data[i]);
    }
    if (len & 0x01) {
        uint16_t spare = 0;
        spare |= (data8[len - 1]) << 8;
        sum += spare;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

static void usage(const char *argv0)
{
    fprintf(stderr, "Usage: %s [-m macaddr] [-t timeout] <interface>\n", argv0);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sock;
    int one = 1;
    const int *val = &one;
    struct dhcp_msg dhcp, *offer;
    struct dhcp_option *opt;
    struct ifreq ifr;
    size_t psize;
    union transport_pseudo_header psh;
    int ret;
    struct sockaddr_ll dst_addr;
    uint8_t rxframe[1514];
    uint32_t dhcp_xid;
    int opt_idx = 1;
    long timeout = DEFAULT_TIMEOUT;
    uint8_t macaddr[6] = {0};
    time_t expire;
    memset(&dhcp, 0, sizeof(dhcp));
    memset(&dhcp.options, 0xFF, sizeof(dhcp.options));
    memset(&ifr, 0, sizeof(ifr));
    memset(&dst_addr, 0, sizeof(dst_addr));
    memset(&psh, 0, sizeof(psh));
    getrandom(&dhcp_xid, sizeof(dhcp_xid), 0);
    getrandom(&dhcp.ip.id, sizeof(dhcp.ip.id), 0);

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGQUIT, sighandler);
    signal(SIGHUP, sighandler);
    atexit(restore_mac);

    ifr.ifr_name[0] = '\0';

    if (argc < 2) {
        usage(argv[0]); /* Implies exit() */
    }
    while (opt_idx < argc) {
        if (strcmp(argv[opt_idx], "-t") == 0) {
            if (++opt_idx < argc) {
                errno = 0;
                timeout = strtol(argv[opt_idx], NULL, 10); 
                if (errno) {
                    fprintf(stderr, "Invalid timeout value\n");
                    usage(argv[0]);
                }
            } else {
                fprintf(stderr, "Option -t requires an argument\n");
                usage(argv[0]);
            }
        } else if (strcmp(argv[opt_idx], "-m") == 0) {
            if (++opt_idx < argc) {
                int i;
                char *p;
                for (i =  0; i < 6; i++) {
                    macaddr[i] = strtol(argv[opt_idx] + i * 3, &p, 16);
                    if (i == 5) {
                        if (*p != '\0') {
                            fprintf(stderr, "Invalid MAC address\n");
                            usage(argv[0]);
                        } else break;
                    } 
                    if (p == NULL || *p != ':') {
                        fprintf(stderr, "Invalid MAC address\n");
                        usage(argv[0]);
                    }
                }
                fprintf(stderr, "Setting MAC address to %02x:%02x:%02x:%02x:%02x:%02x\n",
                        macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
                custom_mac = 1;
            } else {
                fprintf(stderr, "Option -m requires an argument\n");
                usage(argv[0]);
            }
        } else if (opt_idx == argc - 1) {
            strncpy(ifr.ifr_name, argv[opt_idx], IFNAMSIZ - 1);
            strncpy(devname, argv[opt_idx], IFNAMSIZ - 1);
            break;
        } else {
            fprintf(stderr, "Invalid argument: %s\n", argv[opt_idx]);
            usage(argv[0]);
        }
        opt_idx++;
    }
    if (strlen(ifr.ifr_name) == 0) {
        usage(argv[0]);
    }

    sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        fprintf(stderr,"socket() error: %s\n", strerror(errno));
        exit(1);
    }
    /* Retrieve the interface index */
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr,
                "ioctl() error: Cannot get the interface index for %s:%s\n", devname,
                strerror(errno));
        exit(1);
    }
    dst_addr.sll_family = AF_PACKET;
    dst_addr.sll_protocol = htons(ETH_P_IP);
    dst_addr.sll_ifindex = ifr.ifr_ifindex;
    dst_addr.sll_halen = 6;

    /* Retrieve the mac address */
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr,
                "ioctl() error: Cannot get the mac address for %s:%s\n", devname,
                strerror(errno));
        exit(1);
    }
    if (custom_mac) {
        /* Temporarily changing the MAC address of the interface */
        memcpy(original_mac, ifr.ifr_hwaddr.sa_data, 6);
        if (set_macaddr(devname, macaddr) < 0) {
            fprintf(stderr, "Cannot set the MAC address on device %s:%s\n", devname,
                    strerror(errno));
            custom_mac = 0;
            exit(1);
        }
        fprintf(stderr, "Changed MAC address to %02x:%02x:%02x:%02x:%02x:%02x\n",
                macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            fprintf(stderr,
                    "ioctl() error: Cannot get the mac address for %s:%s\n", devname,
                    strerror(errno));
            exit(1);
        }
        sleep(1);
    }
    memcpy(dst_addr.sll_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, val, sizeof(one)) < 0) {
        fprintf(stderr,"setsockopt(SO_BROADCAST) error: %s\n",strerror(errno));
        exit(1);
    }

    dhcp.ip.ihl = 5;
    dhcp.ip.version = 4;
    dhcp.ip.tos = 0;

    dhcp.udp.sport = htons(DHCP_CLIENT_PORT);
    dhcp.udp.dport = htons(DHCP_SERVER_PORT);
    /* 8 bytes UDP header +
     * 240 bytes DHCP message +
     * 3 bytes DHCP option 53 +
     * 5 bytes DHCP option 55 +
     * 1 byte DHCP option 255
     * */
    psize = 8 + 240 + 3 + 5 + 1;
    dhcp.udp.len = htons(psize);
    dhcp.udp.sum = 0;
    dhcp.ip.tot_len = htons(sizeof(struct iphdr) + psize);
    dhcp.ip.frag_off = 0;
    dhcp.ip.ttl = 32;
    dhcp.ip.protocol = IPPROTO_UDP;
    dhcp.ip.check = 0;
    dhcp.ip.saddr = htonl(INADDR_ANY);
    dhcp.ip.daddr = htonl(INADDR_BROADCAST);
    dhcp.op = 1; /* BOOTREQUEST */
    dhcp.htype = 1; /* Ethernet */
    dhcp.hlen = 6; /* Ethernet */
    dhcp.hops = 0;
    dhcp.xid = htonl(dhcp_xid);
    dhcp.secs = htons(0);
    dhcp.flags = htons(0);
    memcpy(dhcp.chaddr, ifr.ifr_hwaddr.sa_data, 6);
    dhcp.magic = htonl(0x63825363); /* DHCP magic cookie */
    opt = (struct dhcp_option *)dhcp.options;
    opt->code = 53; /* DHCP Message Type */
    opt->len = 1;
    opt->data[0] = 1; /* DHCPDISCOVER */
    opt = (struct dhcp_option *)(opt->data + 1);
    opt->code = 55; /* Parameter Request List */
    opt->len = 3;
    opt->data[0] = 1; /* Subnet Mask */
    opt->data[1] = 3; /* Router */
    opt->data[2] = 6; /* Domain Name Server */
    opt = (struct dhcp_option *)(opt->data + 3);
    opt->code = 255; /* End */
    /* Pseudo header for UDP checksum */
    psh.ph.dst = 0xFFFFFFFF;
    psh.ph.proto = IPPROTO_UDP;
    psh.ph.len = htons(psize);
    dhcp.udp.sum = 0;
    dhcp.udp.sum = htons(transport_checksum(&psh, &dhcp.udp.sport));
    /* Calculate IP checksum */
    dhcp.ip.check = htons(ip_checksum(&dhcp.ip));
    /* Add eth header */
    memcpy(dhcp.eth.h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    memset(dhcp.eth.h_dest, 0xff, ETH_ALEN);
    dhcp.eth.h_proto = htons(ETH_P_IP);
    ret = sendto(sock, &dhcp, psize + sizeof(struct ethhdr) + sizeof(struct iphdr), 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
    if (ret < 0) {
        fprintf(stderr,"send error: %s\n",strerror(errno));
    }
    expire = time(NULL) + timeout;
    while (expire > time(NULL)) {
        struct in_addr yip = {0},
                       sid = {0},
                       netmask = {0},
                       router = {0},
                       dns = {0};

        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        pfd.revents = 0;
        ret = poll(&pfd, 1, 1000);
        if (ret == -1) {
            fprintf(stderr,"socket error: %s\n",strerror(errno));
            break;
        }
        if (ret == 0) 
            continue;
        ret = recv(sock, rxframe, sizeof(rxframe), MSG_TRUNC);
        if (ret == -1) {
            fprintf(stderr,"recv error: %s\n",strerror(errno));
            break;
        }
        offer = (struct dhcp_msg *)rxframe;
        /* Filters */
        if (offer->eth.h_proto != htons(ETH_P_IP)) continue;
        if (memcmp(offer->chaddr, dhcp.chaddr, 6) != 0) continue;
        if (offer->ip.protocol != IPPROTO_UDP) continue;
        if (ntohs(offer->udp.dport) != DHCP_CLIENT_PORT) continue;
        if (ntohs(offer->udp.sport) != DHCP_SERVER_PORT) continue;
        if (ntohl(offer->xid) != dhcp_xid) continue;
        /* Parse the options */
        opt = (struct dhcp_option *)offer->options;
        while (opt->code != 255) {
            if (opt->code == 1) {
                memcpy(&netmask, opt->data, 4);
            } else if (opt->code == 3) {
                memcpy(&router, opt->data, 4);
            } else if (opt->code == 6) {
                memcpy(&dns, opt->data, 4);
            }
            opt = (struct dhcp_option *)((uint8_t *)opt + opt->len + 2);
        }
        memcpy(&yip, &offer->yiaddr, 4);
        memcpy(&sid, &offer->ip.saddr, 4);
        printf("Server: %s\n", inet_ntoa(sid));
        printf("Offered: %s\n", inet_ntoa(yip));
        printf("Netmask: %s\n", inet_ntoa(netmask));
        if (router.s_addr)
            printf("Router: %s\n", inet_ntoa(router));
        if (dns.s_addr)
            printf("DNS: %s\n", inet_ntoa(dns));
        close(sock);
        ret = 0;
        goto out;
    }
    fprintf(stderr, "No DHCP servers found.\n");
    ret = 67;
out:
    close(sock);
    return ret;
}
