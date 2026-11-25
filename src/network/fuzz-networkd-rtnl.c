/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for networkd's processing of kernel netlink notifications: manager_rtnl_process_link(),
 * _address(), _route() (with route_nexthops_read_netlink_message()), _rule(), _nexthop(), _neighbor(),
 * _qdisc() and _tclass(), and of nl80211 notifications: manager_genl_process_nl80211_config(), _mlme()
 * (SSID/BSSID of the access point) and _wiphy().
 *
 * networkd runs in test mode with one managed link, fuzz0 (ifindex 2), whose .network file is built from the
 * option bits. Each record of netlink data from the input is received as one datagram from the kernel,
 * through AF_UNIX sockets (see src/fuzz/fuzz-netlink.h), and every message goes to the handler networkd
 * registers for its type in manager_connect_rtnl() and manager_connect_genl(). Nothing reaches the kernel:
 * networkd's requests are only queued, or fail to be sent.
 *
 * Input: 2 bytes of option bits, then records of [selector] [length:2 LE] [netlink data]. Selector bit 0:
 * genl (nl80211) instead of rtnl. The 16 option bits add sections to the .network file (bits 0-11, see
 * option_lines[]), make networkd leave foreign routes, rules and nexthops alone (bits 12-14), and process
 * the data as during the enumeration at startup (bit 15). */

#include <fcntl.h>
#include <linux/if_arp.h>
#include <linux/nexthop.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>

#include "sd-event.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fuzz.h"
#include "fuzz-netlink.h"
#include "hashmap.h"
#include "networkd-address.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-wifi.h"
#include "path-util.h"
#include "qdisc.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tclass.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unaligned.h"

#define NL80211_ID 0x1c
#define MAX_RECORDS 32
#define MAX_PROCESS 256

static const struct ether_addr mac = {{ 0x02, 0x00, 0x5e, 0x10, 0x20, 0x30 }};

static const char *const option_lines[12] = {
        "[Address]\nAddress=192.168.1.10/24\n[Address]\nAddress=2001:db8::10/64\nPreferredLifetime=0\n",
        "[Route]\nGateway=192.168.1.1\n[Route]\nDestination=10.0.0.0/8\nGateway=192.168.1.2\nTable=100\n"
        "[Route]\nDestination=2001:db8:1::/64\nType=unreachable\n",
        "[NextHop]\nId=7\nGateway=192.168.1.1\n[NextHop]\nId=8\nGroup=7\n"
        "[Route]\nNextHop=8\nDestination=172.16.0.0/12\n",
        "[RoutingPolicyRule]\nTo=10.0.0.0/8\nTable=100\nPriority=100\n"
        "[RoutingPolicyRule]\nFrom=2001:db8::/32\nTable=200\n",
        "[Neighbor]\nAddress=192.168.1.1\nLinkLayerAddress=00:11:22:33:44:55\n",
        "[FairQueueingControlledDelay]\nParent=root\nHandle=1\n"
        "[HierarchyTokenBucket]\nParent=2:0\nHandle=2\n"
        "[HierarchyTokenBucketClass]\nParent=2:0\nClassId=2:1\nRate=1M\n",
        "[Network]\nKeepConfiguration=yes\n",
        "[Match]\nSSID=myssid\nWLANInterfaceType=station\n",
        "[Network]\nIPv6AcceptRA=yes\nLinkLocalAddressing=yes\n",
        "[Network]\nIPv4Forwarding=yes\nIPv6Forwarding=yes\nConfigureWithoutCarrier=yes\n",
        "[Network]\nDHCP=yes\n",
        "[Route]\nGateway=_ipv6ra\n"
        "[Route]\nMultiPathRoute=192.168.1.1@fuzz0 10\nMultiPathRoute=192.168.1.2 20\n",
};

static void enforce_ifindex(int *ifindex) {
        if (*ifindex <= 0)
                *ifindex = 1;
}

static void enforce_prefixlen(int family, unsigned char *prefixlen) {
        if (family == AF_INET)
                *prefixlen = MIN(*prefixlen, 32);
        else if (family == AF_INET6)
                *prefixlen = MIN(*prefixlen, 128);
}

/* RTA_OIF and the interface indexes of the RTA_MULTIPATH nexthops of a route. Attributes are identified as
 * sd-netlink does, i.e. without the NLA_F_NESTED and NLA_F_NET_BYTEORDER flags, and values are read in
 * network byte order if the latter is set. */
static void enforce_route_attributes(uint8_t *p, size_t size) {
        for (size_t offset = 0; offset + sizeof(struct rtattr) <= size; ) {
                struct rtattr *a = (struct rtattr*) (p + offset);
                uint16_t type;

                if (a->rta_len < sizeof(struct rtattr) || a->rta_len > size - offset)
                        return;

                type = a->rta_type & NLA_TYPE_MASK;

                if (type == RTA_OIF && a->rta_len >= RTA_LENGTH(sizeof(uint32_t))) {
                        bool be = a->rta_type & NLA_F_NET_BYTEORDER;
                        uint32_t *oif = RTA_DATA(a), v = be ? be32toh(*oif) : *oif;

                        if (v == 0 || v > INT_MAX)
                                *oif = be ? htobe32(1) : 1;
                }

                if (type == RTA_MULTIPATH) {
                        size_t end = offset + a->rta_len;

                        for (size_t o = offset + RTA_LENGTH(0); o + sizeof(struct rtnexthop) <= end; ) {
                                struct rtnexthop *rtnh = (struct rtnexthop*) (p + o);

                                if (rtnh->rtnh_len < sizeof(struct rtnexthop) || rtnh->rtnh_len > end - o)
                                        break;

                                enforce_ifindex(&rtnh->rtnh_ifindex);
                                o += RTNH_ALIGN(rtnh->rtnh_len);
                        }
                }

                offset += RTA_ALIGN(a->rta_len);
        }
}

/* Makes rtnetlink messages from the input honor what the kernel guarantees about the values in them, which
 * networkd relies on (and asserts): interface indexes are > 0 and fit into an int, IPv4/IPv6 prefix lengths
 * are at most 32/128, nexthops have the family AF_UNSPEC, AF_INET or AF_INET6. The structure of the messages
 * is not touched: the walk stops at the first message or attribute that is not well-formed. */
static void enforce_kernel_invariants(void *buf, size_t size) {
        uint8_t *p = buf;

        for (size_t offset = 0; offset + sizeof(struct nlmsghdr) <= size; ) {
                struct nlmsghdr *h = (struct nlmsghdr*) (p + offset);
                size_t payload_size;
                void *payload;

                if (h->nlmsg_len < sizeof(struct nlmsghdr) || h->nlmsg_len > size - offset)
                        return;

                payload = p + offset + NLMSG_HDRLEN;
                payload_size = h->nlmsg_len - MIN((size_t) h->nlmsg_len, (size_t) NLMSG_HDRLEN);

                switch (h->nlmsg_type) {

                case RTM_NEWADDR:
                case RTM_DELADDR:
                        if (payload_size >= sizeof(struct ifaddrmsg)) {
                                struct ifaddrmsg *ifa = payload;

                                enforce_prefixlen(ifa->ifa_family, &ifa->ifa_prefixlen);
                                if (ifa->ifa_index == 0 || ifa->ifa_index > INT_MAX)
                                        ifa->ifa_index = 1;
                        }
                        break;

                case RTM_NEWROUTE:
                case RTM_DELROUTE:
                        if (payload_size >= sizeof(struct rtmsg)) {
                                struct rtmsg *rtm = payload;
                                size_t hdr = MIN(payload_size, NLMSG_ALIGN(sizeof(struct rtmsg)));

                                enforce_prefixlen(rtm->rtm_family, &rtm->rtm_dst_len);
                                enforce_prefixlen(rtm->rtm_family, &rtm->rtm_src_len);
                                enforce_route_attributes((uint8_t*) payload + hdr, payload_size - hdr);
                        }
                        break;

                case RTM_NEWNEXTHOP:
                case RTM_DELNEXTHOP:
                        if (payload_size >= sizeof(struct nhmsg)) {
                                struct nhmsg *nhm = payload;

                                if (!IN_SET(nhm->nh_family, AF_UNSPEC, AF_INET, AF_INET6))
                                        nhm->nh_family = AF_UNSPEC;
                        }
                        break;
                }

                offset += NLMSG_ALIGN(h->nlmsg_len);
        }
}

/* As registered by manager_connect_rtnl() */
static const struct {
        uint16_t type;
        int (*handler)(sd_netlink *, sd_netlink_message *, Manager *);
} rtnl_handlers[] = {
        { RTM_NEWLINK,    manager_rtnl_process_link     },
        { RTM_DELLINK,    manager_rtnl_process_link     },
        { RTM_NEWQDISC,   manager_rtnl_process_qdisc    },
        { RTM_DELQDISC,   manager_rtnl_process_qdisc    },
        { RTM_NEWTCLASS,  manager_rtnl_process_tclass   },
        { RTM_DELTCLASS,  manager_rtnl_process_tclass   },
        { RTM_NEWADDR,    manager_rtnl_process_address  },
        { RTM_DELADDR,    manager_rtnl_process_address  },
        { RTM_NEWNEIGH,   manager_rtnl_process_neighbor },
        { RTM_DELNEIGH,   manager_rtnl_process_neighbor },
        { RTM_NEWROUTE,   manager_rtnl_process_route    },
        { RTM_DELROUTE,   manager_rtnl_process_route    },
        { RTM_NEWRULE,    manager_rtnl_process_rule     },
        { RTM_DELRULE,    manager_rtnl_process_rule     },
        { RTM_NEWNEXTHOP, manager_rtnl_process_nexthop  },
        { RTM_DELNEXTHOP, manager_rtnl_process_nexthop  },
};

static void handle_rtnl(Manager *m, sd_netlink_message *message) {
        uint16_t type;

        if (sd_netlink_message_get_type(message, &type) < 0)
                return;

        FOREACH_ELEMENT(h, rtnl_handlers)
                if (h->type == type) {
                        (void) h->handler(m->rtnl, message, m);
                        return;
                }
}

/* manager_connect_genl() subscribes to the nl80211 multicast groups "config" and "mlme". The station,
 * connection and AP events that manager_genl_process_nl80211_mlme() handles come on "mlme". */
static void handle_genl(Manager *m, sd_netlink_message *message) {
        uint8_t cmd;

        if (sd_genl_message_get_command(m->genl, message, &cmd) >= 0 &&
            IN_SET(cmd,
                   NL80211_CMD_NEW_STATION, NL80211_CMD_DEL_STATION, NL80211_CMD_CONNECT,
                   NL80211_CMD_DISCONNECT, NL80211_CMD_START_AP, NL80211_CMD_STOP_AP,
                   NL80211_CMD_AUTHENTICATE, NL80211_CMD_ASSOCIATE, NL80211_CMD_DEAUTHENTICATE,
                   NL80211_CMD_DISASSOCIATE, NL80211_CMD_ROAM))
                (void) manager_genl_process_nl80211_mlme(m->genl, message, m);
        else
                (void) manager_genl_process_nl80211_config(m->genl, message, m);
}

static void process(Manager *m, bool genl) {
        for (unsigned n = 0; n < MAX_PROCESS; n++) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;

                if (sd_netlink_process(genl ? m->genl : m->rtnl, &message) <= 0)
                        break;

                /* All parts of a multi-part message, like the replies to manager_enumerate()'s dumps */
                for (sd_netlink_message *i = message; i; i = sd_netlink_message_next(i))
                        if (genl)
                                handle_genl(m, i);
                        else
                                handle_rtnl(m, i);
        }
}

static char *network_dir = NULL;

static void network_dir_cleanup(void) {
        network_dir = rm_rf_physical_and_free(network_dir);
}

static Network* load_network(Manager *m, const char *conf) {
        _cleanup_free_ char *path = NULL;

        if (!network_dir) {
                ASSERT_OK(mkdtemp_malloc("/tmp/fuzz-networkd-rtnl-XXXXXX", &network_dir));
                ASSERT_EQ(atexit(network_dir_cleanup), 0);
        }

        path = ASSERT_NOT_NULL(path_join(network_dir, "fuzz.network"));
        ASSERT_OK(write_string_file(path, conf, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE));

        if (network_load_one(m, &m->networks, path) < 0)
                return NULL;

        return ordered_hashmap_get(m->networks, "fuzz");
}

/* The link fuzz0, as networkd learns about it from the kernel, with carrier, the EUI-64 IPv6 link-local
 * address, and the given .network file, in the state link_configure() would put it in (which networkd
 * doesn't run in test mode). */
static void add_link(Manager *m, const char *conf) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        Network *network;
        Link *link;

        ASSERT_OK(sd_rtnl_message_new_link(m->rtnl, &message, RTM_NEWLINK, 2));
        ASSERT_OK(sd_rtnl_message_link_set_type(message, ARPHRD_ETHER));
        ASSERT_OK(sd_rtnl_message_link_set_flags(message,
                                                 IFF_UP|IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST|IFF_LOWER_UP,
                                                 UINT32_MAX));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "fuzz0"));
        ASSERT_OK(sd_netlink_message_append_ether_addr(message, IFLA_ADDRESS, &mac));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFLA_MTU, 1500));
        ASSERT_OK(sd_netlink_message_append_u8(message, IFLA_OPERSTATE, IF_OPER_UP));
        ASSERT_OK(sd_netlink_message_rewind(message, m->rtnl));
        ASSERT_OK(manager_rtnl_process_link(m->rtnl, message, m));
        ASSERT_OK(link_get_by_index(m, 2, &link));

        network = load_network(m, conf);
        if (network) {
                link->network = network_ref(network);
                link->activated = true;
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        const uint8_t *a = mac.ether_addr_octet;
        link->ipv6ll_address = (struct in6_addr) {
                .s6_addr = { 0xfe, 0x80, [8] = a[0] ^ 0x02, a[1], a[2], 0xff, 0xfe, a[3], a[4], a[5] },
        };
}

static Manager* manager_stop_and_free(Manager *m) {
        /* As on exit: in MANAGER_STOPPED, freeing the links doesn't try to mark them dirty */
        if (m)
                m->state = MANAGER_STOPPED;
        return manager_free(m);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_stop_and_free);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_stop_and_freep) Manager *m = NULL;
        _cleanup_close_ int rtnl_fd = -EBADF, genl_fd = -EBADF;
        _cleanup_free_ char *conf = NULL;
        uint16_t options;

        if (outside_size_range(size, 2, 128 * 1024))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        /* Fixed DUIDs, no machine ID */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", /* overwrite= */ true));

        options = unaligned_read_le16(data);
        data += 2;
        size -= 2;

        ASSERT_OK(manager_new(&m, /* test_mode= */ true));
        ASSERT_OK(sd_event_new(&m->event));
        m->rtnl = fuzz_netlink_new(NETLINK_ROUTE, &rtnl_fd);
        m->genl = fuzz_netlink_new(NETLINK_GENERIC, &genl_fd);
        fuzz_genl_add_family(m->genl, NL80211_GENL_NAME, NL80211_ID);

        /* ethtool requests fail on /dev/null instead of opening a socket to query a real device */
        m->ethtool_fd = ASSERT_OK_ERRNO(open("/dev/null", O_RDONLY|O_CLOEXEC));

        m->manage_foreign_routes = !FLAGS_SET(options, 1U << 12);
        m->manage_foreign_rules = !FLAGS_SET(options, 1U << 13);
        m->manage_foreign_nexthops = !FLAGS_SET(options, 1U << 14);
        m->enumerating = FLAGS_SET(options, 1U << 15);

        conf = ASSERT_NOT_NULL(strdup("[Match]\nName=fuzz0\n"
                                      "[Network]\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n"));
        for (unsigned i = 0; i < ELEMENTSOF(option_lines); i++)
                if (FLAGS_SET(options, 1U << i))
                        ASSERT_NOT_NULL(strextend(&conf, option_lines[i]));
        add_link(m, conf);

        for (unsigned n = 0; n < MAX_RECORDS && size >= 3; n++) {
                bool genl = FLAGS_SET(data[0], 1 << 0);
                size_t len = MIN((size_t) unaligned_read_le16(data + 1), size - 3);
                const uint8_t *p = data + 3;
                _cleanup_free_ void *buf = NULL;

                data += 3 + len;
                size -= 3 + len;

                /* The kernel never sends empty datagrams, and sd-netlink would leave them queued */
                if (len == 0)
                        continue;

                /* A copy, as the rtnl messages are adjusted */
                buf = ASSERT_NOT_NULL(memdup(p, len));
                if (!genl)
                        enforce_kernel_invariants(buf, len);

                if (send(genl ? genl_fd : rtnl_fd, buf, len, MSG_DONTWAIT) < 0)
                        continue;

                process(m, genl);
        }

        return 0;
}
