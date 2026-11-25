/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for sd-netlink's processing of received messages: message validation, multi-part
 * reassembly and error messages in socket_read_message(), sd_netlink_process() and sd_netlink_read() on the
 * read queue, the per-protocol policy lookup (rtnl, genl including genl_get_policy_set_and_header_size(),
 * nfnl, sock_diag), container parsing, and the typed attribute readers (netlink_message_read_impl(),
 * sd_netlink_message_enter_container() including unions by string and by family, _enter_array(),
 * _read_strv(), ...).
 *
 * The data is received as one datagram from the kernel, through an AF_UNIX socket (see fuzz-netlink.h).
 * With bit 6 of byte 0, the replies are taken the way synchronous callers (sd_netlink_call()) do, with
 * sd_netlink_read() by serial: error replies, NLMSG_DONE, multi-part replies, and a serial that has no
 * reply.
 *
 * Input: byte 0 selects the protocol (bits 0-1), and whether replies are read synchronously (bit 6, see
 * above). The rest is the received netlink data. */

#include <linux/netfilter/nfnetlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "fuzz-netlink.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "netlink-internal.h"
#include "netlink-types.h"
#include "netlink-types-internal.h"
#include "netlink-util.h"
#include "ordered-set.h"
#include "strv.h"
#include "tests.h"
#include "unaligned.h"

#define MAX_DEPTH 24
#define MAX_MESSAGES 256

/* The generic netlink families sd-netlink has policies for */
static const char *const genl_families[] = {
        "batadv", "ethtool", "fou", "l2tp", "macsec", "NLBL_UNLBL", "nl80211", "wireguard",
};

static void walk_container(sd_netlink_message *m, unsigned depth);

static void walk_attribute(sd_netlink_message *m, uint16_t i, const NLAPolicy *policy, unsigned depth) {
        union in_addr_union a;
        struct hw_addr_data hw;
        struct ether_addr ether;
        struct ifa_cacheinfo ci;
        _cleanup_free_ char *s = NULL;
        const char *str;
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t u8, buf[64];
        size_t size;
        void *data;

        switch (policy_get_type(policy)) {
        case NETLINK_TYPE_U8:
                (void) sd_netlink_message_read_u8(m, i, &u8);
                break;
        case NETLINK_TYPE_U16:
                (void) sd_netlink_message_read_u16(m, i, &u16);
                break;
        case NETLINK_TYPE_U32:
                (void) sd_netlink_message_read_u32(m, i, &u32);
                break;
        case NETLINK_TYPE_U64:
                (void) sd_netlink_message_read_u64(m, i, &u64);
                break;
        case NETLINK_TYPE_STRING:
                (void) sd_netlink_message_read_string(m, i, &str);
                (void) sd_netlink_message_read_string_strdup(m, i, &s);
                break;
        case NETLINK_TYPE_FLAG:
                (void) sd_netlink_message_has_flag(m, i);
                break;
        case NETLINK_TYPE_IN_ADDR:
                (void) netlink_message_read_in_addr_union(m, i, AF_INET, &a);
                (void) netlink_message_read_in_addr_union(m, i, AF_INET6, &a);
                break;
        case NETLINK_TYPE_ETHER_ADDR:
                (void) sd_netlink_message_read_ether_addr(m, i, &ether);
                (void) netlink_message_read_hw_addr(m, i, &hw);
                break;
        case NETLINK_TYPE_CACHE_INFO:
                (void) sd_netlink_message_read_cache_info(m, i, &ci);
                break;
        case NETLINK_TYPE_NESTED:
        case NETLINK_TYPE_NESTED_UNION_BY_STRING:
        case NETLINK_TYPE_NESTED_UNION_BY_FAMILY:
                if (depth >= MAX_DEPTH)
                        break;

                /* Some attributes are declared nested without a policy for their contents, callers never
                 * enter those (sd_netlink_message_enter_container() asserts on them). */
                if (!policy->policy_set)
                        break;

                if (sd_netlink_message_enter_container(m, i) >= 0) {
                        uint16_t max = 0;
                        const NLAPolicySet *ps = m->containers[m->n_containers].policy_set;

                        walk_container(m, depth + 1);
                        (void) sd_netlink_message_get_max_attribute(m, &max);
                        (void) sd_netlink_message_exit_container(m);

                        /* Lists of strings, like IFLA_PROP_LIST. */
                        if (policy_get_type(policy) == NETLINK_TYPE_NESTED)
                                for (uint16_t j = 0; j <= max; j++) {
                                        const NLAPolicy *p = policy_set_get_policy(ps, j);
                                        _cleanup_strv_free_ char **l = NULL;

                                        if (!p || policy_get_type(p) != NETLINK_TYPE_STRING)
                                                continue;

                                        (void) sd_netlink_message_read_strv(m, i, j, &l);
                                }
                }

                /* Arrays of nested attributes using the same policy. */
                if (sd_netlink_message_enter_array(m, i) >= 0) {
                        walk_container(m, depth + 1);
                        (void) sd_netlink_message_exit_container(m);
                }
                break;
        default:
                size = policy_get_size(policy);
                if (size > 0 && size <= sizeof(buf))
                        (void) sd_netlink_message_read(m, i, size, buf);
                if (sd_netlink_message_read_data(m, i, &size, &data) >= 0)
                        free(data);
        }
}

static void walk_container(sd_netlink_message *m, unsigned depth) {
        const NLAPolicySet *ps;
        uint16_t max;

        if (sd_netlink_message_get_max_attribute(m, &max) < 0)
                return;

        ps = m->containers[m->n_containers].policy_set;

        for (uint32_t i = 0; i <= max; i++) {
                const NLAPolicy *policy = policy_set_get_policy(ps, i);

                if (policy)
                        walk_attribute(m, i, policy, depth);
        }
}

static void walk_message(sd_netlink *nl, sd_netlink_message *m) {
        for (; m; m = sd_netlink_message_next(m)) {
                uint16_t type;
                int family;

                (void) sd_netlink_message_get_type(m, &type);
                (void) sd_netlink_message_is_broadcast(m);
                if (sd_netlink_message_is_error(m))
                        (void) sd_netlink_message_get_errno(m);

                if (nl->protocol == NETLINK_ROUTE)
                        (void) sd_rtnl_message_get_family(m, &family);
                if (nl->protocol == NETLINK_GENERIC && m->protocol == NETLINK_GENERIC) {
                        const char *name;
                        uint8_t cmd;

                        (void) sd_genl_message_get_family_name(nl, m, &name);
                        (void) sd_genl_message_get_command(nl, m, &cmd);
                }

                walk_container(m, 0);

                /* Parse again from scratch. */
                if (sd_netlink_message_rewind(m, nl) >= 0)
                        walk_container(m, 0);
        }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static const int protocols[] = { NETLINK_ROUTE, NETLINK_GENERIC, NETLINK_NETFILTER, NETLINK_SOCK_DIAG };
        _cleanup_(sd_netlink_unrefp) sd_netlink *nl = NULL;
        _cleanup_close_ int fd = -EBADF;
        uint8_t flags;

        /* The kernel never sends empty datagrams, and sd-netlink would leave them queued */
        if (outside_size_range(size, 2, 128 * 1024))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        flags = data[0];
        data++;
        size--;

        nl = fuzz_netlink_new(protocols[flags & 3], &fd);

        if (nl->protocol == NETLINK_GENERIC)
                for (size_t i = 0; i < ELEMENTSOF(genl_families); i++)
                        fuzz_genl_add_family(nl, genl_families[i], 0x11 + i);

        if (send(fd, data, size, MSG_DONTWAIT) < 0)
                return 0;

        if (FLAGS_SET(flags, 1 << 6)) {
                uint32_t serial;

                /* As sd_netlink_call() does after sending its request: wait for the reply to its serial. The
                 * replies sent are all there is, hence no time to wait. Start with the serial of the first
                 * message, and then go on with the first one in the read queue. */
                serial = size >= sizeof(struct nlmsghdr) ?
                        unaligned_read_ne32(data + offsetof(struct nlmsghdr, nlmsg_seq)) : 0;

                for (unsigned n = 0; n < MAX_MESSAGES && serial != 0; n++) {
                        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *reply = NULL;
                        sd_netlink_message *first;

                        /* walk_message() walks all parts of a multi-part reply */
                        if (sd_netlink_read(nl, serial, /* timeout= */ 1, &reply) > 0)
                                walk_message(nl, reply);

                        first = ordered_set_first(nl->rqueue);
                        if (!first)
                                break;
                        serial = first->hdr->nlmsg_seq;
                        if (!hashmap_contains(nl->rqueue_by_serial, UINT32_TO_PTR(serial)))
                                break;
                }

                (void) sd_netlink_read(nl, UINT32_MAX, /* timeout= */ 1, /* ret= */ NULL);
        }

        for (unsigned n = 0; n < MAX_MESSAGES; n++) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;

                if (sd_netlink_process(nl, &m) <= 0)
                        break;

                walk_message(nl, m);
        }

        return 0;
}
