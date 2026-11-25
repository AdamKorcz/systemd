/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "log.h"
#include "log-assert-critical.h"
#include "parse-util.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-scope.h"
#include "resolved-fuzz-util.h"
#include "resolved-manager.h"
#include "socket-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"

/* See fuzz_resolved_set_sender() */
static struct {
        int fd;
        union sockaddr_union sender;
        union in_addr_union destination;
        int ifindex;
        int ttl;
} received = {
        .fd = -EBADF,
};

void fuzz_resolved_setup(void) {
        static bool done = false;

        if (done)
                return;
        done = true;

        /* Never look for resolve hooks in /run/systemd/resolve.hook/ (they would be connected to), and do
         * synthesize RRs for our own hostname, which is the made-up one the Manager is given below. */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_RESOLVED_HOOK", "0", /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_RESOLVED_SYNTHESIZE_HOSTNAME", "1", /* overwrite= */ true));

        if (!getenv("SYSTEMD_LOG_LEVEL")) {
                log_set_max_level(LOG_CRIT);
                log_set_assert_return_is_critical(true);
        }
        log_setup();
}

int fuzz_resolved_manager_new(Manager **ret) {
        _cleanup_(fuzz_resolved_manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        /* Like manager_new() and manager_set_defaults(), but without reading any configuration. */
        *m = (Manager) {
                .llmnr_ipv4_udp_fd = -EBADF,
                .llmnr_ipv6_udp_fd = -EBADF,
                .llmnr_ipv4_tcp_fd = -EBADF,
                .llmnr_ipv6_tcp_fd = -EBADF,
                .mdns_ipv4_fd = -EBADF,
                .mdns_ipv6_fd = -EBADF,
                .hostname_fd = -EBADF,

                .llmnr_support = RESOLVE_SUPPORT_YES,
                .mdns_support = RESOLVE_SUPPORT_YES,
                .dnssec_mode = DNSSEC_NO,
                .dns_over_tls_mode = DNS_OVER_TLS_NO,
                .enable_cache = DNS_CACHE_MODE_YES,
                .dns_stub_listener_mode = DNS_STUB_LISTENER_YES,

                .etc_hosts_last = USEC_INFINITY,
                .static_records_last = USEC_INFINITY,
        };

        for (DnsProtocol p = 0; p < _DNS_PROTOCOL_MAX; p++)
                m->cache_max[p] = DEFAULT_CACHE_MAX;

        m->full_hostname = strdup("fuzzhost");
        m->llmnr_hostname = strdup("fuzzhost");
        m->mdns_hostname = strdup("fuzzhost.local");
        if (!m->full_hostname || !m->llmnr_hostname || !m->mdns_hostname)
                return -ENOMEM;

        r = sd_event_new(&m->event);
        if (r < 0)
                return r;

        r = dns_scope_new(m, &m->unicast_scope, DNS_SCOPE_GLOBAL, /* link= */ NULL, /* delegate= */ NULL,
                          DNS_PROTOCOL_DNS, AF_UNSPEC);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

Manager* fuzz_resolved_manager_free(Manager *m) {
        received.fd = -EBADF;

        /* resolved frees the Manager once the event loop finished, and some code (e.g. the mDNS goodbye
         * announcements of link_free()) behaves differently then, hence do the same. */
        if (m && m->event) {
                (void) sd_event_exit(m->event, 0);

                for (unsigned i = 0; i < 64 && sd_event_get_state(m->event) != SD_EVENT_FINISHED; i++)
                        if (sd_event_run(m->event, 0) < 0)
                                break;
        }

        return manager_free(m);
}

void fuzz_resolved_set_sender(
                int fd,
                const union sockaddr_union *sender,
                const union in_addr_union *destination,
                int ifindex,
                int ttl) {

        assert(fd >= 0);
        assert(sender);
        assert(IN_SET(sender->sa.sa_family, AF_INET, AF_INET6));
        /* recvmsg_safe() drops datagrams from port 0 */
        assert((sender->sa.sa_family == AF_INET ? sender->in.sin_port : sender->in6.sin6_port) != 0);
        assert(destination);

        received.fd = fd;
        received.sender = *sender;
        received.destination = *destination;
        received.ifindex = ifindex;
        received.ttl = ttl;
}

/* Wrapped functions (-Wl,--wrap=, see resolve_network_fuzz_template) */

/* NOLINTNEXTLINE(misc-use-internal-linkage) */
_public_ ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags);
/* glibc redirects sendmsg() to __sendmsg64() on 32-bit systems with 64-bit time_t. */
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
_public_ ssize_t __wrap___sendmsg64(int fd, const struct msghdr *message, int flags);
int __wrap_manager_write_resolv_conf(Manager *m);
int __wrap_local_addresses(sd_netlink *context, int ifindex, int af, struct local_address **ret);
int __wrap_local_gateways(sd_netlink *context, int ifindex, int af, struct local_address **ret);
int __wrap_local_outbounds(sd_netlink *context, int ifindex, int af, struct local_address **ret);
int __wrap_in_addr_port_ifindex_name_from_string_auto(
                const char *s,
                int *ret_family,
                union in_addr_union *ret_address,
                uint16_t *ret_port,
                int *ret_ifindex,
                char **ret_server_name);
int __real_in_addr_port_ifindex_name_from_string_auto(
                const char *s,
                int *ret_family,
                union in_addr_union *ret_address,
                uint16_t *ret_port,
                int *ret_ifindex,
                char **ret_server_name);
ssize_t __wrap_recvmsg_safe_full(int fd, struct msghdr *msg, int flags, RecvMsgSafeFlags safe_flags);
ssize_t __real_recvmsg_safe_full(int fd, struct msghdr *msg, int flags, RecvMsgSafeFlags safe_flags);

/* What resolved sends is dropped, as if it had been sent */
ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags) {
        size_t n = 0;

        assert(message);

        for (size_t i = 0; i < (size_t) message->msg_iovlen; i++)
                n += message->msg_iov[i].iov_len;

        return n;
}

ssize_t __wrap___sendmsg64(int fd, const struct msghdr *message, int flags) {
        return __wrap_sendmsg(fd, message, flags);
}

/* The datagrams received on the fd given to fuzz_resolved_set_sender() come from the sender given there,
 * with the control messages resolved enables on its sockets: IP_PKTINFO and IP_RECVTTL, or
 * IPV6_RECVPKTINFO and IPV6_RECVHOPLIMIT. */
ssize_t __wrap_recvmsg_safe_full(int fd, struct msghdr *msg, int flags, RecvMsgSafeFlags safe_flags) {
        bool ipv6 = received.sender.sa.sa_family == AF_INET6;
        socklen_t name_size, sender_size = ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        size_t control_size, pktinfo_size = ipv6 ? sizeof(struct in6_pktinfo) : sizeof(struct in_pktinfo);
        struct cmsghdr *cmsg;
        ssize_t n;

        assert(msg);

        if (fd != received.fd)
                return __real_recvmsg_safe_full(fd, msg, flags, safe_flags);

        name_size = msg->msg_namelen;
        control_size = msg->msg_controllen;

        n = __real_recvmsg_safe_full(fd, msg, flags, safe_flags);
        if (n < 0)
                return n;

        assert(msg->msg_name && name_size >= sender_size);
        memcpy(msg->msg_name, &received.sender, sender_size);
        msg->msg_namelen = sender_size;

        assert(msg->msg_control && control_size >= CMSG_SPACE(pktinfo_size) + CMSG_SPACE(sizeof(int)));
        msg->msg_controllen = control_size;

        cmsg = CMSG_FIRSTHDR(msg);
        *cmsg = (struct cmsghdr) {
                .cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
                .cmsg_type = ipv6 ? IPV6_PKTINFO : IP_PKTINFO,
                .cmsg_len = CMSG_LEN(pktinfo_size),
        };
        if (ipv6)
                *CMSG_TYPED_DATA(cmsg, struct in6_pktinfo) = (struct in6_pktinfo) {
                        .ipi6_addr = received.destination.in6,
                        .ipi6_ifindex = received.ifindex,
                };
        else
                *CMSG_TYPED_DATA(cmsg, struct in_pktinfo) = (struct in_pktinfo) {
                        .ipi_ifindex = received.ifindex,
                        .ipi_addr = received.destination.in,
                };

        cmsg = CMSG_NXTHDR(msg, cmsg);
        *cmsg = (struct cmsghdr) {
                .cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
                .cmsg_type = ipv6 ? IPV6_HOPLIMIT : IP_TTL,
                .cmsg_len = CMSG_LEN(sizeof(int)),
        };
        *CMSG_TYPED_DATA(cmsg, int) = received.ttl;

        msg->msg_controllen = CMSG_SPACE(pktinfo_size) + CMSG_SPACE(sizeof(int));

        return n;
}

int __wrap_manager_write_resolv_conf(Manager *m) {
        assert(m);

        /* Would write /run/systemd/resolve/resolv.conf and stub-resolv.conf */
        return 0;
}

/* The local addresses and gateways resolved synthesizes records from, without asking the kernel: no local
 * addresses, and no gateways either, except one when asked for any family (AF_UNSPEC). That's because
 * synthesize_gateway_rr() asserts that a lookup for _gateway or _outbound of type ANY finds one, a known
 * reachable assertion. */
int __wrap_local_addresses(sd_netlink *context, int ifindex, int af, struct local_address **ret) {
        if (ret)
                *ret = NULL;
        return 0;
}

static int fake_gateways(int ifindex, int af, struct local_address **ret) {
        _cleanup_free_ struct local_address *list = NULL;
        union in_addr_union a = { .in.s_addr = htobe32(UINT32_C(0xc0000201)) }; /* 192.0.2.1 */
        size_t n = 0;
        int r;

        if (af == AF_UNSPEC && IN_SET(ifindex, 0, 2)) {
                r = add_local_address(&list, &n, 2, RT_SCOPE_UNIVERSE, AF_INET, &a);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = TAKE_PTR(list);
        return (int) n;
}

int __wrap_local_gateways(sd_netlink *context, int ifindex, int af, struct local_address **ret) {
        return fake_gateways(ifindex, af, ret);
}

int __wrap_local_outbounds(sd_netlink *context, int ifindex, int af, struct local_address **ret) {
        return fake_gateways(ifindex, af, ret);
}

/* Interface names in addresses ("192.0.2.1%eth0") are resolved via netlink. Resolve the names of our
 * simulated links ("fuzz2") ourselves instead, and pass everything else on with the interface removed. */
int __wrap_in_addr_port_ifindex_name_from_string_auto(
                const char *s,
                int *ret_family,
                union in_addr_union *ret_address,
                uint16_t *ret_port,
                int *ret_ifindex,
                char **ret_server_name) {

        _cleanup_free_ char *copy = NULL, *ifname = NULL;
        const char *pct, *hash;
        int ifindex, r;

        assert(s);

        /* The server name ("#…") is split off first, see the real function */
        pct = strchr(s, '%');
        hash = strchr(s, '#');
        if (!pct || (hash && hash < pct))
                return __real_in_addr_port_ifindex_name_from_string_auto(
                                s, ret_family, ret_address, ret_port, ret_ifindex, ret_server_name);

        if (!ret_ifindex)
                return -EINVAL;

        hash = strchr(pct, '#');
        ifname = hash ? strndup(pct + 1, hash - pct - 1) : strdup(pct + 1);
        copy = strjoin(strndupa_safe(s, pct - s), strempty(hash));
        if (!ifname || !copy)
                return -ENOMEM;

        if (isempty(ifname) || !ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC))
                return -EINVAL;

        ifindex = parse_ifindex(ifname);
        if (ifindex < 0) {
                const char *e = startswith(ifname, "fuzz");

                if (!e || safe_atoi(e, &ifindex) < 0 || ifindex <= 0)
                        return -ENODEV;
        }

        r = __real_in_addr_port_ifindex_name_from_string_auto(
                        copy, ret_family, ret_address, ret_port, ret_ifindex, ret_server_name);
        if (r < 0)
                return r;

        *ret_ifindex = ifindex;
        return r;
}
