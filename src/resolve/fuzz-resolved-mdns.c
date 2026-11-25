/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the mDNS responder and resolver of systemd-resolved: on_mdns_packet(), i.e. the
 * processing of mDNS queries (mdns_scope_process_query(), known-answer suppression) and replies (caching,
 * goodbye packets, matching pending transactions), the zone of the link with the probing and conflict
 * handling of our own hostname and DNS-SD services (dns_zone_*(), dns_scope_check_conflicts()), and the
 * announcements. mDNS packets come from anyone on the local network.
 *
 * resolved's mDNS sockets (manager_mdns_ipv4_fd(), manager_mdns_ipv6_fd()) are AF_UNIX socketpairs:
 * socket(), bind() and setsockopt() are wrapped for that (see __wrap_socket()). The fuzzer sends each packet
 * to the other end, and resolved's event loop passes it to on_mdns_packet(), from a sender and to a
 * destination that the wrapped recvmsg_safe() reports as resolved's IP sockets would. resolved's LLMNR
 * sockets are AF_UNIX sockets on which nothing is ever received, and what it sends is dropped (see
 * resolved-fuzz-util.h). Time doesn't pass, but timers can be made to elapse.
 *
 * Input: two configuration bytes, optionally DNS-SD services, then up to 64 commands (see the CMD_*
 * enum: an mDNS packet, a query, timers elapsing, address/hostname/link changes, cache flushes).
 *
 * Byte 0: bit 0 MulticastDNS=resolve instead of yes, bit 1 LLMNR too, bit 2 a DNS-SD service follows,
 * bit 3 IPv4 only, bit 4 serve stale, bit 5 let the probing of our own records finish first, bit 6 more
 * DNS-SD services follow (a count byte, then up to 8 services), so that announcing and saying goodbye to
 * the zone takes several packets (mdns_announcement_packetize()), bit 7 unregister all DNS-SD services
 * after the commands, which sends goodbyes for them (dnssd_registered_service_unregister()).
 * Byte 1: the cache mode. */

#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "fd-util.h"
#include "fuzz.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "path-util.h"
#include "resolved-dns-query.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-transaction.h"
#include "resolved-dnssd.h"
#include "resolved-fuzz-util.h"
#include "resolved-link.h"
#include "resolved-llmnr.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

#define COMMANDS_MAX 64U
#define RUN_ITERATIONS 64U

enum {
        CMD_PACKET,
        CMD_QUERY,
        CMD_EXPIRE_TIMERS,
        CMD_ADDRESS,
        CMD_FLUSH_CACHES,
        CMD_HOSTNAME,
        CMD_LINK,
        _CMD_MAX,
};

/* A simple cursor over the fuzzer input. Reads past the end return zeros. */
typedef struct FuzzInput {
        const uint8_t *data;
        size_t size;
} FuzzInput;

static bool fuzz_input_eof(const FuzzInput *in) {
        return in->size == 0;
}

static uint8_t fuzz_input_u8(FuzzInput *in) {
        uint8_t v;

        if (in->size == 0)
                return 0;

        v = in->data[0];
        in->data++;
        in->size--;
        return v;
}

static uint16_t fuzz_input_u16(FuzzInput *in) {
        uint16_t hi = fuzz_input_u8(in);
        return (uint16_t) (hi << 8 | fuzz_input_u8(in));
}

/* Returns up to n bytes, the actual number is stored in *ret_n. */
static const uint8_t* fuzz_input_bytes(FuzzInput *in, size_t n, size_t *ret_n) {
        const uint8_t *p = in->data;

        n = MIN(n, in->size);
        in->data += n;
        in->size -= n;
        *ret_n = n;
        return p;
}

/* Reads a string with an 8-bit length prefix. */
static char* fuzz_input_string(FuzzInput *in) {
        const uint8_t *p;
        size_t n;

        assert(in);

        p = fuzz_input_bytes(in, fuzz_input_u8(in), &n);
        return memdup_suffix0(p, n);
}

/* The AF_INET and AF_INET6 datagram sockets resolved creates, i.e. its mDNS sockets: one end of an AF_UNIX
 * socketpair each. The other end (peer) is where the fuzzer sends the packets resolved receives. resolved
 * closes its end without us knowing, hence the inode tells whether fd still refers to it. */
typedef struct FakeSocket {
        int fd;
        int peer;
        ino_t inode;
} FakeSocket;

static FakeSocket fake_sockets[4] = {
        { .fd = -EBADF, .peer = -EBADF },
        { .fd = -EBADF, .peer = -EBADF },
        { .fd = -EBADF, .peer = -EBADF },
        { .fd = -EBADF, .peer = -EBADF },
};

static void fake_socket_close(FakeSocket *f) {
        f->fd = -EBADF;
        f->peer = safe_close(f->peer);
}

static FakeSocket* fake_socket_find(int fd) {
        struct stat st;

        if (fd < 0 || fstat(fd, &st) < 0)
                return NULL;

        FOREACH_ELEMENT(f, fake_sockets)
                if (f->fd == fd && f->inode == st.st_ino)
                        return f;

        return NULL;
}

/* Closes the peers of the sockets resolved closed */
static void fake_sockets_gc(void) {
        FOREACH_ELEMENT(f, fake_sockets)
                if (f->fd >= 0 && fake_socket_find(f->fd) != f)
                        fake_socket_close(f);
}

static void fake_sockets_reset(void) {
        FOREACH_ELEMENT(f, fake_sockets)
                fake_socket_close(f);
}

/* Wrapped functions (-Wl,--wrap=, see the resolved meson.build) */

/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __wrap_socket(int domain, int type, int protocol);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __real_socket(int domain, int type, int protocol);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __real_bind(int fd, const struct sockaddr *addr, socklen_t len);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __wrap_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __real_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
/* glibc redirects setsockopt() to __setsockopt64() on 32-bit systems with 64-bit time_t. */
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __wrap___setsockopt64(int fd, int level, int optname, const void *optval, socklen_t optlen);

/* An AF_INET or AF_INET6 datagram socket is one end of an AF_UNIX socketpair, see fake_sockets */
int __wrap_socket(int domain, int type, int protocol) {
        FakeSocket *slot = NULL;
        struct stat st;
        int fds[2];

        if (!IN_SET(domain, AF_INET, AF_INET6) || (type & ~(SOCK_CLOEXEC|SOCK_NONBLOCK)) != SOCK_DGRAM)
                return __real_socket(domain, type, protocol);

        fake_sockets_gc();

        FOREACH_ELEMENT(f, fake_sockets)
                if (f->fd < 0) {
                        slot = f;
                        break;
                }
        if (!slot) {
                errno = EMFILE;
                return -1;
        }

        if (socketpair(AF_UNIX, type, 0, fds) < 0)
                return -1;

        if (fstat(fds[0], &st) < 0) {
                safe_close_pair(fds);
                return -1;
        }

        *slot = (FakeSocket) {
                .fd = fds[0],
                .peer = fds[1],
                .inode = st.st_ino,
        };

        return fds[0];
}

/* Binding them and setting their options succeeds, without effect */
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
        if (fake_socket_find(fd))
                return 0;

        return __real_bind(fd, addr, len);
}

int __wrap_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
        if (fake_socket_find(fd))
                return 0;

        return __real_setsockopt(fd, level, optname, optval, optlen);
}

int __wrap___setsockopt64(int fd, int level, int optname, const void *optval, socklen_t optlen) {
        return __wrap_setsockopt(fd, level, optname, optval, optlen);
}

static void setup_multicast_sockets(Manager *m) {
        assert(m);

        FOREACH_ELEMENT(fd, ((int *const[]) {
                                &m->llmnr_ipv4_udp_fd, &m->llmnr_ipv6_udp_fd,
                                &m->llmnr_ipv4_tcp_fd, &m->llmnr_ipv6_tcp_fd }))
                if (**fd < 0)
                        **fd = ASSERT_OK_ERRNO(socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));

        /* What manager_mdns_start() does, on a system with IPv6 */
        ASSERT_OK(manager_mdns_ipv4_fd(m));
        ASSERT_OK(manager_mdns_ipv6_fd(m));
}

static char *tmpdir = NULL;

static void tmpdir_remove(void) {
        tmpdir = rm_rf_physical_and_free(tmpdir);
}

static int link_new_up(Manager *m, int ifindex, Link **ret) {
        _cleanup_(link_freep) Link *l = NULL;
        union in_addr_union a, null = {};
        LinkAddress *la;
        int r;

        assert(m);
        assert(ifindex > 1);
        assert(ifindex < 25);

        if (!tmpdir) {
                ASSERT_OK(mkdtemp_malloc("/tmp/fuzz-resolved-XXXXXX", &tmpdir));
                ASSERT_EQ(atexit(tmpdir_remove), 0);
        }

        r = link_new(m, &l, ifindex);
        if (r < 0)
                return r;

        l->flags = IFF_UP|IFF_LOWER_UP|IFF_RUNNING|IFF_MULTICAST|IFF_BROADCAST;
        l->operstate = IF_OPER_UP;
        l->mtu = 1500;
        if (asprintf(&l->ifname, "fuzz%i", ifindex) < 0)
                return -ENOMEM;

        free(l->state_file);
        l->state_file = path_join(tmpdir, l->ifname);
        if (!l->state_file)
                return -ENOMEM;

        a = (union in_addr_union) { .in.s_addr = htobe32(UINT32_C(0xc0000200) | (uint32_t) (10 * ifindex)) };
        r = link_address_new(l, &la, AF_INET, &a, &null);
        if (r < 0)
                return r;
        la->prefixlen = 24;
        la->scope = RT_SCOPE_UNIVERSE;

        a = (union in_addr_union) { .in6 = { .s6_addr = { 0x20, 0x01, 0x0d, 0xb8, [15] = 10 * ifindex } } };
        r = link_address_new(l, &la, AF_INET6, &a, &null);
        if (r < 0)
                return r;
        la->prefixlen = 64;
        la->scope = RT_SCOPE_UNIVERSE;

        a = (union in_addr_union) { .in6 = { .s6_addr = { 0xfe, 0x80, [15] = 10 * ifindex } } };
        r = link_address_new(l, &la, AF_INET6, &a, &null);
        if (r < 0)
                return r;
        la->prefixlen = 64;
        la->scope = RT_SCOPE_LINK;

        if (ret)
                *ret = l;
        TAKE_PTR(l);
        return 0;
}

static int run_event_loop(Manager *m, unsigned max_iterations) {
        int r;

        assert(m);

        for (unsigned i = 0; i < max_iterations; i++) {
                r = sd_event_run(m->event, 0);
                if (r <= 0)
                        return r;
        }

        return 0;
}

static void expire(sd_event_source *s) {
        if (s)
                (void) sd_event_source_set_time(s, 1);
}

static void expire_timers(Manager *m) {
        DnsTransaction *t;

        assert(m);

        HASHMAP_FOREACH(t, m->dns_transactions)
                expire(t->timeout_event_source);

        LIST_FOREACH(queries, q, m->dns_queries) {
                expire(q->timeout_event_source);

                LIST_FOREACH(candidates_by_query, c, q->candidates)
                        expire(c->timeout_event_source);
        }

        LIST_FOREACH(scopes, s, m->dns_scopes) {
                expire(s->conflict_event_source);
                expire(s->announce_event_source);
                expire(s->mdns_goodbye_event_source);
        }
}

static int read_key(FuzzInput *in, DnsResourceKey **ret) {
        static const uint16_t classes[] = {
                DNS_CLASS_IN,
                DNS_CLASS_ANY,
                3 /* CHAOS */,
                DNS_CLASS_IN | MDNS_RR_CACHE_FLUSH_OR_QU,
        };
        _cleanup_free_ char *name = NULL;
        uint16_t type;
        uint8_t c;

        assert(in);
        assert(ret);

        type = fuzz_input_u16(in);
        c = fuzz_input_u8(in);
        name = fuzz_input_string(in);
        if (!name)
                return -ENOMEM;

        *ret = dns_resource_key_new(c < ELEMENTSOF(classes) ? classes[c] : c, type, name);
        return *ret ? 0 : -ENOMEM;
}

/* A DNS packet: a header with the specified id (in network byte order, like DnsTransaction.id), flags and
 * counts, an optional question section with the specified key (qdcount is then 1 unless counts are given),
 * followed by the raw data. */
static int build_packet(
                uint16_t id,
                uint16_t flags,
                const DnsResourceKey *key,
                const uint16_t counts[3],
                const void *raw,
                size_t raw_size,
                DnsPacket **ret) {

        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        int r;

        assert(ret);

        r = dns_packet_new(&p, DNS_PROTOCOL_MDNS, /* min_alloc_dsize= */ 0, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        DNS_PACKET_HEADER(p)->id = id;
        DNS_PACKET_HEADER(p)->flags = htobe16(flags);

        if (key) {
                r = dns_packet_append_key(p, key, /* flags= */ 0, /* start= */ NULL);
                if (r < 0)
                        return r;

                DNS_PACKET_HEADER(p)->qdcount = htobe16(1);
        }

        if (counts) {
                DNS_PACKET_HEADER(p)->ancount = htobe16(counts[0]);
                DNS_PACKET_HEADER(p)->nscount = htobe16(counts[1]);
                DNS_PACKET_HEADER(p)->arcount = htobe16(counts[2]);
        }

        if (raw_size > 0) {
                r = dns_packet_append_blob(p, raw, MIN(raw_size, DNS_PACKET_SIZE_MAX - p->size),
                                           /* start= */ NULL);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(p);
        return 0;
}

static DnsTransaction* pick_pending_transaction(Manager *m, uint8_t sel) {
        DnsTransaction *candidates[64];
        size_t n = 0;

        /* Walk the lists of the scopes rather than the hashmap of transactions, so that the order doesn't
         * depend on the hash key of the process */
        LIST_FOREACH(scopes, s, m->dns_scopes) {
                if (s->protocol != DNS_PROTOCOL_MDNS)
                        continue;

                LIST_FOREACH(transactions_by_scope, t, s->transactions) {
                        if (n >= ELEMENTSOF(candidates))
                                break;
                        if (t->state != DNS_TRANSACTION_PENDING || !t->sent)
                                continue;

                        candidates[n++] = t;
                }
        }

        return n > 0 ? candidates[sel % n] : NULL;
}

static void link_peer_address(int family, uint8_t sel, union in_addr_union *ret) {
        assert(ret);

        /* 0: another host on the link, 1: our own address on link 2, 2: an off-link address */
        if (family == AF_INET)
                *ret = (union in_addr_union) {
                        .in.s_addr = htobe32(sel == 0 ? UINT32_C(0xc0000263) :   /* 192.0.2.99 */
                                             sel == 1 ? UINT32_C(0xc0000214) :   /* 192.0.2.20 */
                                                        UINT32_C(0xc6336407)),   /* 198.51.100.7 */
                };
        else if (sel == 2)
                *ret = (union in_addr_union) {
                        .in6 = { .s6_addr = { 0x20, 0x01, 0x0d, 0xb8, 0, 1, [15] = 7 } },
                };
        else
                *ret = (union in_addr_union) {
                        .in6 = { .s6_addr = { 0xfe, 0x80, [15] = sel == 0 ? 0x99 : 0x14 } },
                };
}

static void deliver_packet(Manager *m, FuzzInput *in) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        const DnsResourceKey *k = NULL;
        union in_addr_union sender_address, destination;
        union sockaddr_union sender = {};
        uint16_t flags, id, port, counts[3];
        const uint8_t *raw;
        uint8_t sel, mode;
        int family, ifindex, fd;
        FakeSocket *f;
        size_t n;
        int r;

        assert(m);

        sel = fuzz_input_u8(in);
        mode = fuzz_input_u8(in);
        flags = fuzz_input_u16(in);
        id = fuzz_input_u16(in);
        port = fuzz_input_u16(in);
        for (size_t i = 0; i < ELEMENTSOF(counts); i++)
                counts[i] = fuzz_input_u8(in);
        if (FLAGS_SET(mode, 1U << 3) && read_key(in, &key) < 0)
                return;
        raw = fuzz_input_bytes(in, fuzz_input_u16(in), &n);

        /* mode bit 0: a reply to one of the pending transactions, with its ID and key,
         *      bit 1: no question section, bit 2: the input is the complete packet, bit 3: a key follows
         *      in the input, which is used for the question section instead */
        if (FLAGS_SET(mode, 1U << 0)) {
                DnsTransaction *t;

                t = pick_pending_transaction(m, sel);
                if (t) {
                        id = t->id;
                        k = dns_transaction_key(t);
                }
        }
        if (key)
                k = key;
        if (FLAGS_SET(mode, 1U << 1))
                k = NULL;

        if (FLAGS_SET(mode, 1U << 2)) {
                r = build_packet(/* id= */ 0, /* flags= */ 0, /* key= */ NULL, /* counts= */ NULL,
                                 raw, n, &p);
                if (r < 0)
                        return;

                /* Replace the header we generated by the input */
                memmove(DNS_PACKET_DATA(p), DNS_PACKET_DATA(p) + DNS_PACKET_HEADER_SIZE,
                        p->size - DNS_PACKET_HEADER_SIZE);
                p->size -= DNS_PACKET_HEADER_SIZE;
        } else if (build_packet(id, flags, k, counts, raw, n, &p) < 0)
                return;

        /* Where the packet comes from, see fuzz_resolved_set_sender(). sel bit 0: IPv6, bits 1-2: sender,
         * see link_peer_address(), bit 3: no interface index known, bit 4: sent to our unicast address
         * instead of the multicast group, bit 5: source port from the input instead of 5353, bit 6: TTL 1
         * instead of 255. */
        family = FLAGS_SET(sel, 1U << 0) ? AF_INET6 : AF_INET;
        ifindex = FLAGS_SET(sel, 1U << 3) ? 0 : 2;
        if (FLAGS_SET(sel, 1U << 5)) {
                /* recvmsg_safe() drops datagrams from port 0 */
                if (port == 0)
                        return;
        } else
                port = MDNS_PORT;

        link_peer_address(family, ((sel >> 1) & 3) % 3, &sender_address);
        if (family == AF_INET)
                sender.in = (struct sockaddr_in) {
                        .sin_family = AF_INET,
                        .sin_port = htobe16(port),
                        .sin_addr = sender_address.in,
                };
        else
                sender.in6 = (struct sockaddr_in6) {
                        .sin6_family = AF_INET6,
                        .sin6_port = htobe16(port),
                        .sin6_addr = sender_address.in6,
                        .sin6_scope_id = in6_addr_is_link_local(&sender_address.in6) ? ifindex : 0,
                };

        if (FLAGS_SET(sel, 1U << 4))
                link_peer_address(family, 1, &destination);
        else if (family == AF_INET)
                destination.in = MDNS_MULTICAST_IPV4_ADDRESS;
        else
                destination.in6 = MDNS_MULTICAST_IPV6_ADDRESS;

        /* resolved's socket for the family, if mDNS is running */
        fd = family == AF_INET ? m->mdns_ipv4_fd : m->mdns_ipv6_fd;
        if (fd < 0)
                return;

        fuzz_resolved_set_sender(fd, &sender, &destination, ifindex, FLAGS_SET(sel, 1U << 6) ? 1 : 255);

        f = fake_socket_find(fd);
        if (!f || send(f->peer, DNS_PACKET_DATA(p), p->size, MSG_DONTWAIT) < 0)
                return;

        /* on_mdns_packet() receives it */
        (void) run_event_loop(m, RUN_ITERATIONS);

        /* Drop the datagram if resolved didn't take it */
        (void) flush_fd(fd);
}

static void on_query_complete(DnsQuery *query) {
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        DnsResourceRecord *rr;
        DnsQuestion *question;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS)
                return;

        /* Like the bus and varlink callers do */
        r = dns_query_process_cname_many(q);
        if (r < 0)
                return;
        if (r == DNS_QUERY_CNAME) {
                /* The query was restarted for the redirected name */
                TAKE_PTR(q);
                return;
        }

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH(rr, q->answer)
                if (dns_question_matches_rr(question, rr,
                                            DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain)) < 0)
                        return;
}

static void start_query(Manager *m, FuzzInput *in) {
        static const uint64_t flag_bits[] = {
                SD_RESOLVED_NO_CNAME,
                SD_RESOLVED_NO_VALIDATE,
                SD_RESOLVED_NO_CACHE,
                SD_RESOLVED_NO_SYNTHESIZE,
                SD_RESOLVED_NO_ZONE,
                SD_RESOLVED_REQUIRE_PRIMARY,
                SD_RESOLVED_CLAMP_TTL,
                SD_RESOLVED_NO_STALE,
        };
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        uint64_t flags = SD_RESOLVED_MDNS|SD_RESOLVED_NO_SEARCH;
        uint8_t b;
        int ifindex;

        assert(m);

        b = fuzz_input_u8(in);
        for (size_t i = 0; i < ELEMENTSOF(flag_bits); i++)
                if (b & (1U << i))
                        flags |= flag_bits[i];
        ifindex = fuzz_input_u8(in) % 4; /* 0 means any, 2 is the link */

        if (read_key(in, &key) < 0)
                return;

        if (m->n_dns_queries >= 8)
                return;

        question = dns_question_new(1);
        if (!question)
                return;
        if (dns_question_add(question, key, /* flags= */ 0) < 0)
                return;

        if (dns_query_new(m, &q, question, question, /* question_bypass= */ NULL, ifindex, flags) < 0)
                return;

        q->complete = on_query_complete;

        if (dns_query_go(q) < 0)
                return;

        TAKE_PTR(q);
}

static void change_address(Link *l, FuzzInput *in) {
        union in_addr_union a = {}, null = {};
        uint8_t sel = fuzz_input_u8(in);
        LinkAddress *la;
        int family;

        if (!l)
                return;

        /* sel bit 0: IPv6, bit 1: remove the first address of the family instead, bits 2-7: address */
        family = FLAGS_SET(sel, 1U << 0) ? AF_INET6 : AF_INET;

        if (FLAGS_SET(sel, 1U << 1)) {
                /* What manager_process_address() does for RTM_DELADDR */
                LIST_FOREACH(addresses, i, l->addresses)
                        if (i->family == family) {
                                link_address_free(i);
                                break;
                        }
                return;
        }

        if (l->n_addresses >= 8)
                return;

        if (family == AF_INET)
                a.in.s_addr = htobe32(UINT32_C(0xc0000200) | (sel >> 2));
        else
                a.in6 = (struct in6_addr) { .s6_addr = { 0xfe, 0x80, [15] = sel >> 2 } };

        if (link_find_address(l, family, &a))
                return;

        if (link_address_new(l, &la, family, &a, &null) < 0)
                return;

        la->prefixlen = family == AF_INET ? 24 : 64;
        la->scope = family == AF_INET ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;

        /* What link_address_update_rtnl() does for RTM_NEWADDR */
        setup_multicast_sockets(l->manager);
        link_allocate_scopes(l);
        link_add_rrs(l, /* force_remove= */ false);
}

static void link_event(Manager *m, Link **l, uint8_t sel) {
        assert(m);
        assert(l);

        if (*l && FLAGS_SET(sel, 1U << 0)) {
                /* What manager_process_link() does for RTM_DELLINK */
                link_remove_user(*l);
                *l = link_free(*l);
                manager_llmnr_maybe_stop(m);
                manager_mdns_maybe_stop(m);
                return;
        }

        if (!*l) {
                /* RTM_NEWLINK for a new link */
                if (link_new_up(m, 2, l) < 0)
                        return;
        }

        /* What link_update() does on RTM_NEWLINK, minus reading networkd's state files */
        setup_multicast_sockets(m);
        link_allocate_scopes(*l);
        link_add_rrs(*l, /* force_remove= */ false);
}

static void change_hostname(Manager *m, uint8_t sel) {
        static const char *const names[] = { "fuzzhost", "otherhost", "fuzzhost2", "x" };
        const char *n = names[sel % ELEMENTSOF(names)];
        _cleanup_free_ char *full = NULL, *llmnr = NULL, *mdns = NULL;

        assert(m);

        /* What on_hostname_change() does when the system hostname changes */
        full = ASSERT_NOT_NULL(strdup(n));
        llmnr = ASSERT_NOT_NULL(strdup(n));
        mdns = ASSERT_NOT_NULL(strjoin(n, ".local"));

        free_and_replace(m->full_hostname, full);
        free_and_replace(m->llmnr_hostname, llmnr);
        free_and_replace(m->mdns_hostname, mdns);

        manager_refresh_rrs(m);
}

static int add_dnssd_service(Manager *m, FuzzInput *in, unsigned idx) {
        _cleanup_(dnssd_registered_service_freep) DnssdRegisteredService *s = NULL;
        _cleanup_(dnssd_txtdata_freep) DnssdTxtData *txt_data = NULL;
        _cleanup_free_ char *txt_key = NULL;
        const uint8_t *txt_value;
        uint8_t flags;
        size_t n;
        int r;

        assert(m);

        /* What dnssd_registered_service_load() does with a .dnssd file */
        s = ASSERT_NOT_NULL(new0(DnssdRegisteredService, 1));

        flags = fuzz_input_u8(in);

        ASSERT_OK(asprintf(&s->id, "fuzz%u", idx));
        s->path = ASSERT_NOT_NULL(strjoin("/etc/systemd/dnssd/", s->id, ".dnssd"));
        s->name_template = ASSERT_NOT_NULL(fuzz_input_string(in));
        s->type = ASSERT_NOT_NULL(fuzz_input_string(in));
        if (FLAGS_SET(flags, 1U << 0))
                s->subtype = ASSERT_NOT_NULL(fuzz_input_string(in));
        s->port = fuzz_input_u16(in);
        s->priority = fuzz_input_u16(in);
        s->weight = fuzz_input_u16(in);

        txt_data = ASSERT_NOT_NULL(new0(DnssdTxtData, 1));
        txt_key = ASSERT_NOT_NULL(fuzz_input_string(in));
        txt_value = fuzz_input_bytes(in, fuzz_input_u8(in), &n);

        if (isempty(txt_key))
                r = dns_txt_item_new_empty(&txt_data->txts);
        else
                r = dnssd_txt_item_new_from_data(txt_key, txt_value, n, &txt_data->txts);
        if (r < 0)
                return r;

        LIST_PREPEND(items, s->txt_data_items, txt_data);
        TAKE_PTR(txt_data);

        r = hashmap_ensure_put(&m->dnssd_registered_services, &dnssd_registered_service_hash_ops, s->id, s);
        if (r < 0)
                return r;

        s->manager = m;

        /* On failure the service is freed, which removes it from the hashmap again */
        r = dnssd_update_rrs(s);
        if (r < 0)
                return r;

        TAKE_PTR(s);
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static const DnsCacheMode cache_modes[] = {
                DNS_CACHE_MODE_YES,
                DNS_CACHE_MODE_NO_NEGATIVE,
                DNS_CACHE_MODE_NO,
        };
        _cleanup_(fuzz_resolved_manager_freep) Manager *m = NULL;
        FuzzInput in = { data, size };
        unsigned n_services = 0;
        uint8_t config, cache;
        Link *l;

        if (outside_size_range(size, 2, 64 * 1024))
                return 0;

        fuzz_forbid_network();
        fuzz_resolved_setup();

        /* The previous input's Manager closed its sockets, close their peers */
        fake_sockets_reset();

        ASSERT_OK(fuzz_resolved_manager_new(&m));
        ASSERT_OK(link_new_up(m, 2, &l));
        setup_multicast_sockets(m);

        /* The configuration bytes, see above */
        config = fuzz_input_u8(&in);
        cache = fuzz_input_u8(&in);

        m->mdns_support = FLAGS_SET(config, 1U << 0) ? RESOLVE_SUPPORT_RESOLVE : RESOLVE_SUPPORT_YES;
        m->llmnr_support = FLAGS_SET(config, 1U << 1) ? RESOLVE_SUPPORT_YES : RESOLVE_SUPPORT_NO;
        m->stale_retention_usec = FLAGS_SET(config, 1U << 4) ? 30 * USEC_PER_SEC : 0;
        m->enable_cache = cache_modes[cache % ELEMENTSOF(cache_modes)];

        if (FLAGS_SET(config, 1U << 2))
                (void) add_dnssd_service(m, &in, n_services++);
        if (FLAGS_SET(config, 1U << 6))
                for (unsigned n = fuzz_input_u8(&in) % 8 + 1; n > 0 && !fuzz_input_eof(&in); n--)
                        (void) add_dnssd_service(m, &in, n_services++);

        if (FLAGS_SET(config, 1U << 3))
                LIST_FOREACH(addresses, a, l->addresses)
                        if (a->family == AF_INET6)
                                a->flags |= IFA_F_TENTATIVE;

        link_allocate_scopes(l);
        link_add_rrs(l, /* force_remove= */ false);

        /* Probing takes three probes, then announcing follows: let the timers elapse a few times */
        if (FLAGS_SET(config, 1U << 5))
                for (unsigned i = 0; i < 8; i++) {
                        expire_timers(m);
                        (void) run_event_loop(m, RUN_ITERATIONS);
                }

        for (unsigned i = 0; i < COMMANDS_MAX && !fuzz_input_eof(&in); i++) {
                switch (fuzz_input_u8(&in) % _CMD_MAX) {

                case CMD_PACKET:
                        deliver_packet(m, &in);
                        break;

                case CMD_QUERY:
                        start_query(m, &in);
                        break;

                case CMD_EXPIRE_TIMERS:
                        expire_timers(m);
                        break;

                case CMD_ADDRESS:
                        change_address(l, &in);
                        break;

                case CMD_FLUSH_CACHES:
                        manager_flush_caches(m, LOG_DEBUG);
                        break;

                case CMD_HOSTNAME:
                        change_hostname(m, fuzz_input_u8(&in));
                        break;

                case CMD_LINK:
                        link_event(m, &l, fuzz_input_u8(&in));
                        break;
                }

                (void) run_event_loop(m, RUN_ITERATIONS);
        }

        if (FLAGS_SET(config, 1U << 7)) {
                DnssdRegisteredService *s;

                /* Unregistering frees the service and drops it from the hashmap */
                while ((s = hashmap_first(m->dnssd_registered_services)))
                        dnssd_registered_service_unregister(s);

                (void) run_event_loop(m, RUN_ITERATIONS);
        }

        return 0;
}
