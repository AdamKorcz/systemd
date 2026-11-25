/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "sd-netlink.h"

#include "fd-util.h"
#include "fuzz.h"
#include "fuzz-netlink.h"
#include "memory-util.h"
#include "netlink-genl.h"
#include "netlink-types.h"
#include "string-util.h"
#include "tests.h"

/* The ends of the socketpairs of fuzz_netlink_new() that sd-netlink uses, and the other ends, from which the
 * kernel replies. sd-netlink closes its end when it is freed, without us knowing, hence the inode tells
 * whether fd still refers to it. */
typedef struct FakeNetlinkSocket {
        int fd;
        ino_t inode;
        int protocol;
        int kernel_fd;
} FakeNetlinkSocket;

static FakeNetlinkSocket sockets[4] = {
        { .fd = -EBADF, .kernel_fd = -EBADF },
        { .fd = -EBADF, .kernel_fd = -EBADF },
        { .fd = -EBADF, .kernel_fd = -EBADF },
        { .fd = -EBADF, .kernel_fd = -EBADF },
};

/* The generic netlink families the kernel knows, see fuzz_genl_add_family() */
static struct {
        char *name;
        uint16_t id;
} families[16];
static size_t n_families = 0;

static FakeNetlinkSocket* fake_socket_find(int fd) {
        struct stat st;

        if (fd < 0 || fstat(fd, &st) < 0)
                return NULL;

        FOREACH_ELEMENT(s, sockets)
                if (s->fd == fd && s->inode == st.st_ino)
                        return s;

        return NULL;
}

sd_netlink* fuzz_netlink_new(int protocol, int *ret_fd) {
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        FakeNetlinkSocket *slot = NULL;
        sd_netlink *nl;
        struct stat st;

        assert(ret_fd);

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, fds));
        ASSERT_OK(fuzz_bind_netlink_address(fds[1], /* nl_pid= */ 0, /* nl_groups= */ 0));
        ASSERT_OK_ERRNO(fstat(fds[0], &st));

        FOREACH_ELEMENT(s, sockets)
                if (s->fd < 0 || fake_socket_find(s->fd) != s) {
                        slot = s;
                        break;
                }
        ASSERT_NOT_NULL(slot);

        *slot = (FakeNetlinkSocket) {
                .fd = fds[0],
                .inode = st.st_ino,
                .protocol = protocol,
                .kernel_fd = fds[1],
        };

        ASSERT_OK(sd_netlink_open_fd(&nl, fds[0]));
        TAKE_FD(fds[0]);

        *ret_fd = TAKE_FD(fds[1]);
        return nl;
}

void fuzz_genl_add_family(sd_netlink *nl, const char *name, uint16_t id) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        bool known = false;
        uint16_t type;
        int r;

        assert(nl);
        assert(name);
        assert(strlen(name) < GENL_NAMSIZ);
        assert(id > GENL_ID_CTRL);

        for (size_t i = 0; i < n_families; i++)
                if (streq(families[i].name, name)) {
                        assert(families[i].id == id);
                        known = true;
                }

        if (!known) {
                assert(n_families < ELEMENTSOF(families));
                families[n_families++] = (typeof(families[0])) {
                        .name = ASSERT_NOT_NULL(strdup(name)),
                        .id = id,
                };
        }

        /* Looks up the family. The policies of some families are indexed by command, see
         * genl_family_is_indexed_by_command(), then creating a message for command 0 fails, but the family
         * is known nonetheless. */
        r = sd_genl_message_new(nl, name, /* cmd= */ 0, &m);
        if (genl_family_is_indexed_by_command(name))
                return;

        ASSERT_OK(r);
        ASSERT_OK(sd_netlink_message_get_type(m, &type));
        ASSERT_EQ(type, id);
}

static void put_attribute(uint8_t *buf, size_t *offset, uint16_t type, const void *data, size_t len) {
        struct nlattr *a = (struct nlattr*) (buf + *offset);

        *a = (struct nlattr) {
                .nla_type = type,
                .nla_len = NLA_HDRLEN + len,
        };
        memcpy(buf + *offset + NLA_HDRLEN, data, len);
        memzero(buf + *offset + NLA_HDRLEN + len, NLA_ALIGN(len) - len);
        *offset += NLA_HDRLEN + NLA_ALIGN(len);
}

/* Answers a request for the ID of a known generic netlink family as the kernel does, without the ACK that
 * follows the reply. sd-netlink only needs the reply. */
static int kernel_reply(const FakeNetlinkSocket *s, const void *buf, size_t len) {
        const struct nlmsghdr *request = buf;
        const struct genlmsghdr *genl;
        const char *name = NULL;
        uint16_t id = 0;
        uint32_t version = 1, header_size = 0;

        if (s->protocol != NETLINK_GENERIC || len < NLMSG_LENGTH(GENL_HDRLEN) || request->nlmsg_len > len ||
            request->nlmsg_type != GENL_ID_CTRL)
                return -EOPNOTSUPP;

        genl = NLMSG_DATA(request);
        if (genl->cmd != CTRL_CMD_GETFAMILY)
                return -EOPNOTSUPP;

        for (size_t offset = NLMSG_LENGTH(GENL_HDRLEN); offset + NLA_HDRLEN <= request->nlmsg_len;) {
                const struct nlattr *a = (const struct nlattr*) ((const uint8_t*) buf + offset);

                if (a->nla_len < NLA_HDRLEN || a->nla_len > request->nlmsg_len - offset)
                        break;

                if ((a->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_NAME &&
                    memchr((const uint8_t*) a + NLA_HDRLEN, 0, a->nla_len - NLA_HDRLEN))
                        name = (const char*) a + NLA_HDRLEN;

                offset += NLA_ALIGN(a->nla_len);
        }
        if (!name)
                return -EINVAL;

        if (streq(name, CTRL_GENL_NAME))
                id = GENL_ID_CTRL;
        else
                for (size_t i = 0; i < n_families; i++)
                        if (streq(families[i].name, name))
                                id = families[i].id;
        if (id == 0)
                return -ENOENT;

        union {
                struct nlmsghdr hdr;
                uint8_t buf[NLMSG_LENGTH(GENL_HDRLEN) + 4 * NLA_HDRLEN + NLA_ALIGN(GENL_NAMSIZ) +
                            NLA_ALIGN(sizeof(uint16_t)) + 2 * sizeof(uint32_t)];
        } reply = {};
        size_t offset = NLMSG_LENGTH(GENL_HDRLEN);

        *(struct genlmsghdr*) NLMSG_DATA(&reply.hdr) = (struct genlmsghdr) {
                .cmd = CTRL_CMD_NEWFAMILY,
                .version = 2,
        };
        put_attribute(reply.buf, &offset, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);
        put_attribute(reply.buf, &offset, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
        put_attribute(reply.buf, &offset, CTRL_ATTR_VERSION, &version, sizeof(version));
        put_attribute(reply.buf, &offset, CTRL_ATTR_HDRSIZE, &header_size, sizeof(header_size));

        /* To our port ID, which is 0 (see the header) */
        reply.hdr = (struct nlmsghdr) {
                .nlmsg_len = offset,
                .nlmsg_type = GENL_ID_CTRL,
                .nlmsg_seq = request->nlmsg_seq,
        };

        if (send(s->kernel_fd, reply.buf, offset, MSG_DONTWAIT) < 0)
                return -errno;

        return 0;
}

/* Wrapped functions (-Wl,--wrap=, see the meson.build of the fuzzer) */

/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __wrap_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __real_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
/* glibc redirects setsockopt() and getsockopt() to __setsockopt64() and __getsockopt64() on 32-bit systems
 * with 64-bit time_t. sd-netlink sets and gets no option that involves time_t. */
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __wrap___setsockopt64(int fd, int level, int optname, const void *optval, socklen_t optlen);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __wrap_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __real_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __wrap___getsockopt64(int fd, int level, int optname, void *optval, socklen_t *optlen);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
ssize_t __wrap_sendto(
                int fd,
                const void *buf,
                size_t len,
                int flags,
                const struct sockaddr *addr,
                socklen_t addrlen);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
ssize_t __real_sendto(
                int fd,
                const void *buf,
                size_t len,
                int flags,
                const struct sockaddr *addr,
                socklen_t addrlen);

/* The netlink options are accepted, without effect */
int __wrap_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
        if (level == SOL_NETLINK && fake_socket_find(fd))
                return 0;

        return __real_setsockopt(fd, level, optname, optval, optlen);
}

int __wrap___setsockopt64(int fd, int level, int optname, const void *optval, socklen_t optlen) {
        return __wrap_setsockopt(fd, level, optname, optval, optlen);
}

/* The protocol is the one given to fuzz_netlink_new(), and there are no multicast group memberships */
int __wrap_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
        const FakeNetlinkSocket *s = fake_socket_find(fd);

        if (s && level == SOL_SOCKET && optname == SO_PROTOCOL) {
                assert(optval && optlen && *optlen >= sizeof(int));
                *(int*) optval = s->protocol;
                *optlen = sizeof(int);
                return 0;
        }

        if (s && level == SOL_NETLINK && optname == NETLINK_LIST_MEMBERSHIPS) {
                assert(optlen);
                *optlen = 0;
                return 0;
        }

        return __real_getsockopt(fd, level, optname, optval, optlen);
}

int __wrap___getsockopt64(int fd, int level, int optname, void *optval, socklen_t *optlen) {
        return __wrap_getsockopt(fd, level, optname, optval, optlen);
}

/* Requests for the ID of a generic netlink family are answered, everything else fails as before */
ssize_t __wrap_sendto(
                int fd,
                const void *buf,
                size_t len,
                int flags,
                const struct sockaddr *addr,
                socklen_t addrlen) {

        const FakeNetlinkSocket *s = fake_socket_find(fd);

        if (s && kernel_reply(s, buf, len) >= 0)
                return len;

        return __real_sendto(fd, buf, len, flags, addr, addrlen);
}
