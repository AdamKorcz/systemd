/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Helpers for fuzzers that feed netlink messages to sd-netlink as if they came from the kernel
 * (fuzz-netlink.c). The sd_netlink objects are opened with sd_netlink_open_fd() on one end of an AF_UNIX
 * socketpair, whose other end has the kernel's address (see fuzz_bind_netlink_address()).
 *
 * AF_UNIX sockets have no netlink socket options and refuse netlink addresses, hence these fuzzers link
 * sd-netlink statically and wrap (-Wl,--wrap=) the socket calls it makes: setsockopt() accepts the netlink
 * options, getsockopt() reports the protocol and no multicast group memberships, and sendto() answers the
 * requests for the ID of a generic netlink family (CTRL_CMD_GETFAMILY) that sd-netlink makes when it first
 * uses one, for the families given to fuzz_genl_add_family(). Everything else sd-netlink sends fails, as
 * AF_UNIX sockets refuse netlink addresses. The messages are always received as unicast, as the multicast
 * group would come in a control message that AF_UNIX sockets cannot carry. */

#include <stdint.h>

#include "sd-netlink.h"

/* Returns an sd_netlink object for the protocol, which receives what is sent on *ret_fd */
sd_netlink* fuzz_netlink_new(int protocol, int *ret_fd);

/* Makes the kernel know the generic netlink family with the given ID, and nl look it up, as it does when it
 * first uses the family */
void fuzz_genl_add_family(sd_netlink *nl, const char *name, uint16_t id);
