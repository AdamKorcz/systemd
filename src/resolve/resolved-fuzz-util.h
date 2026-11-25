/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Helpers for the systemd-resolved fuzzers: a Manager set up like manager_new() does, but without any
 * interaction with the system. What resolved sends is dropped (sendmsg() is wrapped, as in
 * test-dns-scope.c), what it receives can be made to come from anywhere (recvmsg_safe() is wrapped), and the
 * libshared helpers that would ask the kernel via netlink are wrapped too, as is
 * manager_write_resolv_conf(), see resolve_network_fuzz_template. */

#include "resolved-forward.h"

/* One-time process setup: environment and logging. Call after fuzz_forbid_network(). */
void fuzz_resolved_setup(void);

/* Allocates a Manager the way manager_new() does, but without any of the system interaction (event loop
 * signals, netlink, sd-network, D-Bus, hostname, configuration files). It comes with a global unicast scope,
 * no DNS servers, no links, and the hostname "fuzzhost". */
int fuzz_resolved_manager_new(Manager **ret);

/* Makes the datagrams received on fd come from sender (an AF_INET or AF_INET6 address and a port other than
 * 0), to destination on the interface ifindex with the given TTL (hop limit), as resolved learns from the
 * control messages it enables on its sockets (see manager_recv()). recvmsg_safe() is wrapped for that. */
void fuzz_resolved_set_sender(
                int fd,
                const union sockaddr_union *sender,
                const union in_addr_union *destination,
                int ifindex,
                int ttl);

/* Frees the Manager after finishing its event loop, as resolved does on exit. */
Manager* fuzz_resolved_manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, fuzz_resolved_manager_free);
