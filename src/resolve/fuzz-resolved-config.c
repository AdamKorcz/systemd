/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the configuration parsers of systemd-resolved: resolved.conf ([Resolve] section, i.e.
 * config_parse_dns_servers(), config_parse_search_domains(), config_parse_dns_stub_listener_extra(),
 * config_parse_record_types() …), DNS-SD service files (config_parse_dnssd_*()), DNS delegate files
 * (config_parse_delegate_*()) and DNSSEC trust anchor files (dns_trust_anchor_load(), which reads the
 * *.positive and *.negative files in /etc/dnssec-trust-anchors.d/ and elsewhere: here only the file the
 * fuzzer writes, see __wrap_conf_files_list_nulstr()). These are root-owned files.
 *
 * Input: the first byte selects the format, the rest is the file contents. */

#include <fcntl.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "dns-rr.h"
#include "fileio.h"
#include "fuzz.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "path-util.h"
#include "resolved-conf.h"
#include "resolved-dns-delegate.h"
#include "resolved-dns-trust-anchor.h"
#include "resolved-dnssd.h"
#include "resolved-fuzz-util.h"
#include "resolved-manager.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

/* The trust anchor file dns_trust_anchor_load() reads, if any */
static char *trust_anchor_dir = NULL, *trust_anchor_file = NULL;

static void trust_anchor_dir_remove(void) {
        trust_anchor_file = mfree(trust_anchor_file);
        trust_anchor_dir = rm_rf_physical_and_free(trust_anchor_dir);
}

/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __wrap_conf_files_list_nulstr(
                char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dirs);
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
int __real_conf_files_list_nulstr(
                char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dirs);

/* dns_trust_anchor_load() lists the *.positive and *.negative files in the dnssec-trust-anchors.d/
 * directories: it finds trust_anchor_file there, if it has the suffix, and nothing else. */
int __wrap_conf_files_list_nulstr(
                char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dirs) {

        assert(ret);
        assert(dirs);

        /* dirs is a nulstr, its first entry is /etc/dnssec-trust-anchors.d for the trust anchors */
        if (!endswith(dirs, "/dnssec-trust-anchors.d"))
                return __real_conf_files_list_nulstr(ret, suffix, root, flags, dirs);

        if (trust_anchor_file && suffix && endswith(trust_anchor_file, suffix))
                *ret = strv_new(trust_anchor_file);
        else
                *ret = strv_new(NULL);

        return *ret ? 0 : -ENOMEM;
}

static void parse_dnssd(Manager *m, FILE *f) {
        _cleanup_(dnssd_registered_service_freep) DnssdRegisteredService *s = NULL;
        _cleanup_(dnssd_txtdata_freep) DnssdTxtData *txt_data = NULL;

        /* Like dnssd_registered_service_load(), for the file "fuzz.dnssd" without drop-ins */
        s = ASSERT_NOT_NULL(new0(DnssdRegisteredService, 1));
        s->path = ASSERT_NOT_NULL(strdup("/etc/systemd/dnssd/fuzz.dnssd"));
        s->id = ASSERT_NOT_NULL(strdup("fuzz"));

        if (config_parse(/* unit= */ NULL, "fuzz.dnssd", f, "Service\0", config_item_perf_lookup,
                         resolved_dnssd_gperf_lookup, CONFIG_PARSE_WARN, s, /* ret_stat= */ NULL) < 0)
                return;

        if (!s->name_template || !s->type)
                return;

        if (!s->txt_data_items) {
                txt_data = ASSERT_NOT_NULL(new0(DnssdTxtData, 1));
                ASSERT_OK(dns_txt_item_new_empty(&txt_data->txts));

                LIST_PREPEND(items, s->txt_data_items, txt_data);
                TAKE_PTR(txt_data);
        }

        if (hashmap_ensure_put(&m->dnssd_registered_services, &dnssd_registered_service_hash_ops,
                               s->id, s) < 0)
                return;

        s->manager = m;

        if (dnssd_update_rrs(s) < 0)
                return; /* frees the service, which removes it from the hashmap again */

        TAKE_PTR(s);
}

static void parse_delegate(Manager *m, FILE *f) {
        _cleanup_(dns_delegate_freep) DnsDelegate *d = NULL;

        /* Like dns_delegate_load(), for the file "fuzz.dns-delegate" without drop-ins */
        ASSERT_OK(dns_delegate_new(m, "fuzz", &d));

        if (config_parse(/* unit= */ NULL, "fuzz.dns-delegate", f, "Delegate\0", config_item_perf_lookup,
                         resolved_dns_delegate_gperf_lookup, /* flags= */ 0, d, /* ret_stat= */ NULL) < 0)
                return;

        TAKE_PTR(d); /* owned by the Manager now */
}

static void load_trust_anchors(Manager *m, const uint8_t *data, size_t size, bool positive) {
        if (!trust_anchor_dir) {
                ASSERT_OK(mkdtemp_malloc("/tmp/fuzz-resolved-config-XXXXXX", &trust_anchor_dir));
                ASSERT_EQ(atexit(trust_anchor_dir_remove), 0);
        }

        free(trust_anchor_file);
        trust_anchor_file = ASSERT_NOT_NULL(path_join(trust_anchor_dir,
                                                      positive ? "fuzz.positive" : "fuzz.negative"));
        ASSERT_OK(write_data_file_atomic_at(AT_FDCWD, trust_anchor_file, &IOVEC_MAKE(data, size),
                                            /* flags= */ 0));

        /* As manager_new() does, and on reload */
        (void) dns_trust_anchor_load(&m->trust_anchor);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(fuzz_resolved_manager_freep) Manager *m = NULL;
        _cleanup_fclose_ FILE *f = NULL;

        if (outside_size_range(size, 1, 64 * 1024))
                return 0;

        fuzz_forbid_network();
        fuzz_resolved_setup();

        ASSERT_OK(fuzz_resolved_manager_new(&m));

        if (IN_SET(data[0] % 5, 3, 4)) {
                load_trust_anchors(m, data + 1, size - 1, /* positive= */ data[0] % 5 == 3);
                return 0;
        }

        f = ASSERT_NOT_NULL(data_to_file(data + 1, size - 1));

        switch (data[0] % 5) {

        case 0:
                /* What manager_parse_config_file() does for resolved.conf and its drop-ins */
                (void) config_parse(/* unit= */ NULL, "resolved.conf", f, "Resolve\0",
                                    config_item_perf_lookup, resolved_gperf_lookup, CONFIG_PARSE_WARN, m,
                                    /* ret_stat= */ NULL);
                break;

        case 1:
                parse_dnssd(m, f);
                break;

        case 2:
                parse_delegate(m, f);
                break;
        }

        return 0;
}
