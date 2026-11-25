/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for systemd-pcrlock's processing of the TPM event logs: the TCG PC Client firmware event log
 * the firmware leaves in /sys/kernel/security/tpm0/binary_bios_measurements (validated by
 * pcrlock-firmware.c), the userspace CEL log (JSON-SEQ, /run/log/systemd/tpm2-measure.log), and the
 * .pcrlock component definitions that are matched against the records. The harness runs what these verbs
 * do with the logs:
 *
 *   "systemd-pcrlock log"   event_log_load_and_process(), show_log_table(), show_pcr_table()
 *   "systemd-pcrlock cel"   event_log_load() with EV_NO_ACTION records, event_log_record_to_cel()
 *   "systemd-pcrlock lock-firmware-code", "systemd-pcrlock lock-firmware-config"
 *                           lock_firmware(), with the .pcrlock files written to /dev/null
 *
 * pcrlock.c is compiled into the fuzzer to reach these static functions. Its two TPM calls are replaced by
 * a fake TPM, whose PCRs were either never extended, or hold exactly the values the logs result in. All
 * files live in a private temporary directory, pointed to by $SYSTEMD_MEASURE_LOG_FIRMWARE/_USERSPACE and
 * arg_components.
 *
 * Input: the firmware event log; or "PCRL", an options byte, [length, 4 bytes LE] firmware log,
 * [length, 4 bytes LE] userspace log, the component file (a .pcrlock JSON object). Options:
 *   bit 0  also show the log as CEL
 *   bit 1  the component file is present
 *   bit 2  the PCRs of the fake TPM hold the values the logs result in (otherwise they are all zero)
 *   bit 3  also lock the firmware code and config */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "fileio.h"
#include "fuzz.h"
#include "iovec-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "tpm2-util.h"
#include "unaligned.h"

/* The event log whose calculated PCR values the fake TPM reports, or NULL for PCRs that were never
 * extended */
static const struct EventLog *fake_tpm2_pcrs = NULL;

static int fake_tpm2_context_new_or_warn(const char *device, Tpm2Context **ret);
static int fake_tpm2_pcr_read(
                Tpm2Context *c,
                const TPML_PCR_SELECTION *selection,
                Tpm2PCRValue **ret_values,
                size_t *ret_n);

/* tpm2-util.h was included above, so the real functions are declared, and the defines only redirect the
 * calls in pcrlock.c */
int pcrlock_main(int argc, char *argv[]);
#define main pcrlock_main
#define tpm2_context_new_or_warn fake_tpm2_context_new_or_warn
#define tpm2_pcr_read fake_tpm2_pcr_read
#include "pcrlock.c"
#undef main
#undef tpm2_context_new_or_warn
#undef tpm2_pcr_read

static int fake_tpm2_context_new_or_warn(const char *device, Tpm2Context **ret) {
        /* The only caller reached, event_log_read_pcrs(), just passes the context on to tpm2_pcr_read() */
        *ret = NULL;
        return 0;
}

static int fake_tpm2_pcr_read(
                Tpm2Context *c,
                const TPML_PCR_SELECTION *selection,
                Tpm2PCRValue **ret_values,
                size_t *ret_n) {

        _cleanup_free_ Tpm2PCRValue *values = NULL;
        size_t n = 0;

        assert(selection);
        assert(ret_values);
        assert(ret_n);

        for (size_t i = 0; i < selection->count; i++) {
                TPMI_ALG_HASH hash = selection->pcrSelections[i].hash;
                uint32_t mask = tpm2_tpms_pcr_selection_to_mask(selection->pcrSelections + i);
                size_t a = SIZE_MAX;
                int digest_size;

                if (fake_tpm2_pcrs) {
                        for (a = 0; a < fake_tpm2_pcrs->n_algorithms; a++)
                                if (fake_tpm2_pcrs->algorithms[a] == hash)
                                        break;
                        if (a >= fake_tpm2_pcrs->n_algorithms)
                                return -EOPNOTSUPP;
                }

                digest_size = tpm2_hash_alg_to_size(hash);
                if (digest_size < 0)
                        return digest_size;

                for (uint32_t pcr = 0; pcr < TPM2_PCRS_MAX; pcr++) {
                        TPM2B_DIGEST value = { .size = digest_size };

                        if (!BIT_SET(mask, pcr))
                                continue;

                        if (fake_tpm2_pcrs)
                                value = fake_tpm2_pcrs->registers[pcr].banks[a].calculated;

                        if (!GREEDY_REALLOC(values, n + 1))
                                return -ENOMEM;

                        values[n++] = (Tpm2PCRValue) {
                                .index = pcr,
                                .hash = hash,
                                .value = value,
                        };
                }
        }

        *ret_values = TAKE_PTR(values);
        *ret_n = n;
        return 0;
}

static char *private_dir = NULL, *firmware_log_path = NULL, *userspace_log_path = NULL, *component_path = NULL;

static void cleanup_private_dir(void) {
        firmware_log_path = mfree(firmware_log_path);
        userspace_log_path = mfree(userspace_log_path);
        component_path = mfree(component_path);
        private_dir = rm_rf_physical_and_free(private_dir);
}

static void setup(void) {
        _cleanup_free_ char *components = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/fuzz-pcrlock-XXXXXX", &private_dir));
        ASSERT_EQ(atexit(cleanup_private_dir), 0);

        firmware_log_path = ASSERT_NOT_NULL(path_join(private_dir, "binary_bios_measurements"));
        userspace_log_path = ASSERT_NOT_NULL(path_join(private_dir, "tpm2-measure.log"));
        components = ASSERT_NOT_NULL(path_join(private_dir, "pcrlock.d"));
        ASSERT_OK_ERRNO(mkdir(components, 0755));
        component_path = ASSERT_NOT_NULL(path_join(components, "500-fuzz.pcrlock"));

        /* Where pcrlock reads the logs and the component definitions from, instead of the system's */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_MEASURE_LOG_FIRMWARE", firmware_log_path, /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_MEASURE_LOG_USERSPACE", userspace_log_path, /* overwrite= */ true));
        ASSERT_OK(strv_extend(&arg_components, components));

        /* Where lock_firmware() writes its .pcrlock files (by default below /var/lib/pcrlock.d/) */
        ASSERT_OK(free_and_strdup(&arg_pcrlock_path, "/dev/null"));

        /* pcrlock's main() loads libcrypto before anything else, the log validation resolves the digest
         * algorithms through it */
        ASSERT_OK(dlopen_libcrypto(LOG_DEBUG));
}

static void write_or_remove(const char *path, const uint8_t *data, size_t size) {
        if (!data) {
                ASSERT_TRUE(unlink(path) >= 0 || errno == ENOENT);
                return;
        }

        ASSERT_OK(write_data_file_atomic_at(AT_FDCWD, path, &IOVEC_MAKE((void*) data, size), /* flags= */ 0));
}

/* event_log_record_validate_hash_firmware() asserts that the variable data of EV_EFI_VARIABLE_BOOT records
 * fits into the record, which nothing checks before (event_log_record_extract_firmware_description()
 * notices, but keeps such records). The steps that validate the record hashes are skipped for such logs. */
static bool firmware_log_has_variable_data_overrun(void) {
        _cleanup_(event_log_freep) EventLog *el = NULL;

        el = ASSERT_NOT_NULL(event_log_new());
        if (event_log_load(el, /* keep_fw_no_action= */ false) < 0)
                return false;

        FOREACH_ARRAY(rr, el->records, el->n_records) {
                const EventLogRecord *r = *rr;
                const UEFI_VARIABLE_DATA *vdata = r->firmware_payload;

                if (!EVENT_LOG_RECORD_IS_FIRMWARE(r) || r->firmware_event_type != EV_EFI_VARIABLE_BOOT)
                        continue;

                /* The same computation as there */
                if (r->firmware_payload_size < offsetof(UEFI_VARIABLE_DATA, unicodeName))
                        return true;
                size_t skip = offsetof(UEFI_VARIABLE_DATA, unicodeName) + vdata->unicodeNameLength * 2;
                if (r->firmware_payload_size < skip)
                        return true;
        }

        return false;
}

static void show_log(void) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *log_table = NULL, *pcr_table = NULL;
        _cleanup_(event_log_freep) EventLog *el = NULL;

        /* Like verb_show_log() with --json= */
        if (event_log_load_and_process(&el) < 0)
                return;

        (void) show_log_table(el, &log_table);
        (void) show_pcr_table(el, &pcr_table);
}

static void show_cel(void) {
        _cleanup_(event_log_freep) EventLog *el = NULL;
        uint64_t recnum = 0;

        /* Like verb_show_cel() */
        el = ASSERT_NOT_NULL(event_log_new());
        if (event_log_load(el, /* keep_fw_no_action= */ true) < 0)
                return;

        FOREACH_ARRAY(rr, el->records, el->n_records) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *cel = NULL;

                if (event_log_record_to_cel(*rr, &recnum, &cel) < 0)
                        return;
        }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(event_log_freep) EventLog *calculated = NULL;
        const uint8_t *firmware_log = data, *userspace_log = NULL, *component = NULL;
        size_t firmware_log_size = size, userspace_log_size = 0, component_size = 0;
        bool validate_hashes;
        uint8_t options = 0;

        if (outside_size_range(size, 0, 1024 * 1024))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        if (!private_dir)
                setup();

        if (size >= 13 && memcmp(data, "PCRL", 4) == 0) {
                const uint8_t *p = data + 5, *e = data + size;

                options = data[4];

                firmware_log_size = MIN((size_t) unaligned_read_le32(p), (size_t) (e - p - 4));
                firmware_log = p + 4;
                p = firmware_log + firmware_log_size;

                if (e - p >= 4) {
                        userspace_log_size = MIN((size_t) unaligned_read_le32(p), (size_t) (e - p - 4));
                        userspace_log = p + 4;
                        p = userspace_log + userspace_log_size;

                        if (FLAGS_SET(options, 1 << 1)) {
                                component = p;
                                component_size = e - p;
                        }
                }
        }

        write_or_remove(firmware_log_path, firmware_log, firmware_log_size);
        write_or_remove(userspace_log_path, userspace_log, userspace_log_size);
        write_or_remove(component_path, component, component_size);

        validate_hashes = !firmware_log_has_variable_data_overrun();

        /* A TPM whose PCRs hold what the logs say they should: the values a first pass calculates */
        if (validate_hashes && FLAGS_SET(options, 1 << 2) && event_log_load_and_process(&calculated) >= 0)
                fake_tpm2_pcrs = calculated;

        if (validate_hashes)
                show_log();

        if (FLAGS_SET(options, 1 << 0))
                show_cel();

        if (validate_hashes && FLAGS_SET(options, 1 << 3)) {
                (void) lock_firmware(/* is_code= */ true);
                (void) lock_firmware(/* is_code= */ false);
        }

        fake_tpm2_pcrs = NULL;
        return 0;
}
