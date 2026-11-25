/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the user record checks systemd-homed and systemd-homework apply to records they did not
 * create themselves: user_record_self_changes_allowed() (which changes an unprivileged user may make to
 * their own record), user_record_reconcile() (the record embedded in a home directory/image, i.e. on
 * possibly removable media, against the host's copy), signature verification, and the record comparison
 * helpers. (Plain record parsing is covered by fuzz-user-record.)
 *
 * Input: a JSON object with the fields "current" (the record homed has), "incoming" (the record to apply or
 * the embedded one) and optionally "mode" (0…2, the reconciliation mode), "update" (true: "incoming" is
 * loaded as UpdateHome() reads the record a client sends, including its "secret" section, instead of as the
 * record embedded in a home image) and "secret" (a secret-only record as ActivateHome(), UnlockHome() etc.
 * read it from the client, merged into the record like homed does). An Ed25519 key pair generated at
 * startup takes the place of homed's signing key. No user database lookup, no file system access.
 *
 * perMachine sections apply if they match the local system. The fuzzer can't know the host name and machine
 * ID, but matchNotHostname/matchNotMachineId match on every other system. */

#include "sd-bus.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "crypto-util.h"
#include "fuzz.h"
#include "strv.h"
#include "tests.h"
#include "user-record.h"
#include "user-record-sign.h"
#include "user-record-util.h"

static EVP_PKEY *signing_key = NULL;

/* homed signs the records it creates with an Ed25519 key, see manager_generate_key_pair(). */
static void generate_signing_key(void) {
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = NULL;

        ASSERT_OK(dlopen_libcrypto(LOG_DEBUG));

        ctx = ASSERT_NOT_NULL(sym_EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, /* e= */ NULL));
        ASSERT_EQ(sym_EVP_PKEY_keygen_init(ctx), 1);
        ASSERT_EQ(sym_EVP_PKEY_keygen(ctx, &signing_key), 1);
}

static void fuzz_one_record(UserRecord *h) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **languages = NULL;

        (void) user_record_is_supported(h, &error);
        /* homed only asks this for its own records, which always resolve to an image path (a LUKS record
         * without user name doesn't, and trips an assertion) */
        if (user_record_image_path(h))
                (void) user_record_shall_rebalance(h);
        (void) user_record_has_signature(h);
        DO_NOT_OPTIMIZE(user_record_self_modifiable_fields(h));
        DO_NOT_OPTIMIZE(user_record_self_modifiable_blobs(h));
        DO_NOT_OPTIMIZE(user_record_self_modifiable_privileged(h));

        /* The accessors with their fallback logic, which homework uses to set things up */
        DO_NOT_OPTIMIZE(user_record_home_directory(h));
        DO_NOT_OPTIMIZE(user_record_shell(h));
        DO_NOT_OPTIMIZE(user_record_real_name(h));
        DO_NOT_OPTIMIZE(user_record_file_system_type(h));
        DO_NOT_OPTIMIZE(user_record_skeleton_directory(h));
        DO_NOT_OPTIMIZE(user_record_access_mode(h));
        DO_NOT_OPTIMIZE(user_record_mount_flags(h));
        DO_NOT_OPTIMIZE(user_record_luks_cipher(h));
        DO_NOT_OPTIMIZE(user_record_luks_cipher_mode(h));
        DO_NOT_OPTIMIZE(user_record_luks_volume_key_size(h));
        DO_NOT_OPTIMIZE(user_record_luks_pbkdf_type(h));
        DO_NOT_OPTIMIZE(user_record_luks_pbkdf_hash_algorithm(h));
        DO_NOT_OPTIMIZE(user_record_luks_pbkdf_time_cost_usec(h));
        DO_NOT_OPTIMIZE(user_record_luks_pbkdf_memory_cost(h));
        DO_NOT_OPTIMIZE(user_record_luks_pbkdf_parallel_threads(h));
        DO_NOT_OPTIMIZE(user_record_luks_sector_size(h));
        DO_NOT_OPTIMIZE(user_record_luks_offline_discard(h));
        DO_NOT_OPTIMIZE(user_record_removable(h));
        DO_NOT_OPTIMIZE(user_record_ratelimit_interval_usec(h));
        DO_NOT_OPTIMIZE(user_record_ratelimit_burst(h));
        DO_NOT_OPTIMIZE(user_record_auto_resize_mode(h));
        DO_NOT_OPTIMIZE(user_record_rebalance_weight(h));
        DO_NOT_OPTIMIZE(user_record_capability_bounding_set(h));
        DO_NOT_OPTIMIZE(user_record_capability_ambient_set(h));
        DO_NOT_OPTIMIZE(user_record_tmp_limit_scale(h));
        DO_NOT_OPTIMIZE(user_record_dev_shm_limit_scale(h));
        (void) user_record_languages(h, &languages);

        /* Whether homed would accept the record as signed by its own key */
        (void) user_record_verify(h, signing_key);
}

/* A secret-only record as bus_message_read_secret() loads it (the client sends the contents of the
 * "secret" section), merged into a copy of the record as home_activate() and friends do before handing
 * it to homework. */
static void fuzz_secret(UserRecord *current, sd_json_variant *v) {
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL, *merged = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *full = NULL;

        if (!sd_json_variant_is_object(v))
                return;

        ASSERT_OK(sd_json_buildo(&full, SD_JSON_BUILD_PAIR_VARIANT("secret", v)));

        secret = ASSERT_NOT_NULL(user_record_new());
        if (user_record_load(secret, full, USER_RECORD_REQUIRE_SECRET|USER_RECORD_PERMISSIVE) < 0)
                return;

        if (user_record_clone(current, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE, &merged) < 0)
                return;

        (void) user_record_merge_secret(merged, secret);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(user_record_unrefp) UserRecord *current = NULL, *incoming = NULL, *signed_record = NULL,
                *result = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *s = NULL;
        UserRecordLoadFlags incoming_flags;
        sd_json_variant *c, *i, *sv;
        uint64_t mode;
        int r;

        if (outside_size_range(size, 0, 64 * 1024))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        if (!signing_key)
                generate_signing_key();

        s = ASSERT_NOT_NULL(memdup_suffix0(data, size));
        if (sd_json_parse(s, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL) < 0)
                return 0;

        c = sd_json_variant_by_key(v, "current");
        i = sd_json_variant_by_key(v, "incoming");
        sv = sd_json_variant_by_key(v, "secret");
        mode = sd_json_variant_unsigned(sd_json_variant_by_key(v, "mode")) % _USER_RECONCILE_MODE_MAX;

        /* homed loads the records it keeps in /var/lib/systemd/home/ like this
         * (home_load_embedded_identity(), manager_add_home_by_record()) */
        current = ASSERT_NOT_NULL(user_record_new());
        if (!c || user_record_load(current, c, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE) < 0)
                return 0;

        fuzz_one_record(current);

        /* Sign with our key, and verify again */
        if (user_record_sign(current, signing_key, &signed_record) >= 0)
                (void) user_record_verify(signed_record, signing_key);

        if (sv)
                fuzz_secret(current, sv);

        /* UpdateHome() (homed-home-bus.c) reads the client's record with these flags, the record embedded
         * in a home image is loaded with USER_RECORD_LOAD_EMBEDDED (homework.c) */
        if (sd_json_variant_boolean(sd_json_variant_by_key(v, "update")))
                incoming_flags = USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_SECRET|USER_RECORD_ALLOW_PRIVILEGED|
                        USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_PERMISSIVE;
        else
                incoming_flags = USER_RECORD_LOAD_EMBEDDED|USER_RECORD_PERMISSIVE;

        incoming = ASSERT_NOT_NULL(user_record_new());
        if (!i || user_record_load(incoming, i, incoming_flags) < 0)
                return 0;

        fuzz_one_record(incoming);

        (void) user_record_self_changes_allowed(current, incoming);
        (void) user_record_equal(current, incoming);
        (void) user_record_compatible(current, incoming);
        (void) user_record_compare_last_change(current, incoming);
        for (UserRecordMask m = 1; m <= _USER_RECORD_MASK_MAX; m <<= 1)
                (void) user_record_masked_equal(current, incoming, m);

        r = user_record_reconcile(current, incoming, (UserReconcileMode) mode, &result);
        if (r >= 0)
                ASSERT_NOT_NULL(result);

        return 0;
}
