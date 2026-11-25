/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "io-util.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-verify.h"
#include "mmap-cache.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unaligned.h"

#define ENTRIES_MAX 256U

static void make_file(char *name, const uint8_t *data, size_t size) {
        _cleanup_close_ int fd = -EBADF;

        /* sd_journal_open_files() refuses files without a name, so the input goes to a temporary file
         * instead of a memfd. */
        fd = ASSERT_OK(mkostemp_safe(name));
        ASSERT_OK(loop_write(fd, data, size));
}

static void browse_journal(sd_journal *j) {
        _cleanup_free_ char *cursor = NULL, *match = NULL;
        uint64_t realtime = 0, monotonic = 0;
        sd_id128_t boot_id = SD_ID128_NULL;
        const void *data;
        const char *field;
        size_t size, match_size = 0;
        uint64_t from, to, seqnum;
        sd_id128_t seqnum_id;
        unsigned n;

        /* What journalctl --disk-usage, --list-boots, --head and --tail query */
        (void) sd_journal_get_cutoff_realtime_usec(j, &from, &to);
        (void) sd_journal_get_usage(j, &from);
        if (sd_journal_seek_tail(j) >= 0 && sd_journal_previous(j) > 0) {
                (void) sd_journal_get_seqnum(j, &seqnum, &seqnum_id);
                (void) sd_journal_get_monotonic_usec(j, &monotonic, &boot_id);
                (void) sd_journal_get_cutoff_monotonic_usec(j, boot_id, &from, &to);
        }
        if (sd_journal_seek_head(j) >= 0 && sd_journal_next(j) > 0) {
                n = 0;
                sd_journal_restart_data(j);
                while (n++ < ENTRIES_MAX && sd_journal_enumerate_available_data(j, &data, &size) > 0)
                        ;
        }

        n = 0;
        SD_JOURNAL_FOREACH(j) {
                if (n++ >= ENTRIES_MAX)
                        break;

                (void) sd_journal_get_realtime_usec(j, &realtime);
                (void) sd_journal_get_monotonic_usec(j, &monotonic, &boot_id);

                SD_JOURNAL_FOREACH_DATA(j, data, size)
                        if (!match && size > 0 && size < 4096 && memchr(data, '=', size)) {
                                match = memdup(data, size);
                                match_size = size;
                        }

                if (!cursor)
                        (void) sd_journal_get_cursor(j, &cursor);
        }

        n = 0;
        SD_JOURNAL_FOREACH_BACKWARDS(j) {
                if (n++ >= ENTRIES_MAX)
                        break;

                (void) sd_journal_get_data(j, "MESSAGE", &data, &size);
        }

        if (sd_journal_seek_realtime_usec(j, realtime) >= 0) {
                (void) sd_journal_next(j);
                (void) sd_journal_previous_skip(j, 3);
        }

        if (sd_journal_seek_monotonic_usec(j, boot_id, monotonic) >= 0) {
                (void) sd_journal_previous(j);
                (void) sd_journal_next_skip(j, 3);
        }

        if (cursor && sd_journal_seek_cursor(j, cursor) >= 0) {
                (void) sd_journal_next(j);
                (void) sd_journal_test_cursor(j, cursor);
        }

        if (match && sd_journal_add_match(j, match, match_size) >= 0) {
                n = 0;
                SD_JOURNAL_FOREACH(j)
                        if (n++ >= ENTRIES_MAX)
                                break;

                (void) sd_journal_add_disjunction(j);
                (void) sd_journal_add_match(j, "PRIORITY=6", SIZE_MAX);
                (void) sd_journal_add_conjunction(j);
                (void) sd_journal_add_match(j, "_BOOT_ID=00000000000000000000000000000000", SIZE_MAX);

                n = 0;
                SD_JOURNAL_FOREACH_BACKWARDS(j)
                        if (n++ >= ENTRIES_MAX)
                                break;

                if (sd_journal_seek_monotonic_usec(j, boot_id, monotonic) >= 0)
                        (void) sd_journal_next(j);

                sd_journal_flush_matches(j);

                _cleanup_free_ char *unique = memdup_suffix0(match, (const char*) memchr(match, '=', match_size) - match);
                if (unique && sd_journal_query_unique(j, unique) >= 0) {
                        n = 0;
                        SD_JOURNAL_FOREACH_UNIQUE(j, data, size)
                                if (n++ >= ENTRIES_MAX)
                                        break;
                }
        }

        n = 0;
        SD_JOURNAL_FOREACH_FIELD(j, field)
                if (n++ >= ENTRIES_MAX)
                        break;
}

static void read_journal(const char *name, const char *name2) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;

        if (sd_journal_open_files(&j, (const char*[]) { name, name2, NULL }, /* flags= */ 0) < 0)
                return;

        browse_journal(j);
}

/* journalctl -D: the files of a directory, with the file name rules of sd_journal (system vs. user
 * journals, archived and corrupted ".journal~" files), interleaved */
static void read_directory(const char *dir, int flags) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;

        if (sd_journal_open_directory(&j, dir, flags) < 0)
                return;

        browse_journal(j);
}

static void verify_journal(MMapCache *m, const char *name) {
        JournalFile *f = NULL;

        if (journal_file_open(-EBADF, name, O_RDONLY, /* file_flags= */ 0, /* mode= */ 0, UINT64_MAX, /* metrics= */ NULL, m, /* template= */ NULL, &f) < 0)
                return;

        /* journalctl --header (stdout goes to /dev/null) */
        journal_file_print_header(f);

        (void) journal_file_verify(f, /* key= */ NULL, /* ret_first_contained= */ NULL, /* ret_last_validated= */ NULL, /* ret_last_contained= */ NULL, /* show_progress= */ false);
        (void) journal_file_close(f);
}

static int make_tmpdir(char **ret) {
        struct statfs sfs;

        /* Writing journal files involves fsync(), hence prefer a tmpfs */
        if (statfs("/dev/shm", &sfs) >= 0 && F_TYPE_EQUAL(sfs.f_type, TMPFS_MAGIC))
                return mkdtemp_malloc("/dev/shm/fuzz-journal-file-XXXXXX", ret);

        return mkdtemp_malloc("/tmp/fuzz-journal-file-XXXXXX", ret);
}

/* journal_file_append_data() asserts that the field name is not empty, as journald only ever writes
 * validated fields. journal_file_copy_entry() passes on whatever DATA objects the source file contains,
 * so skip entries with such fields, rather than hitting the assertion. */
static bool entry_has_empty_field_name(JournalFile *f, Object *o, uint64_t p) {
        uint64_t n;

        if (journal_file_entry_n_fields(f, o, p, &n) < 0)
                return false;

        for (uint64_t i = 0; i < n; i++) {
                const void *data;
                size_t l;

                if (journal_file_entry_field_payload(f, o, p, i, /* field= */ NULL, /* field_length= */ 0,
                                                     &data, &l) <= 0)
                        continue;

                if (l > 0 && *(const char*) data == '=')
                        return true;
        }

        return false;
}

/* Copies the entries of the input into a new journal file with compression enabled for all but tiny
 * fields, as journald does when flushing /run to /var (journal_file_copy_entry()), and then reads the
 * input and the copy back as one interleaved journal, which decompresses the copied DATA objects. */
static void copy_journal(MMapCache *m, const char *name) {
        _cleanup_(rm_rf_physical_and_freep) char *dir = NULL;
        _cleanup_(journal_file_closep) JournalFile *from = NULL, *to = NULL;
        _cleanup_free_ char *copy = NULL;
        JournalMetrics metrics = {
                .max_size = 4 * U64_MB,
                .min_size = 512 * U64_KB,
                .max_use = 16 * U64_MB,
                .min_use = 0,
                .keep_free = 0,
                .n_max_files = 2,
        };
        sd_id128_t seqnum_id = SD_ID128_NULL;
        uint64_t seqnum = 0, p = 0;
        unsigned n = 0;
        Object *o;
        int r;

        if (journal_file_open(-EBADF, name, O_RDONLY, /* file_flags= */ 0, /* mode= */ 0,
                              /* compress_threshold_bytes= */ UINT64_MAX, /* metrics= */ NULL, m,
                              /* template= */ NULL, &from) < 0)
                return;

        ASSERT_OK(make_tmpdir(&dir));
        copy = ASSERT_NOT_NULL(path_join(dir, "copy.journal"));

        if (journal_file_open(-EBADF, copy, O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0644,
                              /* compress_threshold_bytes= */ 8, &metrics, m, /* template= */ NULL, &to) < 0)
                return;

        for (r = journal_file_next_entry(from, 0, DIRECTION_DOWN, &o, &p);
             r > 0 && n < ENTRIES_MAX;
             r = journal_file_next_entry(from, p, DIRECTION_DOWN, &o, &p), n++) {
                if (entry_has_empty_field_name(from, o, p))
                        continue;

                /* Looking at the fields may have moved the mmap window, get the entry again */
                if (journal_file_move_to_object(from, OBJECT_ENTRY, p, &o) < 0)
                        break;

                if (journal_file_copy_entry(from, to, o, p, &seqnum, &seqnum_id) < 0)
                        break;
        }

        to = journal_file_close(to);
        from = journal_file_close(from);

        read_journal(name, copy);
}

/* Input starting with this instead of a journal file header: up to three journal files, each prefixed with
 * its length (32-bit LE), which are put in one directory under the names below and read together (as
 * journalctl --file=a --file=b and -D do), so that the interleaving logic sees independent, conflicting
 * files. */
#define MULTI_MAGIC "FZJ2"

static void fuzz_multi(MMapCache *m, const uint8_t *data, size_t size) {
        static const char *const names[] = {
                "system.journal",
                "system@0123456789abcdef0123456789abcdef-0000000000000001-0005f3e8b4a1c2d3.journal",
                "user-1000.journal~",
        };
        _cleanup_(rm_rf_physical_and_freep) char *dir = NULL;
        _cleanup_strv_free_ char **files = NULL;
        size_t n = 0;

        ASSERT_OK(make_tmpdir(&dir));

        while (n < ELEMENTSOF(names) && size >= 4) {
                size_t l = MIN((size_t) unaligned_read_le32(data), size - 4);
                _cleanup_close_ int fd = -EBADF;
                char *f;

                f = ASSERT_NOT_NULL(path_join(dir, names[n]));
                ASSERT_OK(strv_consume(&files, f));

                fd = ASSERT_OK_ERRNO(open(files[n], O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600));
                ASSERT_OK(loop_write(fd, data + 4, l));

                data += 4 + l;
                size -= 4 + l;
                n++;
        }

        if (n == 0)
                return;

        read_journal(files[0], n > 1 ? files[1] : NULL);
        read_directory(dir, /* flags= */ 0);
        read_directory(dir, SD_JOURNAL_SYSTEM);
        verify_journal(m, files[n - 1]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-journal-file.XXXXXX";
        static bool initialized = false;

        if (outside_size_range(size, 4, 1024 * 1024))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        if (!initialized) {
                /* journal_file_print_header() writes to stdout */
                if (getenv_bool("SYSTEMD_FUZZ_OUTPUT") <= 0)
                        ASSERT_NOT_NULL(freopen("/dev/null", "w", stdout));
                initialized = true;
        }

        m = ASSERT_NOT_NULL(mmap_cache_new());

        if (memcmp(data, MULTI_MAGIC, 4) == 0) {
                fuzz_multi(m, data + 4, size - 4);
                return 0;
        }

        if (size < sizeof(Header))
                return 0;

        make_file(name, data, size);
        read_journal(name, /* name2= */ NULL);
        verify_journal(m, name);
        copy_journal(m, name);

        return 0;
}
