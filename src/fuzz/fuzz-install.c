/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the unit file installation logic in install.c, as used by systemctl
 * enable/disable/preset/mask/... with --root= (e.g. by image builders on untrusted image trees) and by
 * PID 1's Enable/Disable/Preset methods: unit file [Install] section parsing (Alias=, WantedBy=,
 * RequiredBy=, UpheldBy=, Also=, DefaultInstance=), drop-ins, alias and .wants/ symlink validation,
 * preset file parsing and matching, and the enable/disable/mask/revert/state machinery.
 *
 * Everything operates on a private root directory, created per input below /dev/shm if that is a tmpfs
 * (otherwise below /tmp) and removed again. All files from the input are created before any operation
 * runs, with O_NOFOLLOW|O_EXCL on directories opened with O_NOFOLLOW, so that nothing is ever written
 * through a symlink. Unit names passed to the operations must be valid unit names, i.e. never paths.
 * Symlinks created from the input are named like units and only point to unit names, /dev/null or unit
 * directory paths, which install.c resolves relative to the root.
 *
 * Input layout:
 *   byte 0: scope (bit 0: system or global), initrd root (bit 1)
 *   then records: type (1 byte), length (2 bytes LE), payload. Types:
 *     0-2: unit file in the vendor, admin or runtime unit directory: "name\ncontent"
 *     3:   drop-in in the vendor unit directory: "unit name\ncontent"
 *     4:   preset file: content
 *     5:   symlink in the admin or vendor unit directory: "name\ntarget"
 *     6:   operation: op (1 byte), flags (1 byte), unit names one per line
 *          op bits 0-3: the operation (see run_op()), bit 4: UNIT_FILE_VENDOR, bit 5: UNIT_FILE_PORTABLE,
 *          bit 6: report the changes verbosely. After each operation that makes changes, the changes are
 *          reported with install_changes_dump(), as systemctl does.
 *          Operation 14 is unit_file_link() (systemctl link): it links /opt/<name> for each name, a copy of
 *          the vendor unit file of that name if there is one, otherwise a unit with an [Install] section.
 *     7:   unit_file_verify_alias(): "unit name\nalias" */

#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fuzz.h"
#include "hashmap.h"
#include "install.h"
#include "io-util.h"
#include "mkdir.h"
#include "path-lookup.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unaligned.h"
#include "unit-name.h"

#define MAX_RECORDS 64U
#define MAX_OPS 16U

typedef struct Op {
        uint8_t op, flags;
        char **names;
} Op;

/* The vendor, admin and runtime unit directories, for the system and the global (user) scope */
static const char* const unit_dirs[2][3] = {
        { "usr/lib/systemd/system", "etc/systemd/system", "run/systemd/system" },
        { "usr/lib/systemd/user", "etc/systemd/user", "run/systemd/user" },
};

static const char* preset_dir(bool global, bool initrd) {
        if (global)
                return "usr/lib/systemd/user-preset";
        if (initrd)
                return "usr/lib/systemd/initrd-preset";
        return "usr/lib/systemd/system-preset";
}

/* An empty root with the unit and preset directories, and the usual targets */
static char* make_root(bool global, bool initrd) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        struct statfs sfs;

        /* Many small files are created and removed for every input, hence prefer a tmpfs */
        if (statfs("/dev/shm", &sfs) >= 0 && F_TYPE_EQUAL(sfs.f_type, TMPFS_MAGIC))
                ASSERT_OK(mkdtemp_malloc("/dev/shm/fuzz-install-XXXXXX", &root));
        else
                ASSERT_OK(mkdtemp_malloc("/tmp/fuzz-install-XXXXXX", &root));

        FOREACH_STRING(d, unit_dirs[global][0], unit_dirs[global][1], unit_dirs[global][2], "opt",
                       preset_dir(global, initrd)) {
                _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(root, d));

                ASSERT_OK(mkdir_p(p, 0755));
        }

        if (initrd) {
                _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(root, "etc/initrd-release"));

                ASSERT_OK(touch(p));
        }

        FOREACH_STRING(t, "multi-user.target", "graphical.target", "default.target", "sockets.target") {
                _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(root, unit_dirs[global][0], t));

                ASSERT_OK(touch(p));
        }

        return TAKE_PTR(root);
}

static int open_dir(const char *root, const char *d) {
        _cleanup_free_ char *p = path_join(root, d);
        if (!p)
                return -ENOMEM;

        return RET_NERRNO(open(p, O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
}

/* Creates a new file below dir_fd. Never follows symlinks and never overwrites anything. */
static void write_new_file(int dir_fd, const char *name, const char *content) {
        _cleanup_close_ int fd = -EBADF;

        if (!filename_is_valid(name))
                return;

        fd = openat(dir_fd, name, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0644);
        if (fd < 0)
                return;

        (void) loop_write(fd, content, SIZE_MAX);
}

static int split_payload(const uint8_t *payload, size_t len, char **ret_first, const char **ret_rest) {
        _cleanup_free_ char *s = NULL;
        char *nl;

        s = memdup_suffix0(payload, len);
        if (!s)
                return -ENOMEM;

        nl = strchr(s, '\n');
        if (!nl)
                return -EINVAL;
        *nl = 0;

        *ret_rest = nl + 1;
        *ret_first = TAKE_PTR(s);
        return 0;
}

static void add_file(const char *root, bool global, unsigned dir, const uint8_t *payload, size_t len) {
        _cleanup_close_ int dir_fd = -EBADF;
        _cleanup_free_ char *name = NULL;
        const char *content;

        if (split_payload(payload, len, &name, &content) < 0)
                return;

        dir_fd = open_dir(root, unit_dirs[global][dir]);
        if (dir_fd < 0)
                return;

        write_new_file(dir_fd, name, content);
}

static void add_dropin(const char *root, bool global, const uint8_t *payload, size_t len, unsigned n) {
        _cleanup_close_ int dir_fd = -EBADF, dropin_fd = -EBADF;
        _cleanup_free_ char *unit = NULL, *d = NULL, *conf = NULL;
        const char *content;

        if (split_payload(payload, len, &unit, &content) < 0)
                return;

        d = strjoin(unit, ".d");
        if (!d || !filename_is_valid(d))
                return;

        dir_fd = open_dir(root, unit_dirs[global][0]);
        if (dir_fd < 0)
                return;

        (void) mkdirat(dir_fd, d, 0755);
        dropin_fd = openat(dir_fd, d, O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (dropin_fd < 0)
                return;

        if (asprintf(&conf, "%02u-fuzz.conf", n) < 0)
                return;

        write_new_file(dropin_fd, conf, content);
}

static void add_preset(
                const char *root,
                bool global,
                bool initrd,
                const uint8_t *payload,
                size_t len,
                unsigned n) {

        _cleanup_close_ int dir_fd = -EBADF;
        _cleanup_free_ char *content = NULL, *fn = NULL;

        content = memdup_suffix0(payload, len);
        if (!content)
                return;

        dir_fd = open_dir(root, preset_dir(global, initrd));
        if (dir_fd < 0)
                return;

        if (asprintf(&fn, "%02u-fuzz.preset", n) < 0)
                return;

        write_new_file(dir_fd, fn, content);
}

static bool symlink_target_ok(const char *target, bool global) {
        const char *e;

        /* Only targets that are meaningful for install.c, which resolves them below the root */
        if (filename_is_valid(target) || streq(target, "/dev/null"))
                return true;

        e = path_startswith(target, "/");
        if (!e)
                return false;

        for (unsigned i = 0; i < 3; i++) {
                const char *f = path_startswith(e, unit_dirs[global][i]);
                if (f && filename_is_valid(f))
                        return true;
        }

        return false;
}

static void add_symlink(const char *root, bool global, const uint8_t *payload, size_t len, unsigned n) {
        _cleanup_close_ int dir_fd = -EBADF;
        _cleanup_free_ char *name = NULL;
        const char *target;

        if (split_payload(payload, len, &name, &target) < 0)
                return;

        /* Only unit names as symlink names: install.c never uses those as directories, so the kernel never
         * resolves a path through one of our symlinks (whose absolute targets would point outside the
         * root if not resolved by install.c's root-aware chase()). */
        if (!unit_name_is_valid(name, UNIT_NAME_ANY) || !symlink_target_ok(target, global))
                return;

        dir_fd = open_dir(root, unit_dirs[global][n % 2 == 0 ? 1 : 0]);
        if (dir_fd < 0)
                return;

        (void) symlinkat(target, dir_fd, name);
}

static void verify_alias(const uint8_t *payload, size_t len) {
        _cleanup_free_ char *name = NULL, *dst = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *alias;

        if (split_payload(payload, len, &name, &alias) < 0)
                return;

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return;

        InstallInfo info = {
                .name = name,
        };

        (void) unit_file_verify_alias(&info, alias, &dst, &changes, &n_changes);
        install_changes_free(changes, n_changes);
}

/* Splits at newlines without any unquoting or escape processing, keeping empty lines */
static int split_lines(const char *s, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;

        for (const char *p = s;;) {
                const char *nl = strchrnul(p, '\n');

                if (strv_consume(&l, strndup(p, nl - p)) < 0)
                        return -ENOMEM;
                if (!*nl)
                        break;
                p = nl + 1;
        }

        *ret = TAKE_PTR(l);
        return 0;
}

static int parse_op(const uint8_t *payload, size_t len, Op *ret) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *s = NULL;

        if (len < 2)
                return -EINVAL;

        s = memdup_suffix0(payload + 2, len - 2);
        if (!s)
                return -ENOMEM;

        if (split_lines(s, &l) < 0)
                return -ENOMEM;
        strv_remove(l, "");

        /* Only unit names, never paths: unit_file_enable() and friends accept paths of unit files to link,
         * and those would be read from outside of the root */
        STRV_FOREACH(i, l)
                if (!unit_name_is_valid(*i, UNIT_NAME_ANY))
                        return -EINVAL;

        *ret = (Op) {
                .op = payload[0],
                .flags = payload[1],
                .names = TAKE_PTR(l),
        };
        return 0;
}

/* For "systemctl link": creates /opt/<name> below the root for each name, and returns those paths. The
 * content is copied from the vendor unit file of that name (never following a symlink), if there is one. */
static char** make_link_files(RuntimeScope scope, const char *root, char * const *names) {
        bool global = scope == RUNTIME_SCOPE_GLOBAL;
        _cleanup_close_ int vendor_fd = -EBADF, opt_fd = -EBADF;
        _cleanup_strv_free_ char **paths = NULL;

        vendor_fd = open_dir(root, unit_dirs[global][0]);
        opt_fd = open_dir(root, "opt");
        if (vendor_fd < 0 || opt_fd < 0)
                return NULL;

        STRV_FOREACH(name, names) {
                _cleanup_free_ char *content = NULL;
                _cleanup_close_ int fd = -EBADF;

                fd = openat(vendor_fd, *name, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
                if (fd >= 0) {
                        _cleanup_fclose_ FILE *f = take_fdopen(&fd, "r");
                        if (f)
                                (void) read_full_stream(f, &content, /* ret_size= */ NULL);
                }

                write_new_file(opt_fd, *name,
                               content ?: "[Install]\nWantedBy=multi-user.target\nAlias=linked-alias.service\n");

                if (strv_consume(&paths, path_join("/opt", *name)) < 0)
                        return NULL;
        }

        return TAKE_PTR(paths);
}

static void run_op(const Op *op, RuntimeScope scope, const char *root) {
        static const UnitFilePresetMode preset_modes[] = {
                UNIT_FILE_PRESET_FULL,
                UNIT_FILE_PRESET_ENABLE_ONLY,
                UNIT_FILE_PRESET_DISABLE_ONLY,
        };
        static const UnitDependency deps[] = { UNIT_WANTS, UNIT_REQUIRES }; /* the only ones it supports */
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileFlags flags = 0;
        UnitFileState state;

        if (FLAGS_SET(op->flags, 1 << 0))
                flags |= UNIT_FILE_RUNTIME;
        if (FLAGS_SET(op->flags, 1 << 1))
                flags |= UNIT_FILE_FORCE;
        if (FLAGS_SET(op->flags, 1 << 2))
                flags |= UNIT_FILE_DRY_RUN;
        if (FLAGS_SET(op->flags, 1 << 3))
                flags |= UNIT_FILE_IGNORE_AUXILIARY_FAILURE;
        if (FLAGS_SET(op->op, 1 << 4))
                flags |= UNIT_FILE_VENDOR;
        if (FLAGS_SET(op->op, 1 << 5))
                flags |= UNIT_FILE_PORTABLE;

        UnitFilePresetMode mode = preset_modes[(op->flags >> 4) % ELEMENTSOF(preset_modes)];
        const char *verb = NULL;
        int r = 0;

        switch (op->op & 0x0f) {
        case 0:
                verb = "enable";
                r = unit_file_enable(scope, flags, root, op->names, &changes, &n_changes);
                break;
        case 1:
                verb = "disable";
                r = unit_file_disable(scope, flags, root, op->names, &changes, &n_changes);
                break;
        case 2:
                verb = "reenable";
                r = unit_file_reenable(scope, flags, root, op->names, &changes, &n_changes);
                break;
        case 3:
                verb = "preset";
                r = unit_file_preset(scope, flags, root, op->names, mode, &changes, &n_changes);
                break;
        case 4:
                verb = "preset";
                r = unit_file_preset_all(scope, flags, root, mode, &changes, &n_changes);
                break;
        case 5:
                verb = "mask";
                r = unit_file_mask(scope, flags, root, op->names, &changes, &n_changes);
                break;
        case 6:
                verb = "unmask";
                r = unit_file_unmask(scope, flags, root, op->names, &changes, &n_changes);
                break;
        case 7:
                verb = "revert";
                r = unit_file_revert(scope, root, op->names, &changes, &n_changes);
                break;
        case 8:
                verb = "set default";
                if (!strv_isempty(op->names))
                        r = unit_file_set_default(scope, flags, root, op->names[0], &changes, &n_changes);
                break;
        case 9: {
                _cleanup_free_ char *def = NULL;
                (void) unit_file_get_default(scope, root, &def);
                break;
        }
        case 10:
                verb = "add dependency on";
                if (strv_length(op->names) >= 2)
                        r = unit_file_add_dependency(scope, flags, root, op->names + 1, op->names[0],
                                                     deps[(op->flags >> 4) % ELEMENTSOF(deps)],
                                                     &changes, &n_changes);
                break;
        case 11:
                STRV_FOREACH(i, op->names)
                        (void) unit_file_get_state(scope, root, *i, &state);
                break;
        case 12: {
                _cleanup_hashmap_free_ Hashmap *h = NULL;
                (void) unit_file_get_list(scope, root, /* states= */ NULL, op->names, &h);
                break;
        }
        case 13: {
                _cleanup_(unit_file_presets_done) UnitFilePresets presets = {};
                STRV_FOREACH(i, op->names)
                        (void) unit_file_query_preset(scope, root, *i, &presets);
                break;
        }
        case 14: {
                _cleanup_strv_free_ char **paths = make_link_files(scope, root, op->names);

                verb = "link";
                if (paths)
                        r = unit_file_link(scope, flags, root, paths, &changes, &n_changes);
                break;
        }
        case 15: {
                _cleanup_(lookup_paths_done) LookupPaths lp = {};

                if (lookup_paths_init(&lp, scope, /* flags= */ 0, root) < 0)
                        break;

                /* install.c itself passes various combinations of the SEARCH_* flags */
                STRV_FOREACH(i, op->names) {
                        _cleanup_free_ char *path = NULL;

                        (void) unit_file_exists_full(scope, &lp, (SearchFlags) (op->flags & 0x0f), *i, &path);
                }
                break;
        }
        }

        if (verb)
                (void) install_changes_dump(r, verb, changes, n_changes, /* quiet= */ !FLAGS_SET(op->op, 1 << 6));

        install_changes_free(changes, n_changes);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        Op ops[MAX_OPS] = {};
        size_t n_ops = 0;
        const uint8_t *p, *e;
        RuntimeScope scope;
        bool global, initrd;
        unsigned n = 0;

        if (outside_size_range(size, 1, 64 * 1024))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        global = FLAGS_SET(data[0], 1 << 0);
        initrd = !global && FLAGS_SET(data[0], 1 << 1);
        scope = global ? RUNTIME_SCOPE_GLOBAL : RUNTIME_SCOPE_SYSTEM;

        root = make_root(global, initrd);

        /* First create all files, then run the operations */
        p = data + 1;
        e = data + size;
        while (e - p >= 3 && n++ < MAX_RECORDS) {
                size_t len = MIN((size_t) unaligned_read_le16(p + 1), (size_t) (e - p - 3));
                const uint8_t *payload = p + 3;
                uint8_t type = p[0] % 8;

                p += 3 + len;

                switch (type) {
                case 0 ... 2:
                        add_file(root, global, type, payload, len);
                        break;
                case 3:
                        add_dropin(root, global, payload, len, n);
                        break;
                case 4:
                        add_preset(root, global, initrd, payload, len, n);
                        break;
                case 5:
                        add_symlink(root, global, payload, len, n);
                        break;
                case 6:
                        if (n_ops < MAX_OPS && parse_op(payload, len, ops + n_ops) >= 0)
                                n_ops++;
                        break;
                case 7:
                        verify_alias(payload, len);
                        break;
                }
        }

        FOREACH_ARRAY(op, ops, n_ops) {
                run_op(op, scope, root);
                op->names = strv_free(op->names);
        }

        return 0;
}
