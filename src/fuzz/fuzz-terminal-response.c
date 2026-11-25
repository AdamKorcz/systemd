/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the parsing of the replies to the queries systemd sends to terminals: the ANSI sequence
 * parser (ansi-seq.c) on its own, and the queries of terminal-util.c — terminal_get_cursor_position(),
 * terminal_query() (text area size, cursor position, terminfo name, DA1), terminal_fix_size() and
 * get_default_background_color(). Whatever sits at the other end of the terminal (a terminal emulator, a
 * serial console peer, a VM host) generates these replies.
 *
 * The queries run on a pty pair. A thread plays the terminal: it waits for the query and answers it with
 * the input, followed by a valid reply, so that no query has to wait for its timeout.
 *
 * Input: byte 0 bit 0 selects the queries; otherwise the input goes to the ANSI sequence parser, with
 * (bit 1) or without capturing the sequences, through ansi_seq_parser_feed_harder() (bit 2) or
 * ansi_seq_parser_feed(). The rest of the input is the reply. */

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <termios.h>
#include <unistd.h>

#include "ansi-seq.h"
#include "fd-util.h"
#include "fuzz.h"
#include "io-util.h"
#include "terminal-util.h"
#include "tests.h"

static void fuzz_ansi_seq(const uint8_t *data, size_t size, bool capture, bool harder) {
        _cleanup_(ansi_seq_parser_done) AnsiSeqParser p = {
                .capture = capture,
        };

        for (size_t i = 0; i < size; i++) {
                int r;

                if (harder)
                        r = ansi_seq_parser_feed_harder(&p, (char) data[i]);
                else {
                        /* A character that ended a sequence by aborting it has to be fed again */
                        r = ansi_seq_parser_feed(&p, (char) data[i]);
                        if (r >= 0 && ANSI_SEQ_EVENT_NEEDS_REFEED(r))
                                r = ansi_seq_parser_feed(&p, (char) data[i]);
                }
                if (r < 0)
                        return;

                if (r == ANSI_SEQ_EVENT_END)
                        DO_NOT_OPTIMIZE(ansi_seq_parser_string(&p));
        }
}

/* The terminal end of a pty pair: answers the first query that arrives with the reply and the terminator */
typedef struct FakeTerminal {
        int master, slave;
        int stop[2];
        const uint8_t *reply;
        size_t reply_size;
        const char *terminator;
        pthread_t thread;
} FakeTerminal;

static void* fake_terminal_thread(void *userdata) {
        FakeTerminal *t = ASSERT_PTR(userdata);
        struct pollfd pfd[] = {
                { .fd = t->master,  .events = POLLIN },
                { .fd = t->stop[0], .events = POLLIN },
        };
        char buf[256];

        /* Until the query arrives, or the caller gives up without sending one */
        if (poll(pfd, ELEMENTSOF(pfd), -1) < 0 || !FLAGS_SET(pfd[0].revents, POLLIN))
                return NULL;

        while (read(t->master, buf, sizeof(buf)) > 0)
                ;

        (void) loop_write(t->master, t->reply, t->reply_size);
        (void) loop_write(t->master, t->terminator, SIZE_MAX);
        return NULL;
}

static int fake_terminal_start(FakeTerminal *t, const uint8_t *reply, size_t size, const char *terminator) {
        _cleanup_close_ int master = -EBADF, slave = -EBADF;
        _cleanup_close_pair_ int stop[2] = EBADF_PAIR;
        struct termios ts;
        int r;

        master = openpt_allocate(O_RDWR|O_NONBLOCK, /* ret_peer_path= */ NULL);
        if (master < 0)
                return master;

        slave = pty_open_peer(master, O_RDWR|O_NOCTTY);
        if (slave < 0)
                return slave;

        /* Raw mode before anything arrives, so that the reply isn't held back in the line buffer */
        if (tcgetattr(slave, &ts) < 0)
                return -errno;
        cfmakeraw(&ts);
        if (tcsetattr(slave, TCSANOW, &ts) < 0)
                return -errno;

        if (pipe2(stop, O_CLOEXEC) < 0)
                return -errno;

        *t = (FakeTerminal) {
                .master = TAKE_FD(master),
                .slave = TAKE_FD(slave),
                .stop = { TAKE_FD(stop[0]), TAKE_FD(stop[1]) },
                .reply = reply,
                .reply_size = size,
                .terminator = terminator,
        };

        r = -pthread_create(&t->thread, /* attr= */ NULL, fake_terminal_thread, t);
        if (r < 0) {
                safe_close(t->master);
                safe_close(t->slave);
                safe_close_pair(t->stop);
                return r;
        }

        return 0;
}

static void fake_terminal_stop(FakeTerminal *t) {
        ASSERT_OK_ERRNO(write(t->stop[1], "x", 1));
        ASSERT_EQ(pthread_join(t->thread, /* retval= */ NULL), 0);

        safe_close(t->master);
        safe_close(t->slave);
        safe_close_pair(t->stop);
}

static void fuzz_queries(const uint8_t *data, size_t size) {
        /* Each reply is followed by a character that ends whatever state the reply may have left the parser
         * in (ST ends string sequences, 't' and 'R' CSI sequences), and by the reply the query waits for
         * last: the cursor position (DSR) when the size is queried, DA1 otherwise. */
        static const struct {
                bool size, terminfo;
                const char *terminator;
        } queries[] = {
                { true,  false, ANSI_ST "t\x1B[24;80R"              },
                { false, true,  ANSI_ST "t\x1B[?c"                  },
                { true,  true,  ANSI_ST "t\x1B[8;24;80t\x1B[24;80R" },
        };
        unsigned row, column;
        double red, green, blue;
        FakeTerminal t;

        if (fake_terminal_start(&t, data, size, "R\x1B[1;1R") < 0)
                return;
        (void) terminal_get_cursor_position(t.slave, t.slave, &row, &column);
        fake_terminal_stop(&t);

        FOREACH_ELEMENT(q, queries) {
                _cleanup_free_ char *terminfo = NULL;

                if (fake_terminal_start(&t, data, size, q->terminator) < 0)
                        return;
                (void) terminal_query(t.slave, t.slave,
                                      q->size ? &row : NULL,
                                      q->size ? &column : NULL,
                                      q->terminfo ? &terminfo : NULL);
                fake_terminal_stop(&t);
        }

        /* Queries the size, and then sets it for the pty */
        if (fake_terminal_start(&t, data, size, queries[0].terminator) < 0)
                return;
        (void) terminal_fix_size(t.slave, t.slave);
        fake_terminal_stop(&t);

        /* get_default_background_color() talks to stdin/stdout, which point to the pty meanwhile. BEL ends
         * the OSC sequence. */
        _cleanup_close_ int saved_stdin = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3),
                saved_stdout = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        if (saved_stdin < 0 || saved_stdout < 0)
                return;

        if (fake_terminal_start(&t, data, size, "\a" ANSI_OSC "11;rgb:0/0/0\a") < 0)
                return;

        ASSERT_OK_EQ_ERRNO(dup2(t.slave, STDIN_FILENO), STDIN_FILENO);
        ASSERT_OK_EQ_ERRNO(dup2(t.slave, STDOUT_FILENO), STDOUT_FILENO);

        (void) get_default_background_color(&red, &green, &blue);

        ASSERT_OK_EQ_ERRNO(dup2(saved_stdin, STDIN_FILENO), STDIN_FILENO);
        ASSERT_OK_EQ_ERRNO(dup2(saved_stdout, STDOUT_FILENO), STDOUT_FILENO);

        fake_terminal_stop(&t);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (outside_size_range(size, 1, 4096))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        if (FLAGS_SET(data[0], 1 << 0)) {
                /* The queries are only made if the terminal is not dumb, and the background color only if
                 * colors are enabled */
                ASSERT_OK_ERRNO(setenv("TERM", "xterm-256color", /* overwrite= */ true));
                ASSERT_OK_ERRNO(setenv("SYSTEMD_COLORS", "256", /* overwrite= */ true));

                fuzz_queries(data + 1, MIN(size - 1, 1024u));
        } else
                fuzz_ansi_seq(data + 1, size - 1,
                              /* capture= */ FLAGS_SET(data[0], 1 << 1),
                              /* harder= */ FLAGS_SET(data[0], 1 << 2));

        return 0;
}
