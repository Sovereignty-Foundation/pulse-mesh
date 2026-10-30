/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Copyright (c) 2026 Sovereignty Foundation */
/*
 * smoke.c — C-side smoke test for the pulse-wire-c FFI.
 *
 * Exercises:
 *   1. Pulse field round-trip (set, get, zero), envelope_ref included.
 *   2. UDP loopback round-trip: sender -> receiver, payload and
 *      pulse fields preserved.
 *   3. recv_into into a stack buffer.
 *   4. Error path: too-small buffer surfaces PMS_ERR_BUFFER_TOO_SMALL.
 *   5. Error path: timeout surfaces PMS_ERR_TIMEOUT.
 *   6. Error path: invalid socket address.
 *   7. Destroy is NULL-safe.
 *   8. bind_pair: one socket sends and receives; a reply to the peer
 *      address the receiver saw comes back to it.
 *   9. A shared-memory channel in one process: messages in order, the
 *      size limit, a too-small buffer that leaves the message unread,
 *      timeouts, the wrong end, and the writer's close.
 *  10. A channel between two processes: this binary runs itself as the
 *      reader (`smoke channel-read`) and checks what it printed.
 *
 * With arguments it is one end of a channel, for the test above and for
 * the Python binding's cross-language test (tests/test_channel.py there):
 *
 *   smoke channel-read <name>           open <name>, print each message as
 *                                        a line of hex until the writer
 *                                        closes it, then exit 0
 *   smoke channel-write <name> <hex>... create <name>, send each argument
 *                                        as a message, wait until the
 *                                        reader has read them all, close
 *
 * Build via tests/run.sh from the crate root.
 */

#define _POSIX_C_SOURCE 200809L

#include "pulse_wire.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, msg) do {                                                  \
    if (!(cond)) {                                                             \
        fprintf(stderr, "  FAIL: %s (line %d)\n", msg, __LINE__);              \
        ++failures;                                                            \
    } else {                                                                   \
        fprintf(stderr, "  ok:   %s\n", msg);                                  \
    }                                                                          \
} while (0)

#define CHECK_OK(status, msg) do {                                             \
    pms_status _s = (status);                                                  \
    if (_s != PMS_OK) {                                                        \
        fprintf(stderr, "  FAIL: %s (status=%d, last_error=\"%s\")\n",         \
                msg, (int)_s, pms_last_error());                               \
        ++failures;                                                            \
    } else {                                                                   \
        fprintf(stderr, "  ok:   %s\n", msg);                                  \
    }                                                                          \
} while (0)

static void test_pulse_field_round_trip(void) {
    fprintf(stderr, "[test] pulse field round-trip\n");

    pms_pulse p;
    pms_pulse_zero(&p);

    CHECK(pms_pulse_get_instruction(&p) == 0, "zero -> instruction is 0");
    CHECK(pms_pulse_get_scope(&p) == 0, "zero -> scope is 0");
    CHECK(pms_pulse_get_monotonic_nanos(&p) == 0, "zero -> mono_nanos is 0");

    pms_pulse_set_instruction(&p, 0x0010); /* DATA */
    pms_pulse_set_scope(&p, 0xDEADBEEFu);
    pms_pulse_set_monotonic_nanos(&p, 1234567890ull);
    pms_pulse_set_chain_step(&p, 99ull);

    CHECK(pms_pulse_get_instruction(&p) == 0x0010, "instruction round-trip");
    CHECK(pms_pulse_get_scope(&p) == 0xDEADBEEFu, "scope round-trip");
    CHECK(pms_pulse_get_monotonic_nanos(&p) == 1234567890ull, "mono_nanos round-trip");
    CHECK(pms_pulse_get_chain_step(&p) == 99ull, "chain_step round-trip");

    uint8_t origin_in[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };
    pms_pulse_set_origin_id(&p, origin_in);
    uint8_t origin_out[16] = {0};
    pms_pulse_get_origin_id(&p, origin_out);
    CHECK(memcmp(origin_in, origin_out, 16) == 0, "origin_id round-trip");

    uint8_t ref_out[16] = {0};
    pms_pulse_get_envelope_ref(&p, ref_out);
    static const uint8_t zeros[16] = {0};
    CHECK(memcmp(ref_out, zeros, 16) == 0, "zero -> envelope_ref is zeros");
    uint8_t ref_in[16];
    for (int i = 0; i < 16; ++i) { ref_in[i] = (uint8_t)(0xF0 + i); }
    pms_pulse_set_envelope_ref(&p, ref_in);
    pms_pulse_get_envelope_ref(&p, ref_out);
    CHECK(memcmp(ref_in, ref_out, 16) == 0, "envelope_ref round-trip");
    /* envelope_ref sits at bytes 48..64 of the wire layout. */
    CHECK(memcmp(p.bytes + 48, ref_in, 16) == 0, "envelope_ref at offset 48");
    CHECK(memcmp(origin_in, origin_out, 16) == 0
          && pms_pulse_get_scope(&p) == 0xDEADBEEFu
          && pms_pulse_get_instruction(&p) == 0x0010,
          "setting envelope_ref leaves the other fields");
    pms_pulse_set_envelope_ref(NULL, ref_in);
    pms_pulse_get_envelope_ref(NULL, ref_out);
    pms_pulse_set_envelope_ref(&p, NULL);
    pms_pulse_get_envelope_ref(&p, NULL);
    CHECK(1, "envelope_ref accessors are NULL-safe");
}

static void test_loopback_round_trip(void) {
    fprintf(stderr, "[test] loopback round-trip\n");

    pms_receiver* recv = NULL;
    CHECK_OK(pms_receiver_bind("127.0.0.1:0", &recv), "receiver bind");
    if (!recv) { return; }
    CHECK_OK(pms_receiver_set_read_timeout_ms(recv, 2000), "set read timeout");

    char recv_addr[64] = {0};
    CHECK_OK(pms_receiver_local_addr(recv, recv_addr, sizeof(recv_addr)),
             "receiver local_addr");

    pms_sender* send = NULL;
    CHECK_OK(pms_sender_bind("127.0.0.1:0", &send), "sender bind");
    if (!send) { pms_receiver_destroy(recv); return; }
    CHECK_OK(pms_sender_connect(send, recv_addr), "sender connect");

    pms_pulse out_pulse;
    pms_pulse_zero(&out_pulse);
    pms_pulse_set_instruction(&out_pulse, 0x0010);
    pms_pulse_set_scope(&out_pulse, 42u);
    pms_pulse_set_monotonic_nanos(&out_pulse, 7777ull);

    const uint8_t payload[] = "hello from C smoke test";
    const size_t payload_len = sizeof(payload) - 1; /* drop NUL terminator */

    uint64_t sent_seq = UINT64_MAX;
    CHECK_OK(pms_sender_send(send, 12345ull, &out_pulse, payload, payload_len, &sent_seq),
             "send returned PMS_OK");
    CHECK(sent_seq == 0, "first send seq is 0");

    uint8_t in_buf[1500] = {0};
    pms_pulse in_pulse;
    pms_pulse_zero(&in_pulse);
    size_t in_len = 0;
    uint64_t in_seq = 0;
    uint64_t in_send_ns = 0;
    char peer[64] = {0};

    CHECK_OK(pms_receiver_recv_into(recv, in_buf, sizeof(in_buf),
                                    &in_pulse, &in_len, &in_seq, &in_send_ns,
                                    peer, sizeof(peer)),
             "recv_into returned PMS_OK");
    CHECK(in_len == payload_len, "envelope length matches");
    CHECK(memcmp(in_buf, payload, payload_len) == 0, "envelope bytes match");
    CHECK(pms_pulse_get_scope(&in_pulse) == 42u, "received pulse scope matches");
    CHECK(pms_pulse_get_monotonic_nanos(&in_pulse) == 7777ull,
          "received pulse mono_nanos matches");
    CHECK(in_seq == 0, "received seq is 0");
    CHECK(in_send_ns == 12345ull, "received send_ns matches");
    CHECK(strlen(peer) > 0, "peer string non-empty");

    pms_sender_destroy(send);
    pms_receiver_destroy(recv);
}

static void test_buffer_too_small(void) {
    fprintf(stderr, "[test] buffer-too-small surfaces PMS_ERR_BUFFER_TOO_SMALL\n");

    pms_receiver* recv = NULL;
    pms_receiver_bind("127.0.0.1:0", &recv);
    pms_receiver_set_read_timeout_ms(recv, 2000);

    char recv_addr[64];
    pms_receiver_local_addr(recv, recv_addr, sizeof(recv_addr));

    pms_sender* send = NULL;
    pms_sender_bind("127.0.0.1:0", &send);
    pms_sender_connect(send, recv_addr);

    pms_pulse p;
    pms_pulse_zero(&p);
    pms_pulse_set_instruction(&p, 0x0010);

    uint8_t payload[200];
    memset(payload, 0xAA, sizeof(payload));
    pms_sender_send(send, 0, &p, payload, sizeof(payload), NULL);

    uint8_t small[50];
    pms_pulse pp;
    pms_pulse_zero(&pp);
    size_t got_len = 0;
    pms_status status = pms_receiver_recv_into(recv, small, sizeof(small),
                                                &pp, &got_len, NULL, NULL,
                                                NULL, 0);
    CHECK(status == PMS_ERR_BUFFER_TOO_SMALL,
          "buffer-too-small status returned");
    CHECK(strstr(pms_last_error(), "buffer too small") != NULL
          || strstr(pms_last_error(), "envelope buffer too small") != NULL,
          "last_error mentions buffer-too-small");

    pms_sender_destroy(send);
    pms_receiver_destroy(recv);
}

static void test_recv_timeout(void) {
    fprintf(stderr, "[test] recv timeout surfaces PMS_ERR_TIMEOUT\n");

    pms_receiver* recv = NULL;
    pms_receiver_bind("127.0.0.1:0", &recv);
    pms_receiver_set_read_timeout_ms(recv, 50); /* 50 ms */

    uint8_t buf[1500];
    pms_pulse pp;
    pms_pulse_zero(&pp);
    size_t n = 0;
    pms_status status = pms_receiver_recv_into(recv, buf, sizeof(buf),
                                                &pp, &n, NULL, NULL, NULL, 0);
    CHECK(status == PMS_ERR_TIMEOUT, "timeout status returned");

    pms_receiver_destroy(recv);
}

static void test_invalid_address(void) {
    fprintf(stderr, "[test] invalid socket address rejected\n");

    pms_sender* send = NULL;
    pms_status status = pms_sender_bind("not-an-address", &send);
    CHECK(status != PMS_OK, "bad address returns non-OK");
    CHECK(send == NULL, "sender out-pointer left NULL on failure");
    CHECK(strlen(pms_last_error()) > 0, "last_error is populated");
}

static void test_null_safe_destroy(void) {
    fprintf(stderr, "[test] destroy is NULL-safe\n");
    pms_sender_destroy(NULL);
    pms_receiver_destroy(NULL);
    fprintf(stderr, "  ok:   no crash\n");
}

static void test_constants_match(void) {
    fprintf(stderr, "[test] exported constants\n");
    CHECK(PMS_PULSE_WIRE_SIZE == 128, "PMS_PULSE_WIRE_SIZE == 128");
    CHECK(PMS_MAX_ENVELOPE == 1315, "PMS_MAX_ENVELOPE == 1315");
    CHECK(PMS_HEADER_BYTES == 153, "PMS_HEADER_BYTES == 153");
    CHECK(sizeof(pms_pulse) == 128, "sizeof(pms_pulse) == 128");
}

/* ───────────────────────────── bind_pair ───────────────────────────── */

static void test_bind_pair_round_trip(void) {
    fprintf(stderr, "[test] bind_pair: one socket sends and receives\n");

    pms_sender* a_tx = NULL;
    pms_receiver* a_rx = NULL;
    pms_sender* b_tx = NULL;
    pms_receiver* b_rx = NULL;
    CHECK_OK(pms_bind_pair("127.0.0.1:0", &a_tx, &a_rx), "pair A bound");
    CHECK_OK(pms_bind_pair("127.0.0.1:0", &b_tx, &b_rx), "pair B bound");
    if (a_tx && a_rx && b_tx && b_rx) {
        char a_send[64] = {0};
        char a_recv[64] = {0};
        char b_addr[64] = {0};
        pms_sender_local_addr(a_tx, a_send, sizeof(a_send));
        pms_receiver_local_addr(a_rx, a_recv, sizeof(a_recv));
        pms_receiver_local_addr(b_rx, b_addr, sizeof(b_addr));
        CHECK(strcmp(a_send, a_recv) == 0, "the pair's sender and receiver share one port");
        pms_receiver_set_read_timeout_ms(a_rx, 2000);
        pms_receiver_set_read_timeout_ms(b_rx, 2000);

        pms_pulse p;
        pms_pulse_zero(&p);
        pms_pulse_set_instruction(&p, 0x0010);
        const unsigned char task[] = "task";
        CHECK_OK(pms_sender_send_to(a_tx, 1, &p, task, 4, b_addr, NULL), "A sends to B");

        unsigned char buf[64];
        size_t n = 0;
        char peer[64] = {0};
        pms_pulse got;
        CHECK_OK(pms_receiver_recv_into(b_rx, buf, sizeof(buf), &got, &n, NULL, NULL,
                                        peer, sizeof(peer)),
                 "B receives");
        CHECK(n == 4 && memcmp(buf, task, 4) == 0, "B got the task");
        CHECK(strcmp(peer, a_send) == 0, "B saw it come from A's one port");

        const unsigned char reply[] = "reply";
        CHECK_OK(pms_sender_send_to(b_tx, 2, &p, reply, 5, peer, NULL),
                 "B replies to the address it saw");
        n = 0;
        CHECK_OK(pms_receiver_recv_into(a_rx, buf, sizeof(buf), &got, &n, NULL, NULL, NULL, 0),
                 "A's receiver hears the reply");
        CHECK(n == 5 && memcmp(buf, reply, 5) == 0, "A got the reply");
    }
    pms_sender_destroy(a_tx);
    pms_receiver_destroy(a_rx);
    pms_sender_destroy(b_tx);
    pms_receiver_destroy(b_rx);

    pms_sender* bad_tx = NULL;
    pms_receiver* bad_rx = NULL;
    CHECK(pms_bind_pair("not-an-address", &bad_tx, &bad_rx) != PMS_OK
          && bad_tx == NULL && bad_rx == NULL,
          "bad address: an error and neither handle written");
    CHECK(pms_bind_pair(NULL, &bad_tx, &bad_rx) == PMS_ERR_INVALID_ARG,
          "NULL address: PMS_ERR_INVALID_ARG");
    CHECK(pms_bind_pair("127.0.0.1:0", NULL, &bad_rx) == PMS_ERR_INVALID_ARG,
          "NULL out-pointer: PMS_ERR_INVALID_ARG");
}

/* ────────────────────────────── channels ────────────────────────────── */

static void sleep_ms(long ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1e6;
}

/* A fresh, short channel name: the store's name, the channel's plus "-e",
 * must fit macOS's 31-byte shared-memory name limit. */
static void channel_name(char* out, size_t len) {
    static int count = 0;
    snprintf(out, len, "pwc%d-%d", (int)(getpid() % 100000), ++count);
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/* `smoke channel-read <name>`: print each message as a line of hex until
 * the writer closes the channel. The buffer starts small and grows to the
 * length PMS_ERR_BUFFER_TOO_SMALL reports, the message waiting meanwhile. */
static int channel_read(const char* name) {
    pms_channel* rx = NULL;
    if (pms_channel_open(name, &rx) != PMS_OK) {
        fprintf(stderr, "channel-read: %s\n", pms_last_error());
        return 1;
    }
    size_t cap = 16;
    unsigned char* buf = malloc(cap);
    int rc = buf ? 0 : 1;
    while (rc == 0) {
        size_t n = 0;
        pms_status s = pms_channel_recv(rx, buf, cap, &n, 10000);
        if (s == PMS_ERR_BUFFER_TOO_SMALL) {
            unsigned char* bigger = realloc(buf, n);
            if (!bigger) { rc = 1; break; }
            buf = bigger;
            cap = n;
            continue;
        }
        if (s == PMS_ERR_CLOSED) { break; }
        if (s != PMS_OK) {
            fprintf(stderr, "channel-read: status %d: %s\n", (int)s, pms_last_error());
            rc = 1;
            break;
        }
        for (size_t i = 0; i < n; ++i) { printf("%02x", buf[i]); }
        putchar('\n');
    }
    fflush(stdout);
    free(buf);
    pms_channel_close(rx);
    return rc;
}

/* `smoke channel-write <name> <hex>...`: send each argument as a message,
 * then wait (up to 10 s) until the reader has read them all before the
 * close removes the channel's names, so a reader that attaches late still
 * finds it. */
static int channel_write(const char* name, int count, char** hex) {
    pms_channel* tx = NULL;
    if (pms_channel_create(name, 64, 16, &tx) != PMS_OK) {
        fprintf(stderr, "channel-write: %s\n", pms_last_error());
        return 1;
    }
    int rc = 0;
    for (int i = 0; i < count && rc == 0; ++i) {
        size_t digits = strlen(hex[i]);
        size_t len = digits / 2;
        unsigned char* msg = malloc(len ? len : 1);
        if (!msg || digits % 2 != 0) {
            fprintf(stderr, "channel-write: argument %d is not hex bytes\n", i + 1);
            free(msg);
            rc = 2;
            break;
        }
        for (size_t j = 0; j < len && rc == 0; ++j) {
            int hi = hex_digit(hex[i][2 * j]);
            int lo = hex_digit(hex[i][2 * j + 1]);
            if (hi < 0 || lo < 0) {
                fprintf(stderr, "channel-write: argument %d is not hex bytes\n", i + 1);
                rc = 2;
            }
            msg[j] = (unsigned char)(hi * 16 + lo);
        }
        if (rc == 0 && pms_channel_send(tx, msg, len) != PMS_OK) {
            fprintf(stderr, "channel-write: %s\n", pms_last_error());
            rc = 1;
        }
        free(msg);
    }
    for (int waited = 0; rc == 0 && pms_channel_pending(tx) > 0; ++waited) {
        if (waited >= 10000) {
            fprintf(stderr, "channel-write: the reader left %llu messages unread\n",
                    (unsigned long long)pms_channel_pending(tx));
            rc = 1;
            break;
        }
        sleep_ms(1);
    }
    pms_channel_close(tx);
    return rc;
}

static void test_channel_one_process(void) {
    fprintf(stderr, "[test] channel in one process\n");

    char name[32];
    channel_name(name, sizeof(name));
    pms_channel* tx = NULL;
    pms_channel* rx = NULL;
    CHECK_OK(pms_channel_create(name, 8, 4, &tx), "create the writer end");
    CHECK_OK(pms_channel_open(name, &rx), "open the reader end");
    if (!tx || !rx) {
        pms_channel_close(rx);
        pms_channel_close(tx);
        return;
    }

    const char* msgs[] = { "first", "", "third message" };
    for (int i = 0; i < 3; ++i) {
        CHECK_OK(pms_channel_send(tx, (const unsigned char*)msgs[i], strlen(msgs[i])),
                 "send a message");
    }
    CHECK(pms_channel_pending(tx) == 3, "three messages pending");
    unsigned char buf[64];
    size_t n = 0;
    for (int i = 0; i < 3; ++i) {
        n = 999;
        CHECK_OK(pms_channel_recv(rx, buf, sizeof(buf), &n, 1000), "recv a message");
        CHECK(n == strlen(msgs[i]) && memcmp(buf, msgs[i], n) == 0, "messages arrive in order, intact");
    }
    CHECK(pms_channel_pending(tx) == 0, "none pending once read");

    CHECK(pms_channel_recv(rx, buf, sizeof(buf), &n, 0) == PMS_ERR_TIMEOUT,
          "nothing waiting, timeout 0: PMS_ERR_TIMEOUT at once");
    double t0 = now_ms();
    CHECK(pms_channel_recv(rx, buf, sizeof(buf), &n, 50) == PMS_ERR_TIMEOUT,
          "nothing waiting, timeout 50 ms: PMS_ERR_TIMEOUT");
    double waited = now_ms() - t0;
    CHECK(waited >= 45.0 && waited < 1000.0, "the 50 ms wait took about 50 ms");

    const char* big = "a message longer than the eight-byte buffer";
    const size_t big_len = strlen(big);
    CHECK_OK(pms_channel_send(tx, (const unsigned char*)big, big_len), "send a long message");
    unsigned char small[8];
    n = 0;
    CHECK(pms_channel_recv(rx, small, sizeof(small), &n, 1000) == PMS_ERR_BUFFER_TOO_SMALL
          && n == big_len,
          "too-small buffer: PMS_ERR_BUFFER_TOO_SMALL with the length needed");
    n = 0;
    CHECK(pms_channel_recv(rx, NULL, 0, &n, 0) == PMS_ERR_BUFFER_TOO_SMALL && n == big_len,
          "a NULL buffer of 0 bytes learns the length");
    CHECK(PMS_CHANNEL_WAIT_FOREVER == UINT32_MAX, "PMS_CHANNEL_WAIT_FOREVER == UINT32_MAX");
    CHECK_OK(pms_channel_recv(rx, buf, sizeof(buf), &n, PMS_CHANNEL_WAIT_FOREVER),
             "retry with room, waiting without limit");
    CHECK(n == big_len && memcmp(buf, big, big_len) == 0, "the message waited and arrives whole");

    const size_t max = pms_channel_max_len();
    CHECK(max > 65000 && max < 65536, "pms_channel_max_len is just under 64 KB");
    unsigned char* huge = malloc(max + 1);
    unsigned char* back = malloc(max);
    if (huge && back) {
        for (size_t i = 0; i <= max; ++i) { huge[i] = (unsigned char)(i * 31); }
        CHECK_OK(pms_channel_send(tx, huge, max), "send pms_channel_max_len() bytes");
        CHECK(pms_channel_send(tx, huge, max + 1) == PMS_ERR_ENVELOPE_TOO_LARGE,
              "one byte more: PMS_ERR_ENVELOPE_TOO_LARGE");
        CHECK_OK(pms_channel_recv(rx, back, max, &n, 1000), "recv the largest message");
        CHECK(n == max && memcmp(back, huge, max) == 0, "the largest message is intact");
        CHECK(pms_channel_recv(rx, buf, sizeof(buf), &n, 0) == PMS_ERR_TIMEOUT,
              "the message too large was not sent");
    }
    free(huge);
    free(back);

    CHECK(pms_channel_send(rx, (const unsigned char*)"x", 1) == PMS_ERR_INVALID_ARG,
          "send on the reader end: PMS_ERR_INVALID_ARG");
    CHECK(pms_channel_recv(tx, buf, sizeof(buf), &n, 0) == PMS_ERR_INVALID_ARG,
          "recv on the writer end: PMS_ERR_INVALID_ARG");
    CHECK(pms_channel_recv(rx, NULL, 8, &n, 0) == PMS_ERR_INVALID_ARG,
          "NULL buffer with a capacity: PMS_ERR_INVALID_ARG");
    pms_channel* bad = NULL;
    CHECK(pms_channel_create("a/b", 8, 8, &bad) == PMS_ERR_INVALID_ARG && bad == NULL,
          "a name with an inner slash: PMS_ERR_INVALID_ARG");
    CHECK(pms_channel_create("xxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 8, 8, &bad) == PMS_ERR_INVALID_ARG
          && strstr(pms_last_error(), "too long") != NULL,
          "a name too long for macOS: PMS_ERR_INVALID_ARG");
    CHECK(pms_channel_create(name, 0, 8, &bad) == PMS_ERR_INVALID_ARG,
          "zero capacity: PMS_ERR_INVALID_ARG");

    /* The window is min(capacity 8, store_slots 4): a fifth unread message
     * waits the 5 s send wait, then is refused with nothing sent. */
    for (int i = 0; i < 4; ++i) {
        unsigned char b = (unsigned char)i;
        CHECK_OK(pms_channel_send(tx, &b, 1), "fill the window");
    }
    t0 = now_ms();
    CHECK(pms_channel_send(tx, (const unsigned char*)"over", 4) == PMS_ERR_TIMEOUT,
          "a full window: PMS_ERR_TIMEOUT");
    waited = now_ms() - t0;
    CHECK(waited >= 4900.0 && waited < 15000.0, "the send waited its 5 s");
    CHECK(pms_channel_pending(tx) == 4, "nothing more was sent");

    pms_channel_close(tx);
    for (int i = 0; i < 4; ++i) {
        CHECK_OK(pms_channel_recv(rx, buf, sizeof(buf), &n, 1000), "after the close, drain");
        CHECK(n == 1 && buf[0] == (unsigned char)i, "the drained message is intact");
    }
    CHECK(pms_channel_recv(rx, buf, sizeof(buf), &n, 1000) == PMS_ERR_CLOSED,
          "then PMS_ERR_CLOSED");
    pms_channel_close(rx);
    pms_channel_close(NULL);
}

static void test_channel_two_processes(const char* self) {
    fprintf(stderr, "[test] channel between two processes\n");

    char name[32];
    channel_name(name, sizeof(name));
    pms_channel* tx = NULL;
    CHECK_OK(pms_channel_create(name, 64, 16, &tx), "create the writer end");
    FILE* out = tmpfile();
    CHECK(out != NULL, "a file for the reader's output");
    if (!tx || !out) {
        pms_channel_close(tx);
        if (out) { fclose(out); }
        return;
    }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fileno(out), STDOUT_FILENO);
        execl(self, self, "channel-read", name, (char*)NULL);
        _exit(127);
    }
    CHECK(pid > 0, "fork the reader");

    /* Lengths 0 to 2999 bytes, most past the reader's first 16-byte
     * buffer, more messages than the 16-message window. */
    enum { COUNT = 400, SPAN = 3000 };
    static unsigned char msg[SPAN];
    int sent = 0;
    for (int i = 0; pid > 0 && i < COUNT; ++i) {
        size_t len = (size_t)(i * 7919) % SPAN;
        for (size_t j = 0; j < len; ++j) { msg[j] = (unsigned char)(i + j); }
        if (pms_channel_send(tx, msg, len) != PMS_OK) {
            fprintf(stderr, "  send %d: %s\n", i, pms_last_error());
            break;
        }
        ++sent;
    }
    CHECK(sent == COUNT, "every message sent");
    for (int ms = 0; pms_channel_pending(tx) > 0 && ms < 10000; ++ms) { sleep_ms(1); }
    CHECK(pms_channel_pending(tx) == 0, "the reader read every message");
    pms_channel_close(tx);

    int status = -1;
    if (pid > 0) { waitpid(pid, &status, 0); }
    CHECK(pid > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "the reader exited 0 on PMS_ERR_CLOSED");

    rewind(out);
    char* line = NULL;
    size_t line_cap = 0;
    int lines = 0;
    int intact = 1;
    while (getline(&line, &line_cap, out) >= 0) {
        size_t len = (size_t)(lines * 7919) % SPAN;
        if (strlen(line) != 2 * len + 1) {
            intact = 0;
        }
        for (size_t j = 0; intact && j < len; ++j) {
            int hi = hex_digit(line[2 * j]);
            int lo = hex_digit(line[2 * j + 1]);
            if (hi * 16 + lo != (unsigned char)(lines + j)) { intact = 0; }
        }
        ++lines;
    }
    free(line);
    fclose(out);
    CHECK(lines == COUNT, "the reader printed one line per message");
    CHECK(intact, "every message arrived in order and intact");
}

int main(int argc, char** argv) {
    if (argc == 3 && strcmp(argv[1], "channel-read") == 0) {
        return channel_read(argv[2]);
    }
    if (argc >= 3 && strcmp(argv[1], "channel-write") == 0) {
        return channel_write(argv[2], argc - 3, argv + 3);
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [channel-read <name> | channel-write <name> <hex>...]\n",
                argv[0]);
        return 2;
    }

    fprintf(stderr, "==== pulse-wire-c smoke test ====\n");
    test_constants_match();
    test_pulse_field_round_trip();
    test_loopback_round_trip();
    test_buffer_too_small();
    test_recv_timeout();
    test_invalid_address();
    test_null_safe_destroy();
    test_bind_pair_round_trip();
    test_channel_one_process();
    test_channel_two_processes(argv[0]);

    fprintf(stderr, "================================\n");
    if (failures == 0) {
        fprintf(stderr, "all smoke tests passed\n");
        return 0;
    } else {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
}
