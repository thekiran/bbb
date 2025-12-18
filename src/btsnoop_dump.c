#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAGIC "btsnoop\0"
#define DLT_HCI_H4 1001

struct btsnoop_hdr {
    uint8_t id[8];
    uint32_t version;
    uint32_t dlt;
} __attribute__((packed));

struct btsnoop_rec_hdr {
    uint32_t orig_len;
    uint32_t inc_len;
    uint32_t flags;
    uint32_t drops;
    uint64_t ts;
} __attribute__((packed));

static const char *ptype_name(uint8_t ptype) {
    switch (ptype) {
    case 0x01:
        return "HCI CMD";
    case 0x02:
        return "ACL";
    case 0x03:
        return "SCO";
    case 0x04:
        return "HCI EVT";
    default:
        return "UNKNOWN";
    }
}

static bool read_all(int fd, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, (uint8_t *)buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hci.btsnoop>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *path = argv[1];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }

    struct btsnoop_hdr hdr;
    if (!read_all(fd, &hdr, sizeof(hdr))) {
        fprintf(stderr, "Failed to read header\n");
        close(fd);
        return EXIT_FAILURE;
    }
    if (memcmp(hdr.id, MAGIC, sizeof(hdr.id)) != 0) {
        fprintf(stderr, "Not a btsnoop file (bad magic)\n");
        close(fd);
        return EXIT_FAILURE;
    }
    uint32_t version = be32toh(hdr.version);
    uint32_t dlt = be32toh(hdr.dlt);
    if (dlt != DLT_HCI_H4) {
        fprintf(stderr, "Unsupported DLT: %u (expected %u)\n", dlt, DLT_HCI_H4);
        close(fd);
        return EXIT_FAILURE;
    }
    printf("btsnoop version=%u dlt=%u (HCI H4)\n", version, dlt);

    struct btsnoop_rec_hdr rec;
    size_t idx = 0;
    while (read_all(fd, &rec, sizeof(rec))) {
        uint32_t inc_len = be32toh(rec.inc_len);
        uint32_t orig_len = be32toh(rec.orig_len);
        uint32_t flags = be32toh(rec.flags);
        uint64_t ts = be64toh(rec.ts);

        uint8_t *payload = malloc(inc_len);
        if (!payload) {
            perror("malloc");
            break;
        }
        if (!read_all(fd, payload, inc_len)) {
            fprintf(stderr, "Truncated payload\n");
            free(payload);
            break;
        }

        uint8_t dir = flags & 0x01;
        uint8_t ptype = payload[0];
        printf("#%zu len=%u orig=%u dir=%s ts=%" PRIu64 "us type=%s (0x%02x)\n",
               idx, inc_len, orig_len, dir ? "C->H" : "H->C", ts, ptype_name(ptype), ptype);
        free(payload);
        idx++;
    }

    close(fd);
    return EXIT_SUCCESS;
}
