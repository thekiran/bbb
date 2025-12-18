#include <errno.h>
#include <endian.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

struct conn_info {
    uint16_t handle;
    bdaddr_t addr;
    bool le;
    bool in_use;
};

struct conn_table {
    struct conn_info items[32];
};

struct options {
    int dev_id;
    int duration_secs;
    int rssi_interval_ms;
    bool show_acl;
};

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static const char *addr_to_string(const bdaddr_t *ba, char *out) {
    ba2str(ba, out);
    return out;
}

static struct conn_info *conn_find(struct conn_table *table, uint16_t handle) {
    for (size_t i = 0; i < ARRAY_SIZE(table->items); i++) {
        if (table->items[i].in_use && table->items[i].handle == handle) {
            return &table->items[i];
        }
    }
    return NULL;
}

static struct conn_info *conn_add(struct conn_table *table, uint16_t handle, const bdaddr_t *addr, bool le) {
    struct conn_info *slot = conn_find(table, handle);
    if (slot) {
        slot->addr = *addr;
        slot->le = le;
        return slot;
    }
    for (size_t i = 0; i < ARRAY_SIZE(table->items); i++) {
        if (!table->items[i].in_use) {
            table->items[i].in_use = true;
            table->items[i].handle = handle;
            table->items[i].addr = *addr;
            table->items[i].le = le;
            return &table->items[i];
        }
    }
    return NULL;
}

static void conn_remove(struct conn_table *table, uint16_t handle) {
    struct conn_info *slot = conn_find(table, handle);
    if (slot) {
        slot->in_use = false;
    }
}

static int open_hci_raw(int dev_id, int channel) {
    int sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_hci addr = {
        .hci_family = AF_BLUETOOTH,
        .hci_dev = dev_id,
        .hci_channel = channel,
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    return sock;
}

static void install_filter(int sock, bool include_acl) {
    struct hci_filter flt;
    hci_filter_clear(&flt);
    hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
    if (include_acl) {
        hci_filter_set_ptype(HCI_ACLDATA_PKT, &flt);
    }
    hci_filter_all_events(&flt);
    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        perror("setsockopt(HCI_FILTER)");
        exit(EXIT_FAILURE);
    }
}

static void print_reason(uint8_t reason) {
    printf(" reason=0x%02x", reason);
    switch (reason) {
    case 0x13:
        printf(" (Remote User Terminated)");
        break;
    case 0x16:
        printf(" (Connection Terminated by Local Host)");
        break;
    case 0x08:
        printf(" (Connection Timeout)");
        break;
    default:
        break;
    }
}

static void handle_event(struct conn_table *table, const uint8_t *buf, ssize_t len) {
    if (len < 1 + HCI_EVENT_HDR_SIZE) {
        return;
    }
    evt_hdr *hdr = (evt_hdr *)(buf + 1);
    uint8_t evt = hdr->evt;
    uint8_t plen = hdr->plen;
    const uint8_t *payload = buf + 1 + HCI_EVENT_HDR_SIZE;
    if (plen + 1 + HCI_EVENT_HDR_SIZE > (uint8_t)len) {
        return;
    }

    switch (evt) {
    case EVT_CONN_COMPLETE: {
        if (plen < sizeof(evt_conn_complete)) {
            break;
        }
        const evt_conn_complete *cc = (const evt_conn_complete *)payload;
        char addr[18];
        printf("[HCI] Classic conn complete status=%u handle=0x%04x addr=%s link_type=%u\n",
               cc->status, btohs(cc->handle), addr_to_string(&cc->bdaddr, addr), cc->link_type);
        if (cc->status == 0) {
            conn_add(table, btohs(cc->handle), &cc->bdaddr, false);
        }
        break;
    }
    case EVT_DISCONN_COMPLETE: {
        if (plen < sizeof(evt_disconn_complete)) {
            break;
        }
        const evt_disconn_complete *dc = (const evt_disconn_complete *)payload;
        printf("[HCI] Disconnected handle=0x%04x status=%u", btohs(dc->handle), dc->status);
        print_reason(dc->reason);
        printf("\n");
        conn_remove(table, btohs(dc->handle));
        break;
    }
    case EVT_LE_META_EVENT: {
        if (plen < sizeof(evt_le_meta_event)) {
            break;
        }
        const evt_le_meta_event *me = (const evt_le_meta_event *)payload;
        if (me->subevent == EVT_LE_CONN_COMPLETE) {
            const le_connection_complete *lc = (const le_connection_complete *)me->data;
            char addr[18];
            printf("[HCI] LE conn complete status=%u handle=0x%04x role=%u addr=%s\n",
                   lc->status, btohs(lc->handle), lc->role, addr_to_string(&lc->peer_bdaddr, addr));
            if (lc->status == 0) {
                conn_add(table, btohs(lc->handle), &lc->peer_bdaddr, true);
            }
        } else if (me->subevent == EVT_LE_CONN_UPDATE_COMPLETE) {
            const evt_le_connection_update_complete *cu = (const evt_le_connection_update_complete *)me->data;
            printf("[HCI] LE conn update handle=0x%04x interval=%.2fms latency=%u timeout=%u\n",
                   btohs(cu->handle),
                   cu->interval * 1.25,
                   cu->latency,
                   cu->supervision_timeout);
        }
        break;
    }
    case EVT_CMD_COMPLETE: {
        if (plen < sizeof(evt_cmd_complete)) {
            break;
        }
        const evt_cmd_complete *cc = (const evt_cmd_complete *)payload;
        uint16_t opcode = btohs(cc->opcode);
        if (opcode == cmd_opcode_pack(OGF_STATUS_PARAM, OCF_READ_RSSI)) {
            if (plen >= sizeof(evt_cmd_complete) + sizeof(read_rssi_rp)) {
                const read_rssi_rp *rp = (const read_rssi_rp *)(payload + sizeof(evt_cmd_complete));
                if (rp->status == 0) {
                    printf("[HCI] RSSI handle=0x%04x rssi=%d dBm (approx)\n",
                           btohs(rp->handle), (int8_t)rp->rssi);
                } else {
                    printf("[HCI] RSSI handle=0x%04x status=%u\n", btohs(rp->handle), rp->status);
                }
            }
        }
        break;
    }
    default:
        break;
    }
}

static void handle_acl(const struct options *opts, const uint8_t *buf, ssize_t len, uint64_t *acl_counter) {
    if (len < 1 + HCI_ACL_HDR_SIZE) {
        return;
    }
    const hci_acl_hdr *h = (const hci_acl_hdr *)(buf + 1);
    uint16_t handle = btohs(h->handle) & 0x0FFF;
    uint16_t dlen = btohs(h->dlen);
    if (1 + HCI_ACL_HDR_SIZE + dlen > (uint16_t)len) {
        return;
    }
    const uint8_t *payload = buf + 1 + HCI_ACL_HDR_SIZE;
    (*acl_counter) += dlen;

    if (!opts->show_acl) {
        return;
    }

    if (dlen < L2CAP_HDR_SIZE) {
        return;
    }
    const l2cap_hdr *l = (const l2cap_hdr *)payload;
    uint16_t l2len = le16toh(l->len);
    uint16_t cid = le16toh(l->cid);
    if (l2len + L2CAP_HDR_SIZE > dlen) {
        return;
    }

    if (cid == 0x0001 && l2len >= 4) { /* Signaling channel */
        const uint8_t *sig = payload + L2CAP_HDR_SIZE;
        uint8_t code = sig[0];
        uint8_t id = sig[1];
        uint16_t siglen;
        memcpy(&siglen, sig + 2, sizeof(siglen));
        siglen = le16toh(siglen);
        if (siglen + 4 <= l2len && code == 0x02 && siglen >= 4) { /* Connection Request */
            uint16_t psm, scid;
            memcpy(&psm, sig + 4, sizeof(psm));
            memcpy(&scid, sig + 6, sizeof(scid));
            psm = le16toh(psm);
            scid = le16toh(scid);
            const char *psm_name = NULL;
            if (psm == 0x0019) {
                psm_name = "AVDTP (A2DP signalling)";
            } else if (psm == 0x0017) {
                psm_name = "AVCTP (AVRCP)";
            }
            if (psm_name) {
                printf("[ACL] handle=0x%04x L2CAP Connection Request id=%u PSM=0x%04x (%s) SCID=0x%04x\n",
                       handle, id, psm, psm_name, scid);
            }
        }
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [-i hciX] [--duration N] [--rssi-ms M] [--show-acl]\n"
            "  -i hciX      Use adapter hciX (default: first available)\n"
            "  --duration N Stop after N seconds (default: run until Ctrl+C)\n"
            "  --rssi-ms M  Poll RSSI every M milliseconds for active handles\n"
            "  --show-acl   Decode ACL signaling (PSM hints for A2DP/AVRCP)\n",
            prog);
}

static bool parse_args(int argc, char **argv, struct options *opts) {
    opts->dev_id = hci_get_route(NULL);
    opts->duration_secs = -1;
    opts->rssi_interval_ms = 0;
    opts->show_acl = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            opts->dev_id = hci_devid(argv[++i]);
            if (opts->dev_id < 0) {
                perror("hci_devid");
                return false;
            }
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            opts->duration_secs = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rssi-ms") == 0 && i + 1 < argc) {
            opts->rssi_interval_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--show-acl") == 0) {
            opts->show_acl = true;
        } else {
            usage(argv[0]);
            return false;
        }
    }
    return true;
}

int main(int argc, char **argv) {
    struct options opts;
    if (!parse_args(argc, argv, &opts)) {
        return EXIT_FAILURE;
    }
    if (opts.dev_id < 0) {
        fprintf(stderr, "No HCI adapter found\n");
        return EXIT_FAILURE;
    }

    int evt_sock = open_hci_raw(opts.dev_id, HCI_CHANNEL_RAW);
    if (evt_sock < 0) {
        return EXIT_FAILURE;
    }
    install_filter(evt_sock, true);

    /* Use a dedicated command socket for RSSI polling (also raw). */
    int cmd_sock = open_hci_raw(opts.dev_id, HCI_CHANNEL_RAW);
    if (cmd_sock < 0) {
        close(evt_sock);
        return EXIT_FAILURE;
    }

    printf("Listening on hci%d (events + ACL). Root/CAP_NET_ADMIN may be required.\n", opts.dev_id);
    if (opts.rssi_interval_ms > 0) {
        printf("RSSI polling every %d ms for active handles.\n", opts.rssi_interval_ms);
    }
    if (opts.duration_secs > 0) {
        printf("Will stop after %d seconds.\n", opts.duration_secs);
    }

    struct conn_table connections = {0};
    uint64_t acl_bytes = 0;
    uint64_t start_ms = now_ms();
    uint64_t next_rssi_ms = start_ms + opts.rssi_interval_ms;

    while (1) {
        int timeout = -1;
        if (opts.duration_secs > 0) {
            uint64_t elapsed = now_ms() - start_ms;
            if (elapsed / 1000 >= (uint64_t)opts.duration_secs) {
                break;
            }
            timeout = (int)(((uint64_t)opts.duration_secs * 1000) - elapsed);
        }
        if (opts.rssi_interval_ms > 0) {
            uint64_t now = now_ms();
            if (now >= next_rssi_ms) {
                /* Poll RSSI for each active connection. */
                for (size_t i = 0; i < ARRAY_SIZE(connections.items); i++) {
                    if (!connections.items[i].in_use) {
                        continue;
                    }
                    uint8_t rssi = 0;
                    if (hci_read_rssi(cmd_sock, connections.items[i].handle, &rssi, 1000) == 0) {
                        printf("[HCI] RSSI handle=0x%04x rssi=%d dBm (approx)\n",
                               connections.items[i].handle, (int8_t)rssi);
                    }
                }
                next_rssi_ms = now + opts.rssi_interval_ms;
            }
            int until_rssi = (int)(next_rssi_ms - now_ms());
            if (timeout < 0 || until_rssi < timeout) {
                timeout = until_rssi;
            }
            if (timeout < 0) {
                timeout = 1000;
            }
        }

        struct pollfd pfd = {
            .fd = evt_sock,
            .events = POLLIN,
        };
        int pret = poll(&pfd, 1, timeout);
        if (pret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        } else if (pret == 0) {
            continue;
        }

        uint8_t buf[HCI_MAX_FRAME_SIZE];
        ssize_t n = read(evt_sock, buf, sizeof(buf));
        if (n <= 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read");
            break;
        }

        if (buf[0] == HCI_EVENT_PKT) {
            handle_event(&connections, buf, n);
        } else if (buf[0] == HCI_ACLDATA_PKT) {
            handle_acl(&opts, buf, n, &acl_bytes);
        }
    }

    printf("Total ACL bytes observed: %" PRIu64 "\n", acl_bytes);
    close(cmd_sock);
    close(evt_sock);
    return EXIT_SUCCESS;
}
