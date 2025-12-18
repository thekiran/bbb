# Bluetooth HCI Monitoring Samples (C + BlueZ)

This repository contains two small C utilities for inspecting your **own**
Bluetooth traffic at the HCI level using only legal, official interfaces
(libbluetooth/btmon/btsnoop). No kernel patches or firmware modifications are
required.

> ⚠️ You typically need `CAP_NET_ADMIN` (root) to open raw HCI sockets.

## Building

```bash
make            # builds bin/hci_monitor and bin/btsnoop_dump
```

Dependencies:

- `gcc` (or another C11 compiler)
- `pkg-config` + `libbluetooth-dev` (BlueZ headers) for `hci_monitor`

## hci_monitor

Real-time HCI monitor for your adapter. Captures connect/disconnect events,
reason codes, optional ACL signaling (PSM hints for A2DP/AVRCP), and can poll
RSSI per active handle.

```bash
sudo bin/hci_monitor [-i hciX] [--duration N] [--rssi-ms M] [--show-acl]
```

- `-i hciX`: choose adapter (default: first available).
- `--duration N`: stop after `N` seconds.
- `--rssi-ms M`: periodically issue `Read RSSI` for each active handle.
- `--show-acl`: decode L2CAP signaling to surface PSMs (e.g., 0x0019 AVDTP/A2DP).

What you get:

- HCI events: connect/disconnect + reason codes, LE connection/update events.
- Optional ACL inspection: L2CAP Connection Requests with PSM hints for
  A2DP (0x0019) and AVRCP (0x0017).
- Per-connection RSSI samples (best-effort, depends on controller support).

Limitations (by design):

- Only host-side traffic (your own connections); no over-the-air sniffing.
- Encrypted payloads are not decrypted; this tool reports headers/metadata.

## btsnoop_dump

Minimal parser for `btmon --write hci.btsnoop` captures (HCI H4, DLT 1001).
Prints packet index, length, direction, timestamp, and HCI packet type.

```bash
btmon --write hci.btsnoop &
sudo bin/hci_monitor --duration 10   # exercise your own connections
kill %1                               # stop btmon
bin/btsnoop_dump hci.btsnoop
```

Output example:

```
btsnoop version=1 dlt=1001 (HCI H4)
#0 len=12 orig=12 dir=H->C ts=123456 type=HCI CMD (0x01)
#1 len=20 orig=20 dir=C->H ts=123789 type=HCI EVT (0x04)
...
```
