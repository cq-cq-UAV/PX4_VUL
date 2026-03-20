# PX4 MAVLink FTP: Path traversal enabling file write/read outside root (verification)

## Summary
PX4 v1.16.1 exposes MAVLink FTP (MAVFTP) over `FILE_TRANSFER_PROTOCOL` and accepts attacker-controlled relative paths. In PX4 SITL (POSIX), this allows **directory traversal** (e.g., `../../..`) to access paths outside the intended FTP root.

This verification demonstrates that an unauthenticated sender can:
- create a file at a traversal path resolving to `/tmp/...`
- write marker content
- open and read back the content
- remove the file

## Affected component
- MAVLink message: `FILE_TRANSFER_PROTOCOL` (MAVLink msgid 110)
- Service: MAVLink FTP (MAVFTP)

## Test environment
- PX4: v1.16.1 SITL (POSIX)
- Executable: `~/PX4/PX4-Autopilot/build/px4_sitl_default/bin/px4`
- MAVLink UDP instance (from PX4 console):
  - Listen: `127.0.0.1:18570`
  - Remote (reply) port: `14550`

See `artifacts/px4_console.log` for:
- `mode: Normal ... on udp port 18570 remote port 14550`

## Preconditions
- PX4 SITL is running locally.
- MAVLink normal UDP instance is active (default on `18570/14550`).

## Reproduction steps

### 1) Start PX4 SITL (daemon mode)

```bash
cd ~/PX4/PX4-Autopilot/build/px4_sitl_default
./bin/px4 -d -i 0 -s etc/init.d-posix/rcS > /tmp/px4_case01.log 2>&1
```

Confirm the ports in the log:

```bash
grep -n "mode: Normal" /tmp/px4_case01.log
```

### 2) Run the verification PoC

```bash
PYTHONPATH="/home/yxhueimie/Desktop/UAV-bug-detection/PX4_MAVLink_Audit_1.16.1" \
  python3 disclosure/01-mavftp-path-traversal/poc.py --timeout 10
```

The PoC will compute a traversal path from the SITL working root (`.../px4_sitl_default/rootfs`) to `/tmp` using `os.path.relpath()`, producing a relative path similar to:

- `../../../../../../../tmp/px4_mavftp_disclosure_poc.txt`

### 3) Observe the PoC output
Expected output contains `PASS` and shows the read-back marker content.

The captured output from this run is saved as:
- `artifacts/poc_output.txt`

## Observed result
The PoC received FTP ACKs for:
- `OP_CREATE`
- `OP_WRITE`
- `OP_OPEN_RO`
- `OP_READ`
- `OP_REMOVE_FILE`

And it read back the marker content:

- `b'PX4_MAVFTP_DISCLOSURE_POC\n'`

## Expected secure behavior
MAVFTP should enforce a strict root directory boundary and reject paths that escape the allowed root (canonicalization + traversal detection), regardless of transport or OS.

## Impact
- Unauthorized file creation/write/read/delete outside the intended MAVFTP root (bounded by OS permissions).
- In POSIX/SITL, this can affect host filesystem locations such as `/tmp`.

## Evidence
- PoC stdout: `artifacts/poc_output.txt`
- PX4 console log (MAVLink ports): `artifacts/px4_console.log`

## Safety notes
- Localhost only by default.
- Writes a single marker file under `/tmp` and removes it during the same run.

## Suggested mitigations (high level)
- Canonicalize and validate paths before use (resolve `..` and symlinks as appropriate).
- Enforce an allowlisted root and reject any path that escapes it.
- Require MAVLink signing/authentication for MAVFTP on untrusted links.
