# PX4 MAVLink: TUNNEL `payload_length` unchecked propagation (verification)

## Summary
PX4 v1.16.1 accepts MAVLink `TUNNEL` messages and publishes them to uORB topics while **copying `payload_length` from the MAVLink message without clamping**.

Because the uORB `mavlink_tunnel` / `esc_serial_passthru` message payload buffer is **fixed at 128 bytes**, a sender can set `payload_length > 128`, creating an inconsistent state: *length indicates N bytes, but only 128 bytes are present in the buffer*. Any downstream consumer that uses `payload_length` as a trusted length can then perform an out-of-bounds read.

This verification demonstrates (on local SITL) that `payload_length=200` is observable in uORB for:
- `payload_type=0` published to `mavlink_tunnel`
- `payload_type=211` published to `esc_serial_passthru`

## Vulnerability point
- **Unchecked length propagation**: `payload_length` is accepted from MAVLink and published to uORB even when it exceeds the fixed 128-byte payload buffer.

## Vulnerability analysis (root cause)
In `MavlinkReceiver::handle_message_tunnel()`, PX4:
- decodes `mavlink_tunnel.payload_length` and assigns it directly to `tunnel.payload_length`, and
- copies exactly `sizeof(tunnel.payload)` (128) bytes into `tunnel.payload`.

This creates a structural mismatch where `payload_length` can be up to 255 (uint8) while the buffer is 128 bytes, enabling downstream OOB reads if consumers trust `payload_length`.

## Code references
- `src/modules/mavlink/mavlink_receiver.cpp:1966-1993` (`handle_message_tunnel()` sets `payload_length` then `memcpy(..., sizeof(payload))`)

## Code snippet (illustrative)
From PX4 v1.16.1 `MavlinkReceiver::handle_message_tunnel()`:

```cpp
// mavlink_receiver.cpp

tunnel.payload_length = mavlink_tunnel.payload_length;
memcpy(tunnel.payload, mavlink_tunnel.payload, sizeof(tunnel.payload));
```

Explanation:
- `payload_length` is taken directly from the MAVLink message.
- The payload buffer is always copied at a fixed size (128 bytes).
- If `payload_length > 128`, downstream consumers that trust `payload_length` may read past `payload[128]`.

## CWE
- CWE-125: Out-of-bounds Read (in downstream consumers)
- CWE-20: Improper Input Validation

## Affected component
- MAVLink receive handler for `TUNNEL` (publishes to `mavlink_tunnel` or `esc_serial_passthru` uORB topics)

## Test environment
- PX4: v1.16.1 SITL (POSIX)
- Executable: `~/PX4/PX4-Autopilot/build/px4_sitl_default/bin/px4`
- MAVLink UDP instance:
  - Listen: `127.0.0.1:18570`
  - Remote port (reply): `14550`

Evidence captured in:
- `artifacts/px4_console.log` (startup/ports)
- `artifacts/poc_output_disclosure_type0.txt`
- `artifacts/listener_mavlink_tunnel_disclosure_type0.txt`
- `artifacts/poc_output_disclosure_type211.txt`
- `artifacts/listener_esc_serial_passthru_disclosure_type211.txt`

## Preconditions
- PX4 SITL running locally.
- `px4-listener` is available at `~/PX4/PX4-Autopilot/build/px4_sitl_default/bin/px4-listener`.
- Local UDP receive port `14550` is available.

## Reproduction steps

### 1) Start PX4 SITL (daemon mode)

```bash
cd ~/PX4/PX4-Autopilot/build/px4_sitl_default
./bin/px4 -d -i 0 -s etc/init.d-posix/rcS > /tmp/px4_case08.log 2>&1
```

### 2) Send a `TUNNEL` with `payload_length > 128` (payload_type=0)

```bash
PYTHONPATH="/home/yxhueimie/Desktop/UAV-bug-detection/PX4_MAVLink_Audit_1.16.1" \
  python3 disclosure/08-tunnel-payload-length-oob-read/poc.py \
    --payload-type 0 --payload-length 200

~/PX4/PX4-Autopilot/build/px4_sitl_default/bin/px4-listener mavlink_tunnel -n 1
```

### 3) Send a `TUNNEL` with `payload_length > 128` (payload_type=211)

```bash
PYTHONPATH="/home/yxhueimie/Desktop/UAV-bug-detection/PX4_MAVLink_Audit_1.16.1" \
  python3 disclosure/08-tunnel-payload-length-oob-read/poc.py \
    --payload-type 211 --payload-length 200

~/PX4/PX4-Autopilot/build/px4_sitl_default/bin/px4-listener esc_serial_passthru -n 1
```

## Observed result
- For `payload_type=0`, `px4-listener mavlink_tunnel -n 1` showed:
  - `payload_length: 200`
- For `payload_type=211`, `px4-listener esc_serial_passthru -n 1` showed:
  - `payload_length: 200`

## Security impact
- **Memory safety risk in downstream consumers**: any module that uses `payload_length` as a trusted length for accessing/writing `payload` can trigger an out-of-bounds read when `payload_length > 128`.
- Potential outcomes depend on the consumer:
  - Crash / instability (DoS)
  - Accidental disclosure of adjacent memory if the consumer copies/writes `payload_length` bytes outward

## Safety notes
- The PoC sends a single `TUNNEL` message on localhost.
- This verification does not attempt to trigger a crash or exfiltrate memory; it only demonstrates length propagation to uORB.

## Suggested mitigations (high level)
- Clamp or reject `payload_length` values greater than the uORB payload buffer size (128) in the `TUNNEL` receive path before publishing.
- Add defensive clamping in downstream consumers that use `payload_length` (treat it as untrusted input).
