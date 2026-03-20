# PX4 MAVLink: Unauthenticated `SERIAL_CONTROL(SHELL)` prompt exposure (verification)

## Summary
PX4 v1.16.1 accepts MAVLink `SERIAL_CONTROL` messages targeting the **shell device** and will emit the interactive shell prompt (`pxh>`) to an unauthenticated sender. This provides evidence that the MAVLink shell output channel can be triggered remotely without MAVLink signing/authentication. We have not yet validated version 1.17.1, but it appears that both v1.17.1 and versions prior to 1.16.1 may be affected.

This verification PoC is intentionally **non-destructive**: it sends only a single newline to trigger prompt output, and it does not execute any shell commands.

## Vulnerability point
- **Unauthenticated access to the MAVLink shell channel** via `SERIAL_CONTROL` with `device=SERIAL_CONTROL_DEV_SHELL`.

## Vulnerability analysis (root cause)
`MavlinkReceiver::handle_message_serial_control()` accepts `SERIAL_CONTROL` messages addressed to this system/component (including broadcast targets) and forwards the data to `MavlinkShell` by calling:
- `shell->setTargetID(msg->sysid, msg->compid)` and
- `shell->write(serial_control_mavlink.data, serial_control_mavlink.count)`

There is no authentication requirement at this layer; on UDP the “partner” is determined by first-packet binding, not by a cryptographic handshake.

## Code references
- `src/modules/mavlink/mavlink_receiver.cpp:1833-1865` (`MavlinkReceiver::handle_message_serial_control()`)

## Code snippet 
From PX4 v1.16.1 `MavlinkReceiver::handle_message_serial_control()`:

```cpp
// mavlink_receiver.cpp

if (serial_control_mavlink.device != SERIAL_CONTROL_DEV_SHELL
    || (serial_control_mavlink.flags & SERIAL_CONTROL_FLAG_REPLY)) {
    return;
}

MavlinkShell *shell = _mavlink.get_shell();

if (shell) {
    shell->setTargetID(msg->sysid, msg->compid);
    shell->write(serial_control_mavlink.data, serial_control_mavlink.count);

    if ((serial_control_mavlink.flags & SERIAL_CONTROL_FLAG_RESPOND) == 0) {
        _mavlink.close_shell();
    }
}
```

Explanation:
- A remote peer can send bytes to the PX4 shell device over MAVLink.
- The sender identity is taken from MAVLink header fields (`msg->sysid/compid`), not from an authenticated session.

## CWE
- CWE-306: Missing Authentication for Critical Function

## Affected component
- MAVLink message: `SERIAL_CONTROL` (MAVLink msgid 126)
- Device: `SERIAL_CONTROL_DEV_SHELL` (10)

## Test environment
- PX4: v1.16.1 SITL
- Executable: `~/PX4/PX4-Autopilot/build/px4_sitl_default/bin/px4`
- OS: Linux (local)
- MAVLink UDP instance (from PX4 console):
  - Listen: `127.0.0.1:18570`
  - Remote (reply) port: `14550`

Evidence of MAVLink instance configuration and shell start can be found in `artifacts/px4_console.log`:
- `mode: Normal ... on udp port 18570 remote port 14550`
- `Starting mavlink shell`

## Preconditions
- PX4 SITL is running locally.
- MAVLink normal UDP instance is active on `udp port 18570` with `remote port 14550`.

## Reproduction steps

### 1) Start PX4 SITL (daemon mode)
Run from the build directory:

```bash
cd ~/PX4/PX4-Autopilot/build/px4_sitl_default
./bin/px4 -d -i 0 -s etc/init.d-posix/rcS > /tmp/px4_sitl_run.log 2>&1
```

Confirm in the log you have:
- `INFO  [mavlink] mode: Normal ... on udp port 18570 remote port 14550`

### 2) Run the verification PoC
From this audit repo root:

```bash
PYTHONPATH="/home/yxhueimie/Desktop/UAV-bug-detection/PX4_MAVLink_Audit_1.16.1" \
  python3 disclosure/03-serial-control-shell/poc.py --timeout 6
```

### 3) Observe the PoC output
Expected output (example):

- `PASS: received SERIAL_CONTROL reply containing 'pxh>'`

The exact PoC output captured during this run is saved as:
- `artifacts/poc_output.txt`

## Observed result
The PoC received a `SERIAL_CONTROL` reply containing the shell prompt `pxh>`.

## Expected secure behavior
Without MAVLink signing/authentication (or an explicit allowlist), an unauthenticated sender should not be able to trigger shell output, and the MAVLink shell device should not be reachable remotely.

## Impact
- Remote, unauthenticated proof-of-access to the MAVLink shell channel.
- In many deployments this can be escalated to interactive shell command execution if arbitrary input is accepted.

## Evidence
- PoC stdout: `artifacts/poc_output.txt`
- PX4 console log excerpt (MAVLink ports + shell start): `artifacts/px4_console.log`

## Safety notes
- This PoC sends only a single newline (`\n`).
- It does not attempt to run commands, arm the vehicle, change parameters, or modify missions.

## Suggested mitigations (high level)
- Require MAVLink signing / authentication for shell-related message paths.
- Disable or gate the MAVLink shell (`SERIAL_CONTROL_DEV_SHELL`) on untrusted links.
- Enforce strict target system/component checks (avoid accepting broadcast `0/0` for privileged paths).
