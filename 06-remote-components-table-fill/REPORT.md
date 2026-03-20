# PX4 MAVLink: remote component seen-table exhaustion (verification)

## Summary
PX4 v1.16.1 maintains a fixed-size remote component tracking table (MAX_REMOTE_COMPONENTS = 16) per MAVLink receiver instance. An unauthenticated sender can spoof many distinct `(sysid, compid)` pairs and quickly exhaust this table.

This verification demonstrates that sending more than 16 distinct HEARTBEAT sources triggers the PX4 warning:

- `Max remote components of 16 used up`

## Vulnerability point
- **Fixed-size identity tracking table without eviction/aging**: unauthenticated `(sysid, compid)` spoofing can fill the table.

## Vulnerability analysis (root cause)
`MavlinkReceiver::update_rx_stats()` inserts new `(system_id, component_id)` pairs into a fixed array up to `MAX_REMOTE_COMPONENTS`. Once full, additional distinct identities are not recorded, and the warning is emitted once.

Because MAVLink source identifiers are unauthenticated on untrusted links, an attacker can rapidly allocate all 16 slots using HEARTBEATs from different spoofed `(sysid, compid)` pairs.

## Code references
- Table fill and warning: `src/modules/mavlink/mavlink_receiver.cpp:3320-3370` (`update_rx_stats()`, `MAX_REMOTE_COMPONENTS`)

## Code snippet (illustrative)
From PX4 v1.16.1 `MavlinkReceiver::update_rx_stats()`:

```cpp
// mavlink_receiver.cpp

for (unsigned i = 0; i < MAX_REMOTE_COMPONENTS; ++i) {
    if (_component_states[i].system_id == 0 && _component_states[i].component_id == 0) {
        _component_states[i].system_id = message.sysid;
        _component_states[i].component_id = message.compid;
        ...
        return true;
    }
}

if (!component_states_has_still_space && !_warned_component_states_full_once) {
    PX4_WARN("Max remote components of %u used up", MAX_REMOTE_COMPONENTS);
    _warned_component_states_full_once = true;
}
```

Explanation:
- Each new `(sysid, compid)` pair consumes one slot in a fixed-size array (`MAX_REMOTE_COMPONENTS=16`).
- There is no eviction/aging; spoofed identities can exhaust the table.

## CWE
- CWE-400: Uncontrolled Resource Consumption

## Affected component
- MAVLink receive path (remote component tracking table)
- Limit: `MAX_REMOTE_COMPONENTS = 16`

## Test environment
- PX4: v1.16.1 SITL (POSIX)
- Executable: `~/PX4/PX4-Autopilot/build/px4_sitl_default/bin/px4`
- MAVLink UDP instance (from PX4 console):
  - Listen: `127.0.0.1:18570`
  - Remote port: `14550`

Evidence captured in: `artifacts/px4_console.log`

## Preconditions
- PX4 SITL is running locally.
- MAVLink normal UDP instance is active.

## Reproduction steps

### 1) Start PX4 SITL (daemon mode)

```bash
cd ~/PX4/PX4-Autopilot/build/px4_sitl_default
./bin/px4 -d -i 0 -s etc/init.d-posix/rcS > /tmp/px4_case06.log 2>&1
```

(Any equivalent startup is fine; just ensure the UDP port is `18570`.)

### 2) Run the verification PoC

```bash
PYTHONPATH="/home/yxhueimie/Desktop/UAV-bug-detection/PX4_MAVLink_Audit_1.16.1" \
  python3 disclosure/06-remote-components-table-fill/poc.py
```

The PoC sends 20 distinct HEARTBEAT packets with different `(sysid, compid)` values to `udp:127.0.0.1:18570`.

Captured output:
- `artifacts/poc_output.txt`

### 3) Confirm PX4 warning in console log

```bash
grep -n "Max remote components of" /tmp/px4_case06.log
```

Captured PX4 log:
- `artifacts/px4_console.log`

## Observed result
PX4 emitted:

- `WARN  [mavlink] Max remote components of 16 used up`

after receiving >16 distinct remote component identities.

## Expected secure behavior
- Remote component tracking should not be exhaustible by unauthenticated spoofed identities (or should implement eviction/aging).
- Security-sensitive gating logic should not rely on a small fixed-size seen-table without defenses.

## Impact
- Resource/logic DoS and identity pollution in multi-peer deployments:
  - New legitimate components may no longer be tracked.
  - Any downstream logic relying on “component was seen” may behave incorrectly.

## Evidence
- PoC output: `artifacts/poc_output.txt`
- PX4 console log: `artifacts/px4_console.log`

## Safety notes
- PoC sends only `HEARTBEAT` (no control commands).
- Localhost-only by default.

## Suggested mitigations (high level)
- Implement aging/eviction (e.g., LRU/time-based) for remote component tracking.
- Enforce authentication/signing on untrusted links.
- Avoid using broadcast/"any component" semantics as a security gate.
