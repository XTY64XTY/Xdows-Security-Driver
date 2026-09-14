# Driver Protocol And Maintenance

## Cross-Repository Boundary

The driver repository owns:

- `Public.h` protocol constants, IOCTLs, event structs, decision structs, state structs, authorization token structs, process management structs, and log structs.
- Kernel event production, pending queue behavior, timeout behavior, token hashing, self-protection, injection protection, and log buffering.
- Driver package generation through VS/WDK.

The main app repository owns:

- `Protection\DriverProtocol.cs`, which must mirror `Public.h`.
- `Protection\DriverBridgeClient.cs`, which opens `\\.\XdowsSecurityDriver`, registers the client, sends heartbeats, pulls events/logs, submits decisions, and submits authorized shutdown.
- `Protection\DriverProtection.cs`, which scans, checks trust, asks the user, caches decisions, writes logs, and handles failure policy.
- `Protection\DriverInstaller.cs`, `Protection\DriverPackageLocator.cs`, and `Protection\DriverPackageInstaller.cs`, which install the primitive minifilter INF package and start it automatically before the bridge connects.
- App build/publish output that includes the driver package and native model assets from projects referenced by `Xdows-Security.slnx`.

The model repository owns:

- `Xdows-Model-Native.dll` C ABI.
- ONNX Runtime native dependencies.
- `Xdows-Model.onnx`, `Xdows-Model-Flash.onnx`, and `Xdows-Model-Pro.onnx`.
- Native vs managed consistency testing.

## Protocol Version Rules

Current protocol version: `9`.

Protocol 7 added the `Behavior` event, the shared `BehaviorType` payload,
per-type state counters for that event, and the required R0 behavior module
and capability bits. Protocol 6 builds remain explicit hot-upgrade sources;
they are not accepted as current runtime peers.

Protocol 9 adds the `SetBootProtection` (0x80E) and `SetRegistryProtection`
(0x80F) IOCTLs, the `RegistryWrite` event (type 11), the R0 registry protection
capability bit `0x200`, and the `Registry` module bit `0x40`.

The memory-optimization block (same protocol version 9, additive only) adds:

- `IOCTL_XDOWS_SECURITY_GET_NEXT_EVENTS` (0x810) and `XDOWS_SECURITY_EVENT_BATCH`
  (batch size 16, whole struct under the 85 KB .NET LOH threshold for buffer
  pooling). The call never blocks; the client paces its own drain loop and
  reads only `Count` entries. Capability bit `0x800`.
- `XDOWS_SECURITY_REGISTER_FLAG_ASYNC_REVIEW` (`Flags` bit 0x1 in
  `REGISTER_CLIENT`): non-critical event types are queued for display but the
  origin thread returns immediately with the default Allow decision. Capability
  bit `0x400`. Unknown flag bits are ignored for forward compatibility.
  `FileRename` is excluded: it runs in `PreSetInformation`, can fail the
  operation with `STATUS_VIRUS_INFECTED`, and must stay synchronous so user
  mode can still block ransomware-style renames.
- Per-type sliding-window (1 s) rate limits for non-critical noise types
  (file create 200/s, file write 300/s, driver log 100/s).
  Throttled events are dropped silently (no log entry, no user-mode event) and
  counted in `DroppedByType`. Critical types (process create, file rename,
  handle/thread operations, confirmed behavior, boot writes, registry writes)
  are never throttled, so protection is not weakened.
- The `FileProtect` scannable-extension allowlist is narrowed to
  exe/dll/scr/com/pif/sys; script and document formats are covered at
  execution time by process-launch and command-line behavior rules.

The protection-round block (same protocol version 9, additive only) adds:

- Behavior types 16/17/18 (`EfiMount`, `OobeReset`,
  `SystemDirectoryRansomware`). Types 16/17 are new command-line rules in the
  kernel rule engine: `mountvol` + `/s` (EFI system partition mounting) and
  `sysprep` + `/oobe`|`/generalize`|`/audit` (destructive re-provisioning
  reset). Both are **fail-closed** on bridge/decision infrastructure failure
  (destructive persistence/reset primitives, no recurring legitimate use on
  consumer endpoints). Type 18 is reserved: system-directory ransomware is
  currently enforced purely in-kernel (see below) and never reaches user mode.
- System-binary masquerade interception (`FileProtect` `PreCreate`): a
  write-open that creates or replaces a Windows system-binary name
  (svchost.exe, rundll32.exe, regsvr32.exe, dllhost.exe, lsass.exe, csrss.exe,
  smss.exe, winlogon.exe, wininit.exe, services.exe, spoolsv.exe, taskhostw.exe,
  conhost.exe, dwm.exe, dllhst3g.exe) under `AppData`, `Downloads`, `Desktop`
  (including OneDrive-redirected desktops), or `ProgramData` is denied
  synchronously with `STATUS_ACCESS_DENIED`. Pure kernel denial: no event, no
  user-mode round trip. CI-trusted processes and the registered client are
  exempt.
- System-directory ransomware dimension (`RansomwareMonitor`): destructive
  opens (DELETE access) by script hosts (cmd/powershell/pwsh/wscript/cscript/
  mshta/rundll32/regsvr32) under any `\Windows\` subtree are counted in a
  separate slot table. Crossing `XDOWS_RANSOM_SYS_FILE_THRESHOLD` (50) opens
  within `XDOWS_RANSOM_SYS_WINDOW_MS` (3000) flags the process, and further
  opens are denied with `STATUS_VIRUS_INFECTED` exactly like the user-data
  dimension. The CI-trust gate is deliberately NOT applied here: the
  interpreter binary itself is always legitimately signed, so the
  script-host identity is the discriminator. No user-data threshold changed:
  `XDOWS_RANSOM_FILE_THRESHOLD` stays 10 document/media writes in 3000 ms;
  the media extension class was widened (wav/flac/aac/m4a/m4v/wmv/mpg/mpeg/
  3gp/flv/heic/webp) plus epub/vsd/one.
- Registry protection round: registry gate honors the `KillActor` result-code
  sentinel (`XDOWS_DECISION_RESULT_KILL_ACTOR`, mirrored by
  `DriverProtocol.KillActorResultCode`) on confirmed Block verdicts for
  critical persistence keys; the counter-kill shares the injection guard
  rails (never the client, critical system processes, self-protected
  processes, or PID <= 4). The rule-path budget stays
  `XDOWS_SECURITY_MAX_REGISTRY_RULES = 32`; the app deploys 26 rules under
  `Recommended`, so no protocol-breaking budget increase was required.

The declarative-rule block (same protocol version 9, additive only) adds:

- `IOCTL_XDOWS_SECURITY_SET_BEHAVIOR_RULES` (0x811) with capability bit
  `0x1000`, and `IOCTL_XDOWS_SECURITY_SET_INITIATOR_EXCLUSIONS` (0x812) with
  capability bit `0x2000`. Both are opt-in downcalls; no existing struct
  layout, enum value, or IOCTL code changed, so an older app build keeps
  working against a newer driver and vice versa.
- `XDOWS_SECURITY_BEHAVIOR_RULE`: a user-mode-authored rule is the tuple
  Initiator x CommandLine x Target scoped by `Operations`, optionally
  rate-limited by `Threshold`/`WindowMs`, optionally escalated by `Flags`.
  `Initiator`, `Target`, and `CommandLine` are `XDOWS_SECURITY_RULE_TERM_AXIS`
  values holding up to `XDOWS_SECURITY_MAX_RULE_TERMS` (3) terms of
  `XDOWS_SECURITY_MAX_RULE_TERM_CHARS` (96, including the NUL) wide chars.
  Axis semantics: `TermCount == 0` leaves the axis unconstrained; an Initiator
  term is an image leaf name (e.g. `cmd.exe`) or, when it contains a backslash,
  a case-insensitive actor-path **suffix**; every CommandLine term must appear
  as a substring; Target terms are interpreted with the rule's
  `TargetMatchKind` (`Any`/`Suffix`/`Segment`/`Prefix`/`Contains`) and the rule
  matches when **any** target term matches. A rule that constrains no axis at
  all is rejected.
- The whole request is validated before anything is applied and rejected as a
  unit, so a malformed rule can never leave a partially applied set: a rule id
  and behavior type must be non-zero, `TargetMatchKind` must be in range,
  `Operations` must be non-zero and inside the supported mask, `Flags` must
  contain only known bits, `Threshold` must be 0-10000, and each term must be
  non-empty, NUL-terminated inside its fixed buffer, and contain no literal
  `*`/`?` wildcard (the interpreter only does literal matching, so a wildcard
  term would silently never match and hide a configuration mistake). A
  rejected request returns `STATUS_INVALID_PARAMETER` and leaves the previously
  applied set untouched; the swap itself is done under the exclusive side of an
  `EX_PUSH_LOCK` that the evaluation path holds shared.
- Fail-open / fail-closed is now a per-rule property instead of a per-rule-id
  hard-coded list. When the bridge or the decision round trip fails, a rule
  **without** `XDOWS_SECURITY_RULE_FLAG_FAIL_CLOSED` (0x2) releases the
  operation (fail-open, like the legitimate-management command rules), and a
  rule **with** it denies. `XDOWS_SECURITY_RULE_FLAG_KILL_ACTOR` (0x1)
  escalates a confirmed Block verdict to a counter-kill of the acting process,
  sharing the injection guard rails (never the registered client, a critical
  system process, a self-protected process, or PID <= 4). A rate-limited rule
  (`Threshold > 0`) fires only after that many matches by the same process
  inside `WindowMs` (clamped to 60000), tracked in a fixed 32-slot sliding
  window keyed by (rule id, process id).
- The fixed in-kernel rules are always evaluated **before** the declarative
  set, so their fail-open/fail-closed classification is unchanged and the
  declarative set can only add coverage, never weaken a built-in denial.
- `XDOWS_SECURITY_INITIATOR_EXCLUSION` (up to
  `XDOWS_SECURITY_MAX_INITIATOR_EXCLUSIONS` = 32 entries of
  `XDOWS_SECURITY_MAX_EXCLUSION_CHARS` = 160 wide chars) suppresses the
  user-mode consultation for the scopes named in its `ScopeMask`
  (`Process`/`File`/`Handle`/`Registry`). A pattern is an image leaf name
  (e.g. `steam.exe`) or, when it contains a backslash, a case-insensitive
  actor-path suffix.
- Exclusions are deliberately evaluated **after** every critical gate, so they
  can never weaken protection: the handle gate applies them only after the
  sensitive-process rights-stripping gate, the registry gate only after the
  CI-trust gate, and the file gate only after the built-in denials and the
  autorun rule. They also never bypass a confirmed-threat command-line rule.
- The hot-path gates resolve only the requestor image leaf name (no actor path
  is materialized), so a **path-suffix** exclusion pattern applies to the
  `Process` scope only; on `File`/`Handle`/`Registry` scopes it simply does not
  match. Author exclusions as leaf names unless only the process gate is being
  targeted.
- The rule set is authored in the main app as `Config\BehaviorRules.json` and
  parsed by `DriverBehaviorRuleCatalog`; a missing file is a valid "no rules"
  state, while a malformed file is reported (and skipped) instead of aborting
  the attach sequence. An empty exclusion array, an `Enabled` of 0, or a
  `RuleCount` of 0 clears the corresponding set.

The main app repository must mirror the new struct/IOCTL/flags in
`DriverProtocol.cs` and `DriverBridgeClient.cs` to use the batch drain and
async review; older app builds keep working unchanged because every addition
is opt-in via capability/flag bits. The declarative-rule and exclusion
structs additionally carry a field-by-field layout assertion in
`DriverBridgeClient` (rule 1784 bytes, request 57068 bytes, exclusion 328
bytes) so a mirror drift fails fast instead of corrupting the downcall.

Any change to `Public.h` that modifies a struct layout, enum value, IOCTL function code, string buffer length, token length, or device path requires all of the following in the same block:

1. Update `Protection\DriverProtocol.cs`.
2. Update `Protection\DriverBridgeClient.cs` if IOCTL behavior changed.
3. Update `Protection\DriverProtection.cs` if event or decision semantics changed.
4. Run `D:\Code\Xdows-Security\tests\Invoke-DriverBridgeProtocolSmoke.ps1`.
5. Update this document and `plan.json` evidence.
6. Commit and push each affected repository.

Do not reuse old enum values for new meanings. Add new values at the end unless a breaking protocol version bump is intentional.

## IOCTL Map

| IOCTL | Function | C# mirror | Purpose |
| --- | --- | --- | --- |
| `IOCTL_XDOWS_SECURITY_REGISTER_CLIENT` | `0x801` | `RegisterClient` | Register the app bridge and return the privileged authorization token once. |
| `IOCTL_XDOWS_SECURITY_HEARTBEAT` | `0x802` | `Heartbeat` | Keep bridge liveness fresh. |
| `IOCTL_XDOWS_SECURITY_GET_NEXT_EVENT` | `0x803` | `GetNextEvent` | Pull one pending protection event. |
| `IOCTL_XDOWS_SECURITY_SUBMIT_DECISION` | `0x804` | `SubmitDecision` | Return Allow, Block, or Timeout for an event. |
| `IOCTL_XDOWS_SECURITY_GET_STATE` | `0x805` | `GetState` | Query bridge and queue state. |
| `IOCTL_XDOWS_SECURITY_DISCONNECT_CLIENT` | `0x806` | `DisconnectClient` | Explicit bridge disconnect. |
| `IOCTL_XDOWS_SECURITY_REGISTER_PROTECTED_PROCESS` | `0x807` | `RegisterProtectedProcess` | Register the main app process for self-protection. |
| `IOCTL_XDOWS_SECURITY_SET_VOLUNTARY_EXIT` | `0x808` | `SetVoluntaryExit` | Tell the driver the app is intentionally exiting. |
| `IOCTL_XDOWS_SECURITY_AUTHORIZED_SHUTDOWN` | `0x809` | `AuthorizedShutdown` | Stop protection with the one-time shutdown token. |
| `IOCTL_XDOWS_SECURITY_GET_NEXT_LOG` | `0x80A` | `GetNextLog` | Pull one buffered driver log entry. |
| `IOCTL_XDOWS_SECURITY_SET_STARTUP_PROTECTION` | `0x80B` | `SetStartupProtection` | Synchronize startup-entry self-protection. |
| `IOCTL_XDOWS_SECURITY_QUERY_PROCESSES` | `0x80C` | `QueryProcesses` | Return a token-authorized, paged kernel process snapshot. |
| `IOCTL_XDOWS_SECURITY_OPERATE_PROCESS` | `0x80D` | `OperateProcess` | Suspend, resume, or terminate a process after protected-client and token validation. |
| `IOCTL_XDOWS_SECURITY_SET_BOOT_PROTECTION` | `0x80E` | `SetBootProtection` | Configure EFI and BCD boot protection. |
| `IOCTL_XDOWS_SECURITY_SET_REGISTRY_PROTECTION` | `0x80F` | `SetRegistryProtection` | Configure R0 registry protection rules. |
| `IOCTL_XDOWS_SECURITY_GET_NEXT_EVENTS` | `0x810` | `GetNextEvents` | Drain up to 16 undelivered events in one call; never blocks. |
| `IOCTL_XDOWS_SECURITY_SET_BEHAVIOR_RULES` | `0x811` | `SetBehaviorRules` | Replace the declarative behavior rule set (capability `0x1000`). Validated as a unit; a malformed request is rejected and the previous set is retained. |
| `IOCTL_XDOWS_SECURITY_SET_INITIATOR_EXCLUSIONS` | `0x812` | `SetInitiatorExclusions` | Replace the initiator exclusion list (capability `0x2000`). Count 0 clears it. |

Process management requests require both the registered, self-protected main process identity and the authorization token issued during registration. The driver rejects PID 0, PID 4, the calling main process, the protected process, and critical processes.

## Decision Semantics

- `Allow`: continue the original operation.
- `Block`: deny the original operation.
- `Timeout`: user-mode decision timeout; confirmed threats map to deny behavior.

`Behavior` events always carry `ThreatConfirmed` and enter the user-decision
hold before path resolution or UI work. Command-line behavior values 1-6 map
to shadow-copy destruction, hidden PowerShell, encoded commands, policy bypass,
download/execute, and LOLBin abuse. Values 7-8 correlate dangerous process and
thread handle requests from the injection module. User release allows the
original operation; block or user-decision timeout denies it. If the bridge is
unavailable before a hold starts, high-confidence command rules retain their
kernel fail-closed behavior, policy bypass stays fail-open, and injection keeps
its existing fail-open infrastructure policy.

Behavior value 16 (`EfiMount`, `mountvol` + `/s`) and 17 (`OobeReset`,
`sysprep` + `/oobe`|`/generalize`|`/audit`) are fail-closed command-line rules;
values 13-15 (destructive directory delete, ownership escalation, system
control) remain fail-open on infrastructure failure. Behavior value 18
(`SystemDirectoryRansomware`) is currently kernel-internal: the ransomware
rate monitor denies flagged script hosts without emitting an event.

Declarative rules (capability `0x1000`) reuse the same hold: a matched rule
emits a `Behavior` event carrying the rule's `BehaviorType` and enters the
user-decision hold, then denies on a Block verdict or on a user-decision
timeout. On infrastructure failure the rule's own `FAIL_CLOSED` flag decides -
absent the flag the operation is released and logged (fail-open), present the
operation is denied with `STATUS_ACCESS_DENIED` (fail-closed); a rule carrying
`KILL_ACTOR` additionally counter-kills the acting process on a confirmed
Block. The fixed in-kernel rules run first and keep the classification
described above. Initiator exclusions (capability `0x2000`) suppress the hold
for the configured scopes but are evaluated after every critical gate, so an
over-broad exclusion list degrades noise, never protection.

When the bridge or model fails before a threat is confirmed, user mode allows and logs the failure. When a threat is confirmed and the user refuses or times out, the decision is Block or Timeout.

## Maintenance Checklist

Before pushing protocol or driver behavior changes:

```powershell
Get-Content -LiteralPath 'D:\Code\Xdows-Security-Driver\plan.json' -Raw | ConvertFrom-Json | Out-Null
& 'D:\Code\Xdows-Security-Driver\tests\Invoke-DriverPackageSmoke.ps1'
& 'D:\Code\Xdows-Security\tests\Invoke-DriverBridgeProtocolSmoke.ps1'
& 'D:\Code\Xdows-Security\tests\Invoke-PublishAssetSmoke.ps1'
& 'D:\Code\Xdows-Model\tests\Invoke-NativeConsistency.ps1' -SkipBuild
```

Use `tests\driver-validation-matrix.md` for VM, Driver Verifier, stress, and performance evidence.
