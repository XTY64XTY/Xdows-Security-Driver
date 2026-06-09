# Xdows Security Driver Protection Spec

Version: 2026-06-09

This document freezes the B01 scope for the driver-backed protection path. It
maps the user requirements to modules, defines decision semantics, and records
kernel/user-mode boundaries used by B02-B05.

## Requirement Traceability

| ID | Requirement | Modules | Event | Decision | Test coverage |
| --- | --- | --- | --- | --- | --- |
| R01 | Remove ETW as the real-time protection path | Settings, Protection | N/A | Driver protection wins when available | B12 |
| R02 | Add driver-backed protection | KMDF control device, DriverProtection | Driver state, pending events | Enable/disable by driver session | B02, B03, B13 |
| R03 | Use native Xdows Model access, not Xdows-Model-Caller | Xdows-Model-Native, NativeModelScanner | Scan request | Safe, Threat, Unsupported, Error | B04, B17 |
| R04 | Intercept process starts | ProcessProtect, DriverBridgeClient | ProcessCreate | Allow, Block, Timeout | B05 |
| R05 | Intercept file create/write/rename | FileProtect, DriverBridgeClient | FileCreate/FileWrite/FileRename | Allow, Block, Timeout | B06 |
| R06 | Ask the user before continuing after a threat | DriverProtection, InterceptWindow | ThreatDecision | UserAllow or UserBlock | B07 |
| R07 | Verify operator process trust/certificate | TrustQuarantine, DriverProtection | ActorTrustCheck | Trusted actors are cached | B08 |
| R08 | Protect the main Xdows Security process | SelfProtect, DriverProtection | SelfProcessHandle | Strip dangerous access | B09 |
| R09 | Prevent common injection prerequisites | InjectionProtect | ProcessHandle, ThreadHandle, ImageLoad | Allow, StripAccess, Block | B10 |
| R10 | Require a shutdown token | TokenAuth, DriverShutdownToken | ShutdownRequest | Authorized or Denied | B11 |
| R11 | Detect driver environment and repair | DriverEnvironmentChecker, DriverInstaller | EnvironmentCheck | Repairable or ManualAction | B14 |
| R12 | Surface every block/log event in the main app | Log, LogService | DriverLog | Display/export | B15 |

## Blocking Event Model

All kernel-to-user events use a shared protocol header with version and size.
The kernel event contains an event id, correlation id, event type, process ids,
timestamps, path fields, and flags. User mode must return a decision for the
same event id.

Decision values:

| Value | Meaning |
| --- | --- |
| Allow | Continue the original operation. Safe scans and explicit user release map here. |
| Block | Fail the original operation. User rejection and confirmed malicious results map here. |
| Timeout | Treat as user-mode policy timeout. For confirmed threats this maps to Block. |

B05 process events are emitted before process creation completes. The bridge
scans the target image and only asks the UI when the scanner reports a threat.
Safe or unsupported files are allowed without UI.

## Failure And Timeout Policy

The driver must not deadlock process creation if user mode is absent. These
rules apply until a stricter policy is introduced by a later block:

| Failure | Process create policy | Rationale |
| --- | --- | --- |
| No bridge connected | Allow and record/log the condition when logging is available | Blocking all launches would make recovery impossible. |
| Bridge connected but no event fetched before kernel wait timeout | Allow | The kernel cannot know whether the target is malicious yet. |
| Native model throws before a threat is confirmed | Allow and log model error | Avoid blocking normal boot/app launch because of model deployment issues. |
| Threat confirmed and user explicitly releases | Allow with a short cache TTL | Prevent repeated prompts for the same image. |
| Threat confirmed and user rejects/closes/times out | Block | Matches the user-consent requirement. |

Default B05 kernel wait timeout: 5000 ms.
Default user threat-decision timeout: 30 seconds.
Default allow cache TTL for an explicitly released threat: 5 minutes.

## Protection Priority

When driver protection is running, it is the authoritative real-time protection
path. Compatibility modes may remain enabled as fallback settings, but they
must not start ETW or duplicate driver decisions.

Priority order:

1. Driver protection, if installed, running, and bridged.
2. Legacy compatibility protection, only when driver protection is not running.
3. ETW protection is not a preferred real-time path and is removed by B12.

## Kernel Boundary

Kernel mode may:

- collect process, file, handle, image-load, and self-protection events;
- maintain bounded queues, short-lived caches, and token hashes;
- wait at PASSIVE_LEVEL for bounded user-mode decisions where the callback
  contract allows it;
- fail operations only at documented pre-operation decision points.

Kernel mode must not:

- load .NET or the model runtime;
- call command-line model tools;
- show UI;
- perform certificate-chain validation beyond lightweight cached policy;
- wait while holding internal locks;
- wait from high IRQL.

## Privilege, Signing, And Restart Requirements

| Capability | Requires admin | Requires test/signing | Requires restart |
| --- | --- | --- | --- |
| Build driver | No | WDK installed | No |
| Install driver package | Yes | Test mode or valid signature | Sometimes |
| Start/stop kernel service | Yes | Valid load signature | No |
| Register process callback | No extra runtime privilege | Driver image must satisfy kernel integrity/signing requirements | No |
| PPL self-protection | Yes | Microsoft/Windows protected-service signing constraints | Usually |
| ObRegisterCallbacks self/injection protection | Driver service running | Signed driver | No |
| Shutdown token authorization | Main app memory token | No extra | No |

PPL is not assumed for B05. If PPL cannot be satisfied, later self-protection
uses object callbacks and explicit user-authorized shutdown only.

