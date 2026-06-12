# Driver Protocol And Maintenance

## Cross-Repository Boundary

The driver repository owns:

- `Public.h` protocol constants, IOCTLs, event structs, decision structs, state structs, shutdown token structs, and log structs.
- Kernel event production, pending queue behavior, timeout behavior, token hashing, self-protection, injection protection, and log buffering.
- Driver package generation through VS/WDK.

The main app repository owns:

- `Protection\DriverProtocol.cs`, which must mirror `Public.h`.
- `Protection\DriverBridgeClient.cs`, which opens `\\.\XdowsSecurityDriver`, registers the client, sends heartbeats, pulls events/logs, submits decisions, and submits authorized shutdown.
- `Protection\DriverProtection.cs`, which scans, checks trust, asks the user, caches decisions, writes logs, and handles failure policy.
- App publish output that includes the driver package and native model assets.

The model repository owns:

- `Xdows-Model-Native.dll` C ABI.
- ONNX Runtime native dependencies.
- `Xdows-Model.onnx`, `Xdows-Model-Flash.onnx`, and `Xdows-Model-Pro.onnx`.
- Native vs managed consistency testing.

## Protocol Version Rules

Current protocol version: `1`.

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
| `IOCTL_XDOWS_SECURITY_REGISTER_CLIENT` | `0x801` | `RegisterClient` | Register the app bridge and return shutdown token once. |
| `IOCTL_XDOWS_SECURITY_HEARTBEAT` | `0x802` | `Heartbeat` | Keep bridge liveness fresh. |
| `IOCTL_XDOWS_SECURITY_GET_NEXT_EVENT` | `0x803` | `GetNextEvent` | Pull one pending protection event. |
| `IOCTL_XDOWS_SECURITY_SUBMIT_DECISION` | `0x804` | `SubmitDecision` | Return Allow, Block, or Timeout for an event. |
| `IOCTL_XDOWS_SECURITY_GET_STATE` | `0x805` | `GetState` | Query bridge and queue state. |
| `IOCTL_XDOWS_SECURITY_DISCONNECT_CLIENT` | `0x806` | `DisconnectClient` | Explicit bridge disconnect. |
| `IOCTL_XDOWS_SECURITY_REGISTER_PROTECTED_PROCESS` | `0x807` | `RegisterProtectedProcess` | Register the main app process for self-protection. |
| `IOCTL_XDOWS_SECURITY_SET_VOLUNTARY_EXIT` | `0x808` | `SetVoluntaryExit` | Tell the driver the app is intentionally exiting. |
| `IOCTL_XDOWS_SECURITY_AUTHORIZED_SHUTDOWN` | `0x809` | `AuthorizedShutdown` | Stop protection with the one-time shutdown token. |
| `IOCTL_XDOWS_SECURITY_GET_NEXT_LOG` | `0x80A` | `GetNextLog` | Pull one buffered driver log entry. |

## Decision Semantics

- `Allow`: continue the original operation.
- `Block`: deny the original operation.
- `Timeout`: user-mode decision timeout; confirmed threats map to deny behavior.

When the bridge or model fails before a threat is confirmed, user mode allows and logs the failure. When a threat is confirmed and the user refuses or times out, the decision is Block or Timeout.

## Maintenance Checklist

Before pushing protocol or driver behavior changes:

```powershell
Get-Content -LiteralPath 'D:\Code\Xdows-Security-Driver\plan.json' -Raw | ConvertFrom-Json | Out-Null
& 'D:\Code\Xdows-Security-Driver\tests\Invoke-DriverPackageSmoke.ps1'
& 'D:\Code\Xdows-Security\tests\Invoke-DriverBridgeProtocolSmoke.ps1'
& 'D:\Code\Xdows-Security\tests\Invoke-PublishAssetSmoke.ps1' -SkipBuild
& 'D:\Code\Xdows-Model\tests\Invoke-NativeConsistency.ps1' -SkipBuild
```

Use `tests\driver-validation-matrix.md` for VM, Driver Verifier, stress, and performance evidence.
