# Xdows Security Driver Validation Matrix

This matrix is the B17 VM and regression checklist. It assumes a VS/WDK development-signed driver package.

## Test Environment Record

Before running VM tests, record:

- Windows edition, build, and architecture.
- VM snapshot name or recovery point.
- Secure Boot state.
- `bcdedit /enum '{current}'` test-signing state.
- Driver package path and certificate thumbprint.
- Xdows Security app commit and model commit.

## Local Smoke Tests

| Area | Command | Pass Criteria |
| --- | --- | --- |
| Driver package | `tests\Invoke-DriverPackageSmoke.ps1` | INF, SYS, and CAT exist; SYS and CAT have a VS/WDK development signature. |
| Driver build and package | Build `Xdows-Security-Driver` in VS2026, then run `tests\Invoke-DriverPackageSmoke.ps1` | Build succeeds; catalog regenerates; SYS and CAT are signed. |
| Main solution build and app assets | `D:\Code\Xdows-Security\tests\Invoke-PublishAssetSmoke.ps1` | Main solution builds the driver/native projects; app output contains driver package, native model DLL, ORT DLLs, and ONNX files. |
| First-time app install/start path | Enable Driver Protection from elevated Xdows Security on a disposable VM with no existing `Root\XdowsSecurityDriver` device | App creates the root device, installs the copied driver package, starts `Xdows-Security-Driver`, and connects the bridge. |
| Protocol mirror | `D:\Code\Xdows-Security\tests\Invoke-DriverBridgeProtocolSmoke.ps1` | Public.h, DriverProtocol.cs, and DriverBridgeClient IOCTL usage match. |
| Model parity | `D:\Code\Xdows-Model\tests\Invoke-NativeConsistency.ps1 -SkipBuild` | Native and managed results match for Standard, Flash, and Pro within tolerance. |

## VM End-to-End Tests

| Module | Positive Path | Refuse Path | Failure or Timeout Path | Evidence |
| --- | --- | --- | --- | --- |
| Process create | Launch a benign unsigned PE. Confirm event reaches app, model returns safe, process starts. | Use a known test-detection sample and select Block. Confirm process is blocked. | Kill the app bridge during a pending decision. Confirm kernel timeout policy is applied and logged. | App log, driver log, process exit result. |
| File create/write | Create and write a benign file. Confirm no block and no quarantine. | Write a test-detection file and select Block. Confirm create/write is denied or quarantined. | Stop the bridge before decision return. Confirm timeout decision and log correlation ID. | File result, quarantine entry, driver log. |
| File rename | Rename a benign file. Confirm allow. | Rename a test-detection file and select Block. Confirm rename denied. | Use a path that disappears before scan. Confirm safe failure handling. | File state, app log. |
| Process handle protection | From an unsigned helper, try to open the Xdows Security process with terminate rights. Confirm prompt. | Select Block. Confirm handle is denied. | Terminate bridge during prompt. Confirm timeout policy and self-protect log. | Helper output, driver log. |
| Thread handle protection | From an unsigned helper, try to open the main UI thread with suspend rights. Confirm prompt. | Select Block. Confirm handle is denied. | Exit app voluntarily and confirm voluntary-exit token path avoids false block. | Helper output, driver log. |
| Image load / injection | Attempt benign DLL load into a test process from a trusted signer. Confirm allow. | Attempt DLL load from unsigned helper and select Block. Confirm load is denied or process is stopped. | Bridge unavailable during image-load event. Confirm timeout behavior and no bugcheck. | Loader output, driver log. |
| Shutdown token | Stop protection from the app. Confirm authorized shutdown succeeds. | Replay or forge a shutdown IOCTL without token. Confirm denied. | Submit stale token after successful stop. Confirm denied and no plaintext token in logs. | Service state, driver log. |
| Environment repair | Start app with driver missing. Confirm environment dialog identifies missing driver and repair creates `Root\XdowsSecurityDriver` before installation. | Install with untrusted/unsigned package while test signing disabled. Confirm diagnostic is explicit. | Remove model/native assets. Confirm repair guidance reports missing files. | Dialog screenshot, app log. |

## Driver Verifier

Run only inside a disposable VM snapshot.

1. Enable standard verifier rules for `Xdows-Security-Driver.sys`.
2. Reboot the VM.
3. Install the VS/WDK development-signed driver package.
4. Run the process, file, self-protect, injection, shutdown-token, and log-pump E2E tests.
5. Query verifier state with `verifier /querysettings`.
6. Disable verifier and reboot before returning the VM to normal use.

Pass criteria:

- No bugcheck.
- No verifier violation.
- Driver unload path completes.
- App reconnect works after driver restart.

## Stress and Performance

| Metric | Method | Target |
| --- | --- | --- |
| Concurrent process events | Launch 100 benign helper processes in parallel. | No dropped events except documented queue pressure; no app crash. |
| Read-only system workload | Repeatedly open 1,000 system DLLs without write access and compare protocol-v2 counters. | Zero `FileCreate` or `FileWrite` user-mode decisions. |
| File event burst | Create/write/rename 1,000 small files in a temp directory. | At most one `FileWrite` decision per dirty handle; zero dropped events and non-induced timeouts. |
| Decision latency | Log `ElapsedMs` and measure cached/trusted decisions separately from cold model scans. | Cached/trusted p95 below 50 ms; cold scan p95 no more than 1.25x standalone model benchmark; Pro below 1 second. |
| Memory stability | Observe app and driver memory during 15 minute event burst. | No unbounded growth. |
| Timeout ratio | Disconnect bridge during controlled test windows. | Timeout count equals induced disconnect cases. |
| Idle overhead | Leave protection enabled for 15 minutes after caches warm. | Combined app/driver average CPU below 2%. |

## Evidence Template

Record each VM run as:

```text
Date:
Windows build:
Architecture:
Driver commit:
App commit:
Model commit:
Package path:
Certificate thumbprint:
Test signing state:
Driver Verifier state:
Executed tests:
Failures:
Latency median/p95:
CPU/memory observations:
Logs/screenshots:
```
