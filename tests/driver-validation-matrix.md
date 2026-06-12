# Xdows Security Driver Validation Matrix

This matrix is the B17 VM and regression checklist. It assumes test signing only.

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
| Driver package | `tests\Invoke-DriverPackageSmoke.ps1 -SkipBuild` | INF, SYS, CAT, CER exist; SYS and CAT have the test signer. |
| Driver build and package | `tools\Build-TestSignedDriver.ps1 -Configuration Debug -Platform x64` | Build succeeds; catalog regenerates; test certificate is exported. |
| Main app assets | `D:\Code\Xdows-Security\tests\Invoke-PublishAssetSmoke.ps1 -SkipBuild` | App output contains driver package, native model DLL, ORT DLLs, and ONNX files. |
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
| Environment repair | Start app with driver missing. Confirm environment dialog identifies missing driver. | Install with untrusted/unsigned package while test signing disabled. Confirm diagnostic is explicit. | Remove model/native assets. Confirm repair guidance reports missing files. | Dialog screenshot, app log. |

## Driver Verifier

Run only inside a disposable VM snapshot.

1. Enable standard verifier rules for `Xdows-Security-Driver.sys`.
2. Reboot the VM.
3. Install the test-signed driver package.
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
| File event burst | Create/write/rename 1,000 small files in a temp directory. | Driver remains responsive; average decision latency recorded. |
| Decision latency | Log elapsed time from driver event ID to submitted decision. | Median and p95 captured in test notes. |
| Memory stability | Observe app and driver memory during 15 minute event burst. | No unbounded growth. |
| Timeout ratio | Disconnect bridge during controlled test windows. | Timeout count equals induced disconnect cases. |

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
