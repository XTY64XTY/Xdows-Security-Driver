# Xdows-Security-Driver

Xdows Security 的内核驱动防护仓库。驱动负责事件采集、短时等待、决策缓存、自保护、注入相关句柄控制、关闭 token 校验和日志缓冲；模型推理、证书信任判断、用户确认 UI 和安装修复流程在用户态主程序中完成。

当前发布范围是开发和测试机签名，不包含生产 EV、Attestation 或 HLK 签名流程。

## Repository Layout

- `Xdows-Security-Driver\Public.h`: 内核与主程序共享的协议版本、IOCTL、枚举和结构体。
- `Xdows-Security-Driver\*.c`, `*.h`: KMDF 控制面、进程/文件/注入/自保护/token/log 模块。
- `docs\driver-protection-spec.md`: 需求追踪、决策语义、失败策略和安全边界。
- `docs\driver-packaging-signing.md`: VS/WDK 构建、签名和发布资产说明。
- `docs\protocol-and-maintenance.md`: 协议升级、跨仓库边界和维护规则。
- `tests\Invoke-DriverPackageSmoke.ps1`: 驱动包与签名烟测。
- `tests\driver-validation-matrix.md`: VM E2E、Driver Verifier、压力和性能验证矩阵。

## Prerequisites

- Windows 11 test machine or disposable VM.
- Visual Studio 2026 with C++ and WDK components.
- Windows SDK / WDK `10.0.28000.0`.
- MSBuild at `D:\Visual-Studio\MSBuild\Current\Bin\amd64\MSBuild.exe`.
- Administrator rights for install/start/stop/uninstall.
- Windows test-signing mode enabled when the target machine does not trust the development driver signature.

Enable test-signing on the VM:

```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

## Build

For the app-integrated flow, build `D:\Code\Xdows-Security\Xdows-Security.slnx` with VS2026/MSBuild as `Debug|x64`. That solution references this driver project and copies the generated package into the Xdows Security app output.

You can still build the driver directly by opening `D:\Code\Xdows-Security-Driver\Xdows-Security-Driver.slnx`, selecting `Debug|x64`, and building `Xdows-Security-Driver`.

Expected package directory:

```text
D:\Code\Xdows-Security-Driver\x64\Debug\Xdows-Security-Driver
```

Expected package files:

- `Xdows-Security-Driver.inf`
- `Xdows-Security-Driver.sys`
- `xdows-security-driver.cat`

## Install And Uninstall

The Xdows Security app creates or reuses the `Root\XdowsSecurityDriver` root device when needed, stages the package from its `Driver` output folder with `pnputil`, binds the INF to that root device, starts `Xdows-Security-Driver`, and then checks that the bridge can connect when Driver Protection is enabled.

Manual install in an elevated PowerShell session on a test machine is mainly for upgrade or diagnosis after the root device exists:

```powershell
pnputil /add-driver 'D:\Code\Xdows-Security-Driver\x64\Debug\Xdows-Security-Driver\Xdows-Security-Driver.inf' /install
sc start Xdows-Security-Driver
```

For first-time installs, prefer the Xdows Security app flow so the root device is created before `pnputil /install` binds the driver package.

Query state:

```powershell
sc query Xdows-Security-Driver
pnputil /enum-drivers | findstr /i Xdows
```

Uninstall:

```powershell
sc stop Xdows-Security-Driver
pnputil /delete-driver oemXX.inf /uninstall /force
```

Replace `oemXX.inf` with the published name returned by `pnputil /enum-drivers`.

## Validation

Local smoke tests:

```powershell
& 'D:\Code\Xdows-Security-Driver\tests\Invoke-DriverPackageSmoke.ps1'
& 'D:\Code\Xdows-Security\tests\Invoke-DriverBridgeProtocolSmoke.ps1'
& 'D:\Code\Xdows-Security\tests\Invoke-PublishAssetSmoke.ps1'
& 'D:\Code\Xdows-Model\tests\Invoke-NativeConsistency.ps1' -SkipBuild
```

`Invoke-DriverPackageSmoke.ps1` validates the package already produced by VS.

VM and Driver Verifier coverage is tracked in:

```text
D:\Code\Xdows-Security-Driver\tests\driver-validation-matrix.md
```

Do not run Driver Verifier on a non-recoverable host. Use a VM snapshot.

## Troubleshooting

- Driver load fails with signature errors: confirm the VS/WDK build signed SYS/CAT, then enable test-signing on the VM and reboot if this is a development build.
- `inf2cat` reports `DriverVer set to a date in the future`: keep `Inf2CatUseLocalTime` enabled in the project and rebuild. This avoids UTC/local-time mismatches around midnight.
- `Microsoft.Cpp.Default.props` missing: install or repair Visual Studio 2026 C++ MSBuild components and WDK integration.
- `inf2cat` or `signtool` missing: verify the `10.0.28000.0` SDK/WDK path under `D:\Windows Kits\10\bin`.
- Main app reports missing assets: build `D:\Code\Xdows-Security\Xdows-Security.slnx` with VS2026/MSBuild as `Debug|x64` so the driver and native model projects are generated before app asset collection.
- Bridge cannot connect: verify the driver service is running and `DriverProtocol.DevicePath` still matches `Public.h`.
- Protocol mismatch: run `D:\Code\Xdows-Security\tests\Invoke-DriverBridgeProtocolSmoke.ps1`.

## Safety Boundary

The driver must not load .NET, start `Xdows-Model-Caller.exe`, show UI, perform heavyweight certificate-chain work, store plaintext shutdown tokens, or wait while holding internal locks. These rules are part of the implementation contract with the main app and model repositories.
