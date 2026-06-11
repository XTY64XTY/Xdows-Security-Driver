# Xdows Security Driver Packaging and Test Signing

## Toolchain

- Visual Studio 2026 Preview MSBuild: `D:\Visual-Studio\MSBuild\Current\Bin\amd64\MSBuild.exe`
- Windows SDK / WDK: `10.0.28000.0`
- Target platform: `x64` by default
- Driver package output: `D:\Code\Xdows-Security-Driver\x64\Debug\Xdows-Security-Driver`

## Test Signing

Development builds use test signing only.

Run:

```powershell
D:\Code\Xdows-Security-Driver\tools\Build-TestSignedDriver.ps1 -Configuration Debug -Platform x64
```

The script:

1. Reuses or creates a current-user code-signing certificate named `CN=Xdows Security Driver Test Certificate`.
2. Builds the driver with WDK signing disabled to avoid stale WDK certificate state.
3. Signs `Xdows-Security-Driver.sys`.
4. Regenerates the catalog with `inf2cat`.
5. Signs `xdows-security-driver.cat`.
6. Exports `Xdows-Security-Driver-Test.cer` into the driver package directory.

Expected package files:

- `Xdows-Security-Driver.inf`
- `Xdows-Security-Driver.sys`
- `xdows-security-driver.cat`
- `Xdows-Security-Driver-Test.cer`

Windows test-signing must be enabled on the test machine:

```powershell
bcdedit /set testsigning on
```

Restart Windows after changing test-signing. Import the exported `.cer` into the test machine certificate store before installing when Windows reports the test certificate is not trusted.

## App Publish Assets

The WinUI app publish output includes:

- `Driver\Xdows-Security-Driver.inf`
- `Driver\Xdows-Security-Driver.sys`
- `Driver\xdows-security-driver.cat`
- `Driver\Xdows-Security-Driver-Test.cer`
- `Xdows-Model-Native.dll`
- `onnxruntime.dll`
- `onnxruntime_providers_shared.dll`
- `Xdows-Model.onnx`
- `Xdows-Model-Flash.onnx`
- `Xdows-Model-Pro.onnx`

## Production Signing

Production driver signing, EV certificates, Microsoft attestation signing, and HLK submission are outside the current test-signing scope. Before distributing beyond local development/test machines, replace the test-signing flow with the required Microsoft driver signing pipeline.
