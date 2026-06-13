# Xdows Security Driver Build And Signing

## Toolchain

- Visual Studio 2026 Preview MSBuild: `D:\Visual-Studio\MSBuild\Current\Bin\amd64\MSBuild.exe`
- Windows SDK / WDK: `10.0.28000.0`
- Target platform: `x64` by default
- Driver package output: `D:\Code\Xdows-Security-Driver\x64\Debug\Xdows-Security-Driver`

## Recommended Build

For app-integrated local development, build the main Xdows Security solution:

```powershell
& 'D:\Visual-Studio\MSBuild\Current\Bin\amd64\MSBuild.exe' `
  'D:\Code\Xdows-Security\Xdows-Security.slnx' `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /p:WindowsTargetPlatformVersion=10.0.28000.0 `
  /p:SignMode=Off `
  /m
```

The main solution references `Xdows-Security-Driver.vcxproj`, then copies the generated driver package into the Xdows Security app output.

For driver-only validation, build the driver directly from Visual Studio 2026:

1. Open `D:\Code\Xdows-Security-Driver\Xdows-Security-Driver.slnx`.
2. Select `Debug|x64`.
3. Build `Xdows-Security-Driver`.

VS/WDK generates the package and signs both:

- `D:\Code\Xdows-Security-Driver\x64\Debug\Xdows-Security-Driver.sys`
- `D:\Code\Xdows-Security-Driver\x64\Debug\Xdows-Security-Driver\xdows-security-driver.cat`

Expected package files:

- `Xdows-Security-Driver.inf`
- `Xdows-Security-Driver.sys`
- `xdows-security-driver.cat`

The project sets `Inf2CatUseLocalTime=true` for all configurations so WDK `inf2cat` does not reject a freshly stamped local `DriverVer` around midnight as a future date.

## Test Machine Requirements

Development driver packages still require a loadable test/development signature on the target machine. If Windows refuses to load the driver, enable test-signing on the VM and reboot:

```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

Production driver signing, EV certificates, Microsoft attestation signing, and HLK submission are outside the current local development flow.

## App Publish Assets

After building `Xdows-Security.slnx`, the WinUI app output includes:

- `Driver\Xdows-Security-Driver.inf`
- `Driver\Xdows-Security-Driver.sys`
- `Driver\xdows-security-driver.cat`
- `Xdows-Model-Native.dll`
- `onnxruntime.dll`
- `onnxruntime_providers_shared.dll`
- `Xdows-Model.onnx`
- `Xdows-Model-Flash.onnx`
- `Xdows-Model-Pro.onnx`
