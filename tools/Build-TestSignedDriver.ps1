param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",

    [string]$WindowsTargetPlatformVersion = "10.0.28000.0",

    [string]$CertificateSubject = "CN=Xdows Security Driver Test Certificate",

    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repoRoot "Xdows-Security-Driver.slnx"
$projectRoot = Join-Path $repoRoot "Xdows-Security-Driver"
$outputRoot = Join-Path $repoRoot (Join-Path $Platform $Configuration)
$packageDir = Join-Path $outputRoot "Xdows-Security-Driver"

$msbuild = "D:\Visual-Studio\MSBuild\Current\Bin\amd64\MSBuild.exe"
$kitBin = "D:\Windows Kits\10\bin\$WindowsTargetPlatformVersion"
$signtool = Join-Path $kitBin "x64\signtool.exe"
$inf2cat = Join-Path $kitBin "x86\inf2cat.exe"

if (!(Test-Path $msbuild)) {
    throw "MSBuild was not found: $msbuild"
}
if (!(Test-Path $signtool)) {
    throw "SignTool was not found: $signtool"
}
if (!(Test-Path $inf2cat)) {
    throw "Inf2Cat was not found: $inf2cat"
}

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object {
        $_.Subject -eq $CertificateSubject -and
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($null -eq $cert) {
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $CertificateSubject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddYears(10)
}

if (!$SkipBuild) {
    & $msbuild $solution `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform `
        /p:WindowsTargetPlatformVersion=$WindowsTargetPlatformVersion `
        /p:SignMode=Off `
        /m
    if ($LASTEXITCODE -ne 0) {
        throw "Driver build failed with exit code $LASTEXITCODE"
    }
}

$sys = Join-Path $outputRoot "Xdows-Security-Driver.sys"
$inf = Join-Path $packageDir "Xdows-Security-Driver.inf"
$packageSys = Join-Path $packageDir "Xdows-Security-Driver.sys"
$cat = Join-Path $packageDir "xdows-security-driver.cat"
$certPath = Join-Path $packageDir "Xdows-Security-Driver-Test.cer"

foreach ($required in @($sys, $inf, $packageSys)) {
    if (!(Test-Path $required)) {
        throw "Expected driver output was not found: $required"
    }
}

& $signtool sign /fd sha256 /sha1 $cert.Thumbprint $sys
if ($LASTEXITCODE -ne 0) {
    throw "Failed to test-sign driver sys with certificate $($cert.Thumbprint)"
}

Copy-Item -LiteralPath $sys -Destination $packageSys -Force

$os = if ($Platform -eq "ARM64") { "10_ARM64" } else { "10_X64" }
& $inf2cat /os:$os /driver:$packageDir\
if ($LASTEXITCODE -ne 0) {
    throw "Inf2Cat failed with exit code $LASTEXITCODE"
}

if (!(Test-Path $cat)) {
    $cat = Get-ChildItem -LiteralPath $packageDir -Filter *.cat | Select-Object -First 1 -ExpandProperty FullName
}
if (!(Test-Path $cat)) {
    throw "Catalog file was not generated in $packageDir"
}

& $signtool sign /fd sha256 /sha1 $cert.Thumbprint $cat
if ($LASTEXITCODE -ne 0) {
    throw "Failed to test-sign driver catalog with certificate $($cert.Thumbprint)"
}

Export-Certificate -Cert $cert -FilePath $certPath | Out-Null

[pscustomobject]@{
    Configuration = $Configuration
    Platform = $Platform
    CertificateThumbprint = $cert.Thumbprint
    PackageDirectory = $packageDir
    Sys = $packageSys
    Cat = $cat
    Certificate = $certPath
}
