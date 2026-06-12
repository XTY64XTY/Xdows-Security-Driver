param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$packageDir = Join-Path $repoRoot (Join-Path $Platform (Join-Path $Configuration "Xdows-Security-Driver"))
$requiredFiles = @(
    "Xdows-Security-Driver.inf",
    "Xdows-Security-Driver.sys",
    "xdows-security-driver.cat"
)

foreach ($relative in $requiredFiles) {
    $path = Join-Path $packageDir $relative
    if (!(Test-Path $path)) {
        throw "Required driver package file was not found: $path. Build Xdows-Security-Driver in VS2026 first, then rerun this smoke test."
    }

    if ((Get-Item -LiteralPath $path).Length -le 0) {
        throw "Driver package file is empty: $path"
    }
}

$infPath = Join-Path $packageDir "Xdows-Security-Driver.inf"
$infText = Get-Content -Raw -LiteralPath $infPath
foreach ($pattern in @(
    "(?i)CatalogFile\s*=\s*Xdows-Security-Driver\.cat",
    "ServiceBinary\s*=\s*%(?:12|13)%\\Xdows-Security-Driver\.sys",
    "DisplayName\s*=\s*%Xdows-Security-Driver\.SVCDESC%"
)) {
    if ($infText -notmatch $pattern) {
        throw "INF package metadata check failed: $pattern"
    }
}

$signedFiles = @(
    (Join-Path $packageDir "Xdows-Security-Driver.sys"),
    (Join-Path $packageDir "xdows-security-driver.cat")
)

$signatureResults = foreach ($path in $signedFiles) {
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -eq "NotSigned" -or $null -eq $signature.SignerCertificate) {
        throw "Expected a VS/WDK build signature on $path, but signature status was $($signature.Status)."
    }

    [pscustomobject]@{
        Path = $path
        Status = $signature.Status
        Signer = $signature.SignerCertificate.Subject
        Thumbprint = $signature.SignerCertificate.Thumbprint
    }
}

$signatureResults | Format-Table -AutoSize
Write-Host "Driver package smoke passed for package: $packageDir"
