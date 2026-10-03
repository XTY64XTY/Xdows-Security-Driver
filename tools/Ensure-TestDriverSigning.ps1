param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDirectory,

    [Parameter(Mandatory = $true)]
    [string]$SignTool,

    [string]$Subject = "Xdows Security Driver Test Certificate",

    [string]$DriverFileName = "Xdows-Security-Driver.sys"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $PackageDirectory -PathType Container)) {
    throw "Driver package directory was not found: $PackageDirectory"
}

if (-not (Test-Path -LiteralPath $SignTool -PathType Leaf)) {
    throw "signtool.exe was not found: $SignTool"
}

$subjectName = "CN=$Subject"
$codeSigningOid = "1.3.6.1.5.5.7.3.3"

function Test-CodeSigningCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $enhancedKeyUsages = @(
        $Certificate.Extensions |
            Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
    )

    if ($enhancedKeyUsages.Count -eq 0) {
        return $true
    }

    foreach ($extension in $enhancedKeyUsages) {
        foreach ($usage in $extension.EnhancedKeyUsages) {
            if ($usage.Value -eq $codeSigningOid) {
                return $true
            }
        }
    }

    return $false
}

function Get-TestCertificate {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)

    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try {
        $minimumExpiration = (Get-Date).AddDays(30)
        return @(
            $store.Certificates |
                Where-Object { $_.Subject -eq $subjectName -and $_.NotAfter -gt $minimumExpiration } |
                Where-Object { $_.HasPrivateKey } |
                Where-Object { Test-CodeSigningCertificate -Certificate $_ } |
                Sort-Object NotAfter -Descending
        ) | Select-Object -First 1
    }
    finally {
        $store.Close()
    }
}

function New-TestCertificate {
    $newSelfSignedCertificate = Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue
    if ($null -ne $newSelfSignedCertificate) {
        try {
            New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject $subjectName `
                -CertStoreLocation Cert:\CurrentUser\My `
                -KeyExportPolicy Exportable `
                -KeyLength 2048 `
                -HashAlgorithm SHA256 `
                -NotAfter (Get-Date).AddYears(10) | Out-Null

            $created = Get-TestCertificate
            if ($null -ne $created) {
                return $created
            }
        }
        catch {
            Write-Warning "New-SelfSignedCertificate failed: $($_.Exception.Message). Falling back to MakeCert."
        }
    }

    $makeCert = Join-Path (Split-Path -Parent $SignTool) "MakeCert.exe"
    if (-not (Test-Path -LiteralPath $makeCert -PathType Leaf)) {
        throw "MakeCert.exe was not found next to signtool.exe: $makeCert"
    }

    $temporaryCertificatePath = Join-Path $PackageDirectory "Xdows-Security-Driver-Test.created.cer"
    & $makeCert -r -pe -ss My -sr CurrentUser -n $subjectName -eku $codeSigningOid -len 2048 -a sha256 -cy end $temporaryCertificatePath
    if ($LASTEXITCODE -ne 0) {
        throw "MakeCert failed to create the driver test certificate."
    }

    Remove-Item -LiteralPath $temporaryCertificatePath -Force -ErrorAction SilentlyContinue

    $createdByMakeCert = Get-TestCertificate
    if ($null -eq $createdByMakeCert) {
        throw "The driver test certificate was created, but could not be reopened from CurrentUser\My."
    }

    return $createdByMakeCert
}

$cert = Get-TestCertificate
if ($null -eq $cert) {
    $cert = New-TestCertificate
}

$certificatePath = Join-Path $PackageDirectory "Xdows-Security-Driver-Test.cer"
[System.IO.File]::WriteAllBytes(
    $certificatePath,
    $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

$driver = Join-Path $PackageDirectory $DriverFileName
$catalog = Get-ChildItem -LiteralPath $PackageDirectory -Filter "*.cat" |
    Sort-Object Name |
    Select-Object -First 1

if (-not (Test-Path -LiteralPath $driver -PathType Leaf)) {
    throw "Driver binary was not found: $driver"
}

if ($null -eq $catalog) {
    throw "Driver catalog was not found in $PackageDirectory"
}

foreach ($file in @($driver, $catalog.FullName)) {
    & $SignTool sign /fd SHA256 /sha1 $cert.Thumbprint $file
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed for $file"
    }
}

Write-Host "Signed driver package with $($cert.Thumbprint)"
