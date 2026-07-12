[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DevicePrefix = 'ROOT\XDOWSSECURITYDRIVER\',
    [switch]$Force,
    [switch]$ScanDevicesAfterRemoval
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-XdowsSecurityDriverDevices {
    param(
        [Parameter(Mandatory)]
        [string]$Prefix
    )

    $devices = Get-PnpDevice -ErrorAction Stop
    return @(
        $devices |
            Where-Object {
                $_.InstanceId -and
                $_.InstanceId.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)
            } |
            Sort-Object InstanceId
    )
}

if (-not $DevicePrefix.EndsWith('\')) {
    $DevicePrefix = "$DevicePrefix\"
}

$matchedDevices = @(Get-XdowsSecurityDriverDevices -Prefix $DevicePrefix)

if ($matchedDevices.Count -eq 0) {
    Write-Host "No devices matched prefix: $DevicePrefix"
    exit 0
}

Write-Host "Matched $($matchedDevices.Count) device(s) with prefix: $DevicePrefix"
$matchedDevices |
    Select-Object Status, Class, FriendlyName, InstanceId |
    Format-Table -AutoSize

if (-not $Force) {
    Write-Host ''
    Write-Host 'Preview only. Re-run with -Force from an elevated PowerShell session to remove these devices.'
    Write-Host 'Example:'
    Write-Host '  powershell -ExecutionPolicy Bypass -File .\tools\Remove-XdowsSecurityDriverDevices.ps1 -Force'
    exit 0
}

if (-not (Test-IsAdministrator)) {
    throw 'Device removal requires an elevated PowerShell session. Run PowerShell as Administrator and try again.'
}

$removed = New-Object System.Collections.Generic.List[string]
$failed = New-Object System.Collections.Generic.List[string]

foreach ($device in $matchedDevices) {
    $instanceId = $device.InstanceId

    if (-not $PSCmdlet.ShouldProcess($instanceId, 'Remove PnP device')) {
        continue
    }

    Write-Host "Removing: $instanceId"
    $output = & pnputil.exe /remove-device "$instanceId" 2>&1
    $exitCode = $LASTEXITCODE

    if ($output) {
        $output | ForEach-Object { Write-Host "  $_" }
    }

    if ($exitCode -eq 0) {
        $removed.Add($instanceId)
    }
    else {
        Write-Warning "Failed to remove '$instanceId' (pnputil exit code: $exitCode)."
        $failed.Add($instanceId)
    }
}

if ($ScanDevicesAfterRemoval) {
    Write-Host 'Scanning devices...'
    $scanOutput = & pnputil.exe /scan-devices 2>&1
    if ($scanOutput) {
        $scanOutput | ForEach-Object { Write-Host "  $_" }
    }
}

Write-Host ''
Write-Host "Removed: $($removed.Count)"
Write-Host "Failed:  $($failed.Count)"

if ($failed.Count -gt 0) {
    Write-Host ''
    Write-Host 'Failed device instance IDs:'
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}
