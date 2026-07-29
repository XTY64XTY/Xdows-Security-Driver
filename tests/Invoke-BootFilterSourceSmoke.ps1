param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Read-RequiredFile([string]$RelativePath) {
    $path = Join-Path $repoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required file missing: $path"
    }
    return Get-Content -LiteralPath $path -Raw
}

function Assert-Match([string]$Text, [string]$Pattern, [string]$Label) {
    if ($Text -notmatch $Pattern) {
        throw "Missing R0 boot protection evidence: $Label"
    }
}

$files = @{
    Public = Read-RequiredFile 'Xdows-Security-BootFilter\Public.h'
    Filter = Read-RequiredFile 'Xdows-Security-BootFilter\Driver.c'
    Inf = Read-RequiredFile 'Xdows-Security-BootFilter\Xdows-Security-BootFilter.inf'
    Project = Read-RequiredFile 'Xdows-Security-BootFilter\Xdows-Security-BootFilter.vcxproj'
    MainPublic = Read-RequiredFile 'Xdows-Security-Driver\Public.h'
    MainFile = Read-RequiredFile 'Xdows-Security-Driver\FileProtect.c'
    MainQueue = Read-RequiredFile 'Xdows-Security-Driver\Queue.c'
    Solution = Read-RequiredFile 'Xdows-Security-Driver.slnx'
}

Assert-Match $files.Public 'XDOWS_BOOT_MAX_REQUEST_BYTES\s*\(1u\s*\*\s*1024u\s*\*\s*1024u\)' '1 MiB per-request cap'
Assert-Match $files.Public 'XDOWS_BOOT_MAX_PENDING_BYTES\s*\(8u\s*\*\s*1024u\s*\*\s*1024u\)' '8 MiB global pending cap'
Assert-Match $files.Public 'XDOWS_BOOT_DECISION_TIMEOUT_MS\s*25000u' '25-second decision timeout'
Assert-Match $files.Filter 'IoAttachDeviceToDeviceStackSafe' 'live storage stack attachment'
Assert-Match $files.Filter 'Tail\.Overlay\.Thread(?s:.*?)PsGetThreadProcessId' 'IRP requestor process attribution'
Assert-Match $files.Filter 'Harddisk%lu\\\\Partition0' 'selected physical disk attachment'
Assert-Match $files.Filter 'XdowsBootWriteIntersectsProtectedRange' 'protected raw range intersection'
Assert-Match $files.Filter 'BlockedNoClientCount\+\+' 'missing bridge fail-closed counter'
Assert-Match $files.Filter 'STATUS_ACCESS_DENIED' 'blocked raw write completion'
Assert-Match $files.Filter 'IoWriteErrorLogEntry' 'kernel error-log persistence'
Assert-Match $files.Filter 'XdowsBootDecisionAllow' 'explicit user allow forwarding'
Assert-Match $files.Inf 'ServiceType\s*=\s*1' 'kernel driver service type'
Assert-Match $files.Inf 'StartType\s*=\s*3' 'demand start without reboot'
Assert-Match $files.Project '<DriverType>WDM</DriverType>' 'dedicated WDM filter project'
Assert-Match $files.Solution 'Xdows-Security-BootFilter/Xdows-Security-BootFilter\.vcxproj' 'solution integration'

Assert-Match $files.MainPublic 'XdowsSecurityEventBootWrite\s*=\s*10' 'EFI and BCD write event'
Assert-Match $files.MainPublic 'IOCTL_XDOWS_SECURITY_SET_BOOT_PROTECTION' 'boot-volume configuration IOCTL'
Assert-Match $files.MainFile 'EFI\\\\Microsoft\\\\Boot' 'EFI path protection'
Assert-Match $files.MainFile 'Boot\\\\BCD' 'BCD path protection'
Assert-Match $files.MainFile 'XdowsFileBootMutationMustBeBlocked' 'fail-closed boot-file policy'
Assert-Match $files.MainFile 'XdowsFilePostCreate(?s:.*?)FltCancelFileOpen(?s:.*?)STATUS_ACCESS_DENIED' 'boot handle context fail-closed policy'
Assert-Match $files.MainFile 'XdowsSecurityEventFlagThreatConfirmed' 'direct user decision event'
Assert-Match $files.MainQueue 'case IOCTL_XDOWS_SECURITY_SET_BOOT_PROTECTION' 'protected-client configuration dispatch'
Assert-Match $files.MainQueue 'XdowsRequireProtectedClient\(Request' 'configuration caller authorization'

Write-Host 'R0 boot filter source smoke passed.'
