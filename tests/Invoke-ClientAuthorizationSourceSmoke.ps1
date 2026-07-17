$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Queue = Join-Path $repoRoot "Xdows-Security-Driver\Queue.c"
    Context = Join-Path $repoRoot "Xdows-Security-Driver\DriverContext.c"
    ContextHeader = Join-Path $repoRoot "Xdows-Security-Driver\DriverContext.h"
}

foreach ($path in $files.Values) {
    if (!(Test-Path -LiteralPath $path)) {
        throw "Required source file missing: $path"
    }
}

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) {
        throw "$Name was not found in $Path"
    }
}

Assert-Match $files.Queue 'WdfRequestWdmGetIrp\(Request\)(?s:.*?)Tail\.Overlay\.Thread(?s:.*?)PsGetThreadProcessId' 'kernel requestor process identity'
Assert-Match $files.Queue 'input->ClientProcessId\s*!=\s*requestorProcessId' 'spoofed client PID rejection'
Assert-Match $files.Context 'ClientConnected\s*&&(?s:.*?)ClientProcessId\s*!=\s*ULongToHandle\(RequestorProcessId\)(?s:.*?)STATUS_DEVICE_BUSY' 'connected client takeover rejection'
Assert-Match $files.ContextHeader 'XdowsIsRegisteredClientProcess' 'registered-client authorization API'

foreach ($ioctl in @(
    'HEARTBEAT',
    'GET_NEXT_EVENT',
    'SUBMIT_DECISION',
    'GET_NEXT_LOG',
    'DISCONNECT_CLIENT',
    'REGISTER_PROTECTED_PROCESS',
    'SET_VOLUNTARY_EXIT'
)) {
    Assert-Match $files.Queue "(?s)case IOCTL_XDOWS_SECURITY_$ioctl(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsRequireRegisteredClient\(Request" "$ioctl registered-client authorization"
}

foreach ($ioctl in @('AUTHORIZED_SHUTDOWN', 'SET_STARTUP_PROTECTION')) {
    Assert-Match $files.Queue "(?s)case IOCTL_XDOWS_SECURITY_$ioctl(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsRequireProtectedClient\(Request" "$ioctl protected-client authorization"
}

Assert-Match $files.Queue '(?s)REGISTER_PROTECTED_PROCESS(?:(?!case IOCTL_XDOWS_SECURITY_).)*input->ProcessId\s*!=\s*requestorProcessId' 'protected PID spoofing rejection'
Assert-Match $files.Queue '(?s)SET_VOLUNTARY_EXIT(?:(?!case IOCTL_XDOWS_SECURITY_).)*input->ProcessId\s*!=\s*requestorProcessId' 'voluntary-exit PID spoofing rejection'
Assert-Match $files.Context 'SeLocateProcessImageName(?s:.*?)Xdows-Security\.exe(?s:.*?)STATUS_ACCESS_DENIED' 'registered client executable identity validation'

Write-Host "Driver client authorization source smoke passed."
