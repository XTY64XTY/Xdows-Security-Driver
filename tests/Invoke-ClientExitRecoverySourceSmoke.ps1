$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Process = Join-Path $repoRoot "Xdows-Security-Driver\ProcessProtect.c"
    Context = Join-Path $repoRoot "Xdows-Security-Driver\DriverContext.c"
    Queue = Join-Path $repoRoot "Xdows-Security-Driver\Queue.c"
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

Assert-Match $files.Process 'CreateInfo\s*==\s*NULL(?s:.*?)XdowsIsRegisteredClientProcess\(HandleToULong\(ProcessId\)\)(?s:.*?)XdowsSelfProtectClearRegistration\(\)(?s:.*?)XdowsDisconnectClient\(\)' 'registered client process-exit cleanup'
Assert-Match $files.Queue '(?s)case IOCTL_XDOWS_SECURITY_DISCONNECT_CLIENT:(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsRequireRegisteredClient\(Request,\s*&requestorProcessId\)(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsSelfProtectIsProcessProtected\(ULongToHandle\(requestorProcessId\)\)(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsSelfProtectClearRegistration\(\)(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsDisconnectClient\(\)' 'explicit client disconnect self-protection cleanup'
Assert-Match $files.Context 'XdowsDisconnectClient(?s:.*?)while\s*\(!IsListEmpty\(&g_XdowsDriverContext\.PendingEvents\)\)' 'pending decision drain on disconnect'
Assert-Match $files.Context 'XdowsDisconnectClient(?s:.*?)XdowsSecurityDecisionTimeout(?s:.*?)KeSetEvent\(&pending->DecisionEvent' 'pending decision timeout wakeup'
Assert-Match $files.Context 'XdowsDisconnectClient(?s:.*?)PendingEventCount\s*=\s*0' 'pending event counter reset'

Write-Host "Driver client exit recovery source smoke passed."
