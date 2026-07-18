$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$public = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security-Driver\Public.h")
$queue = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security-Driver\Queue.c")
$manager = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security-Driver\ProcessManager.c")
$project = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security-Driver\Xdows-Security-Driver.vcxproj")

function Assert-Match([string]$Text, [string]$Pattern, [string]$Name) {
    if ($Text -notmatch $Pattern) {
        throw "$Name was not found."
    }
}

Assert-Match $public 'XDOWS_SECURITY_PROTOCOL_VERSION\s+6u' 'protocol v6'
Assert-Match $public 'XDOWS_SECURITY_CAP_PROCESS_MANAGEMENT\s+0x00000020u' 'process management capability'
Assert-Match $public 'IOCTL_XDOWS_SECURITY_QUERY_PROCESSES' 'process query IOCTL'
Assert-Match $public 'IOCTL_XDOWS_SECURITY_OPERATE_PROCESS' 'process operation IOCTL'
Assert-Match $queue 'IOCTL_XDOWS_SECURITY_QUERY_PROCESSES(?s:.*?)XdowsRequireProtectedClient(?s:.*?)XdowsTokenAuthValidate' 'token-authorized process query'
Assert-Match $queue 'IOCTL_XDOWS_SECURITY_OPERATE_PROCESS(?s:.*?)XdowsRequireProtectedClient(?s:.*?)XdowsTokenAuthValidate' 'token-authorized process operation'
Assert-Match $manager 'ZwQuerySystemInformation' 'kernel process enumeration'
Assert-Match $manager 'Request->ProcessId\s*==\s*RequestorProcessId' 'self termination guard'
Assert-Match $manager 'XdowsSelfProtectIsProcessProtected' 'protected process guard'
Assert-Match $manager 'XdowsProcessManagerQueryCriticalState' 'critical process guard'
Assert-Match $manager 'ZwSuspendProcess' 'kernel suspend operation'
Assert-Match $manager 'ZwResumeProcess' 'kernel resume operation'
Assert-Match $manager 'ZwTerminateProcess' 'kernel terminate operation'
Assert-Match $project '<ClCompile Include="ProcessManager.c"' 'process manager source project entry'
Assert-Match $project '<ClInclude Include="ProcessManager.h"' 'process manager header project entry'

Write-Host "Driver process manager source smoke passed."
