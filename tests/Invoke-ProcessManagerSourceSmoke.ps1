$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$public = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security-Driver\Public.h")
$queue = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security-Driver\Queue.c")
$manager = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security-Driver\ProcessManager.c")
$driverContext = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security-Driver\DriverContext.c")
$project = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security-Driver\Xdows-Security-Driver.vcxproj")

function Assert-Match([string]$Text, [string]$Pattern, [string]$Name) {
    if ($Text -notmatch $Pattern) {
        throw "$Name was not found."
    }
}

Assert-Match $public 'XDOWS_SECURITY_PROTOCOL_VERSION\s+7u' 'protocol v7'
Assert-Match $public 'XDOWS_SECURITY_CAP_PROCESS_MANAGEMENT\s+0x00000020u' 'process management capability'
Assert-Match $public 'XDOWS_SECURITY_CAPABILITIES(?s:.*?)XDOWS_SECURITY_CAP_PROCESS_MANAGEMENT' 'shared capability mask includes process management'
$capabilityAssignments = [regex]::Matches(
    $driverContext,
    '(?:Response|State)->Capabilities\s*=\s*XDOWS_SECURITY_CAPABILITIES;')
if ($capabilityAssignments.Count -ne 2) {
    throw "Registration and state responses must both use the shared capability mask; found $($capabilityAssignments.Count) assignments."
}
Assert-Match $public 'IOCTL_XDOWS_SECURITY_QUERY_PROCESSES' 'process query IOCTL'
Assert-Match $public 'IOCTL_XDOWS_SECURITY_OPERATE_PROCESS' 'process operation IOCTL'
Assert-Match $queue 'IOCTL_XDOWS_SECURITY_QUERY_PROCESSES(?s:.*?)XdowsRequireProtectedClient(?s:.*?)XdowsTokenAuthValidate' 'token-authorized process query'
Assert-Match $queue 'IOCTL_XDOWS_SECURITY_OPERATE_PROCESS(?s:.*?)XdowsRequireProtectedClient(?s:.*?)XdowsTokenAuthValidate' 'token-authorized process operation'
Assert-Match $manager 'ZwQuerySystemInformation' 'kernel process enumeration'
Assert-Match $manager 'ZwQuerySystemInformation\(\s*_In_ ULONG SystemInformationClass' 'local system information query ABI declaration'
Assert-Match $manager 'ZwQueryInformationProcess\(\s*_In_ HANDLE ProcessHandle,\s*_In_ ULONG ProcessInformationClass' 'local process information query ABI declaration'
Assert-Match $manager 'XDOWS_PROCESS_ACCESS_QUERY_INFORMATION\s+0x0400u' 'local query-information access mask'
Assert-Match $manager 'XDOWS_PROCESS_ACCESS_SUSPEND_RESUME\s+0x0800u' 'local suspend-resume access mask'
Assert-Match $manager 'XDOWS_PROCESS_ACCESS_TERMINATE\s+0x0001u' 'local terminate access mask'
if ($manager -match '\(SYSTEM_INFORMATION_CLASS\)' -or
    $manager -match '\(PROCESSINFOCLASS\)' -or
    $manager -match '(?<!XDOWS_PROCESS_ACCESS_)PROCESS_QUERY_INFORMATION' -or
    $manager -match '(?<!XDOWS_PROCESS_ACCESS_)PROCESS_TERMINATE') {
    throw 'Process manager still depends on WDK declarations that are absent from the Universal KMDF header surface.'
}
Assert-Match $manager 'Request->ProcessId\s*==\s*RequestorProcessId' 'self termination guard'
Assert-Match $manager 'XdowsSelfProtectIsProcessProtected' 'protected process guard'
Assert-Match $manager 'XdowsProcessManagerQueryCriticalState' 'critical process guard'
Assert-Match $manager 'MmGetSystemRoutineAddress' 'runtime process-control routine resolution'
Assert-Match $manager 'L"ZwSuspendProcess"' 'runtime suspend routine name'
Assert-Match $manager 'L"ZwResumeProcess"' 'runtime resume routine name'
if ($manager -match 'NTSYSAPI(?s:.*?)ZwSuspendProcess\(' -or
    $manager -match 'NTSYSAPI(?s:.*?)ZwResumeProcess\(' -or
    $manager -match 'status\s*=\s*ZwSuspendProcess\(' -or
    $manager -match 'status\s*=\s*ZwResumeProcess\(') {
    throw 'Process manager still creates unsupported static imports for suspend/resume.'
}
Assert-Match $manager 'ZwTerminateProcess' 'kernel terminate operation'
Assert-Match $project '<ClCompile Include="ProcessManager.c"' 'process manager source project entry'
Assert-Match $project '<ClInclude Include="ProcessManager.h"' 'process manager header project entry'

Write-Host "Driver process manager source smoke passed."
