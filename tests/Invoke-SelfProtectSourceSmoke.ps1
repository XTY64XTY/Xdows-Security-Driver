$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$selfProtect = Join-Path $repoRoot "Xdows-Security-Driver\SelfProtect.c"

if (!(Test-Path -LiteralPath $selfProtect)) {
    throw "Required source file missing: $selfProtect"
}

$text = Get-Content -LiteralPath $selfProtect -Raw

function Assert-Match([string]$Pattern, [string]$Name) {
    if ($text -notmatch $Pattern) {
        throw "$Name was not found in $selfProtect"
    }
}

Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)PROCESS_TERMINATE' 'process termination restriction'
Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)PROCESS_SUSPEND_RESUME' 'process suspension restriction'
Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)PROCESS_CREATE_THREAD' 'remote thread restriction'
Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)PROCESS_VM_OPERATION' 'remote memory operation restriction'
Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)PROCESS_VM_WRITE' 'remote memory write restriction'
Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)PROCESS_VM_READ' 'remote memory and shutdown-token read restriction'
Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)PROCESS_SET_QUOTA' 'working-set quota restriction'
Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)WRITE_DAC' 'process security descriptor restriction'
Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)WRITE_OWNER' 'process owner restriction'
Assert-Match 'XDOWS_GUARD_PROCESS_RESTRICTED_MASK(?s:.*?)DELETE' 'process delete restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)THREAD_TERMINATE' 'thread termination restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)THREAD_SUSPEND_RESUME' 'thread suspension restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)THREAD_GET_CONTEXT' 'thread context read restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)THREAD_SET_CONTEXT' 'thread context injection restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)THREAD_SET_INFORMATION' 'thread information restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)THREAD_SET_THREAD_TOKEN' 'thread token replacement restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)THREAD_IMPERSONATE' 'thread impersonation restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)THREAD_DIRECT_IMPERSONATION' 'direct thread impersonation restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)WRITE_DAC' 'thread security descriptor restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)WRITE_OWNER' 'thread owner restriction'
Assert-Match 'XDOWS_GUARD_THREAD_RESTRICTED_MASK(?s:.*?)DELETE' 'thread delete restriction'
Assert-Match 'Info->Operation\s*==\s*OB_OPERATION_HANDLE_CREATE' 'handle creation coverage'
Assert-Match 'Info->Operation\s*==\s*OB_OPERATION_HANDLE_DUPLICATE' 'handle duplication coverage'
Assert-Match 'PsGetThreadProcessId' 'all guarded-process thread coverage'
Assert-Match 'callerProcessId\s*=\s*PsGetCurrentProcessId\(\)' 'caller process identity lookup'
Assert-Match 'targetProcessId\s*==\s*callerProcessId' 'guarded process self-handle compatibility'

Write-Host "Self-protection source smoke passed."
