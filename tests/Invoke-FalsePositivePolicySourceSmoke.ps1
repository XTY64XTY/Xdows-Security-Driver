$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    CodeIntegrity = Join-Path $repoRoot "Xdows-Security-Driver\CodeIntegrity.c"
    Injection = Join-Path $repoRoot "Xdows-Security-Driver\InjectionProtect.c"
    Registry = Join-Path $repoRoot "Xdows-Security-Driver\RegistryProtect.c"
}

foreach ($path in $files.Values) {
    if (!(Test-Path -LiteralPath $path)) { throw "Required source file missing: $path" }
}

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) { throw "$Name was not found in $Path" }
}

function Assert-NotMatch([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -match $Pattern) { throw "$Name is still present in $Path" }
}

Assert-Match $files.CodeIntegrity 'securityDirectoryOffset\s*=\s*dataDirectoryOffset\s*\+\s*4\s*\*\s*8' 'certificate-directory offset calculation'
Assert-Match $files.CodeIntegrity 'checksumOffset\s*\+\s*4(?s:.*?)securityDirectoryOffset(?s:.*?)securityDirectoryOffset\s*\+\s*8(?s:.*?)certificateOffset' 'Authenticode checksum and certificate-directory omission'

Assert-Match $files.Injection '#define\s+XDOWS_INJECTION_PROCESS_PRIMARY_MASK\s+\\\r?\n\s*\(PROCESS_CREATE_THREAD \| PROCESS_VM_WRITE\)' 'high-confidence process injection mask'
Assert-Match $files.Injection '#define\s+XDOWS_INJECTION_PROCESS_CONDITIONAL_MASK\s+\\\r?\n\s*\(PROCESS_VM_OPERATION \| PROCESS_SUSPEND_RESUME\)' 'conditional process injection mask'
Assert-Match $files.Injection 'Target->ConditionalMask\s*=\s*XDOWS_INJECTION_PROCESS_CONDITIONAL_MASK;' 'conditional mask wiring'

Assert-Match $files.Registry '#include\s+"codeintegrity\.h"' 'registry CI trust dependency'
Assert-Match $files.Registry 'processId\s*<=\s*4(?s:.*?)return\s+STATUS_SUCCESS' 'kernel and System registry fast allow'
Assert-Match $files.Registry 'XdowsCodeIntegrityQueryProcessTrust(?s:.*?)signatureKnown\s*&&\s*sourceTrusted(?s:.*?)return\s+STATUS_SUCCESS' 'trusted registry actor fast allow'
Assert-Match $files.Registry 'decision\.Decision\s*==\s*XdowsSecurityDecisionTimeout(?s:.*?)return\s+STATUS_SUCCESS' 'registry fail-open on timeout or bridge failure'
Assert-Match $files.Registry 'decision\.Decision\s*!=\s*XdowsSecurityDecisionBlock(?s:.*?)return\s+STATUS_SUCCESS(?s:.*?)STATUS_ACCESS_DENIED' 'explicit-block-only registry denial'
Assert-NotMatch $files.Registry 'event\.Flags\s*=\s*XdowsSecurityEventFlagUserModeRequired\s*\|\s*\r?\n\s*XdowsSecurityEventFlagThreatConfirmed' 'unconditionally confirmed registry event'

Write-Host "Injection and registry false-positive policy source smoke passed."
