$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$publicHeaderPath = Join-Path $repoRoot "Xdows-Security-Driver\Public.h"
$contextHeaderPath = Join-Path $repoRoot "Xdows-Security-Driver\DriverContext.h"
$contextSourcePath = Join-Path $repoRoot "Xdows-Security-Driver\DriverContext.c"
$processSourcePath = Join-Path $repoRoot "Xdows-Security-Driver\ProcessProtect.c"
$injectionSourcePath = Join-Path $repoRoot "Xdows-Security-Driver\InjectionProtect.c"

foreach ($path in @($publicHeaderPath, $contextHeaderPath, $contextSourcePath, $processSourcePath, $injectionSourcePath)) {
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

Assert-Match $publicHeaderPath 'XDOWS_SECURITY_PROTOCOL_VERSION\s+7u' 'protocol v7'
Assert-Match $publicHeaderPath 'XdowsSecurityDecisionPending\s*=\s*4' 'pending user-decision verdict'
Assert-Match $contextHeaderPath 'XDOWS_SECURITY_USER_DECISION_TIMEOUT_MS\s+25000u' '25 second user-decision timeout'
Assert-Match $contextSourcePath 'Decision->Decision\s*==\s*XdowsSecurityDecisionPending' 'pending verdict handling'
Assert-Match $contextSourcePath 'KeResetEvent\(&pending->DecisionEvent\)' 'safe decision-event reset'
Assert-Match $contextSourcePath 'userDecisionPending\s*=\s*TRUE' 'user-decision phase tracking'
Assert-Match $contextSourcePath 'userDecisionPending\s*\?\s*XdowsSecurityDecisionBlock\s*:\s*XdowsSecurityDecisionTimeout' 'timeout policy split'
Assert-Match $contextSourcePath 'user-decision-timeout-blocked' 'timeout block diagnostic reason'
Assert-Match $contextSourcePath 'User decision timed out; operation blocked' 'kernel timeout block log'
Assert-Match $processSourcePath 'XDOWS_PROCESS_LAUNCH_VERDICT_TIMEOUT_MS\s+5000u' 'bounded process scan timeout'
Assert-Match $injectionSourcePath 'XDOWS_INJECTION_CONSULT_TIMEOUT_MS\s+500u' 'short injection infrastructure timeout'
Assert-NotMatch $injectionSourcePath 'XDOWS_INJECTION_CONSULT_TIMEOUT_MS\s+25000u' 'global 25 second injection timeout'

Write-Host "User decision timeout source smoke passed."
