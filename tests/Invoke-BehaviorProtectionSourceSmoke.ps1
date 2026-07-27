$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Public = Join-Path $repoRoot "Xdows-Security-Driver\Public.h"
    Rules = Join-Path $repoRoot "Xdows-Security-Driver\BehaviorRules.c"
    Process = Join-Path $repoRoot "Xdows-Security-Driver\ProcessProtect.c"
    Injection = Join-Path $repoRoot "Xdows-Security-Driver\InjectionProtect.c"
    Registry = Join-Path $repoRoot "Xdows-Security-Driver\ModuleRegistry.c"
    Context = Join-Path $repoRoot "Xdows-Security-Driver\DriverContext.c"
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

Assert-Match $files.Public 'XDOWS_SECURITY_CAP_R0_BEHAVIOR_PROTECTION\s+0x00000080u' 'R0 behavior capability'
Assert-Match $files.Public 'XDOWS_SECURITY_MODULE_BEHAVIOR\s+0x00000020u' 'behavior module bit'
Assert-Match $files.Public 'XdowsSecurityEventBehavior\s*=\s*9' 'behavior event type'
Assert-Match $files.Public 'ULONG\s+BehaviorType;' 'behavior payload field'

$behaviorValues = @{
    VssDeletion = 1
    HiddenPowerShell = 2
    EncodedCommand = 3
    PolicyBypass = 4
    DownloadExecute = 5
    LolbinAbuse = 6
    ProcessInjection = 7
    ThreadInjection = 8
}
foreach ($entry in $behaviorValues.GetEnumerator()) {
    Assert-Match $files.Public "XdowsSecurityBehavior$($entry.Key)\s*=\s*$($entry.Value)" "$($entry.Key) behavior value"
}

foreach ($rule in @(
    'vssadmin(?s:.*?)delete(?s:.*?)shadow',
    'shadowcopy(?s:.*?)delete',
    'wbadmin(?s:.*?)delete(?s:.*?)catalog',
    '-windowstyle hidden',
    '-encodedcommand ',
    '-executionpolicy bypass',
    'downloadstring',
    'certutil(?s:.*?)-urlcache',
    'mshta(?s:.*?)javascript',
    'rundll32(?s:.*?)javascript:'
)) {
    Assert-Match $files.Rules $rule "behavior rule $rule"
}

Assert-Match $files.Registry 'XdowsTryStartModule\(XdowsModuleBehavior,\s*L"Behavior",\s*XdowsBehaviorProtectInitialize\)' 'forced behavior module startup'
Assert-Match $files.Context 'XdowsSecurityEventBehavior' 'behavior event critical queue priority'
Assert-Match $files.Process 'XdowsProcessApplyBehaviorPolicy(?s:.*?)XdowsSecurityEventBehavior(?s:.*?)XdowsSecurityEventFlagThreatConfirmed(?s:.*?)XdowsQueueEventAndWait' 'command behavior user-decision queue'
Assert-Match $files.Process 'XdowsSecurityBehaviorPolicyBypass(?s:.*?)Policy bypass allowed because user decision infrastructure was unavailable' 'policy bypass infrastructure fallback'
Assert-NotMatch $files.Process 'behavior\s*!=\s*XdowsBehaviorPolicyBypass(?s:.*?)CreateInfo->CreationStatus' 'old immediate behavior block path'
Assert-Match $files.Injection 'XdowsSecurityEventBehavior(?s:.*?)XdowsSecurityBehaviorProcessInjection(?s:.*?)XdowsSecurityBehaviorThreadInjection(?s:.*?)XdowsSecurityEventFlagThreatConfirmed' 'injection behavior correlation'

Write-Host "R0 behavior protection driver source smoke passed."
