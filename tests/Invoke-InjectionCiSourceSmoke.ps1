$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Header = Join-Path $repoRoot "Xdows-Security-Driver\CodeIntegrity.h"
    CodeIntegrity = Join-Path $repoRoot "Xdows-Security-Driver\CodeIntegrity.c"
    Injection = Join-Path $repoRoot "Xdows-Security-Driver\InjectionProtect.c"
    Registry = Join-Path $repoRoot "Xdows-Security-Driver\ModuleRegistry.c"
    Project = Join-Path $repoRoot "Xdows-Security-Driver\Xdows-Security-Driver.vcxproj"
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

Assert-Match $files.Registry 'XdowsTryStartModule\(XdowsModuleInjection,\s*L"Injection",\s*XdowsInjectionProtectInitialize\)' 'injection module startup'
Assert-Match $files.Project '<ClCompile Include="CodeIntegrity\.c"' 'CI source project inclusion'
Assert-Match $files.Project '<ClInclude Include="CodeIntegrity\.h"' 'CI header project inclusion'
Assert-Match $files.CodeIntegrity 'CiValidateFileObject' 'ci.dll file validation export'
Assert-Match $files.CodeIntegrity 'CiFreePolicyInfo' 'ci.dll policy cleanup export'
Assert-Match $files.CodeIntegrity 'XDOWS_CI_POLICY_ACCEPT_ANY_ROOT_CERTIFICATE\s+0x00000020u' 'trusted third-party root policy'
Assert-Match $files.CodeIntegrity 'PsSetCreateProcessNotifyRoutineEx\(XdowsCiProcessNotify,\s*FALSE\)' 'asynchronous process validation registration'
Assert-Match $files.CodeIntegrity 'CreateInfo->FileObject(?s:.*?)XdowsCiQueueValidation\(Process,\s*CreateInfo->FileObject\)' 'create-notify file object capture'
Assert-Match $files.CodeIntegrity 'IoQueueWorkItem(?s:.*?)XdowsCiWorkItemRoutine' 'CI worker queue'
Assert-Match $files.CodeIntegrity 'ExWaitForRundownProtectionRelease' 'CI worker shutdown drain'
Assert-Match $files.CodeIntegrity 'FreePolicyInfo\(&timestampPolicy\)(?s:.*?)FreePolicyInfo\(&signerPolicy\)' 'CI policy cleanup'
Assert-Match $files.Injection 'XdowsCodeIntegrityQueryProcessTrust(?s:.*?)signatureKnown\s*&&\s*sourceTrusted' 'signed source fast allow'
Assert-NotMatch $files.Injection 'XdowsCodeIntegrityValidateProcessImage' 'synchronous CI validation in Ob callback'

Write-Host "Process/thread injection ci.dll source smoke passed."
