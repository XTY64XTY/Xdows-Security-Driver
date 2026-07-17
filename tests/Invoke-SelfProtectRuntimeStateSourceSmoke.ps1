$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Public = Join-Path $repoRoot "Xdows-Security-Driver\Public.h"
    Context = Join-Path $repoRoot "Xdows-Security-Driver\DriverContext.c"
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

Assert-Match $files.Public 'XDOWS_SECURITY_PROTOCOL_VERSION\s+5u' 'protocol v5'
Assert-Match $files.Public 'ULONG\s+SelfProtectionEnabled;\s*ULONG\s+ProtectedProcessId;\s*ULONG\s+StartupProtectionEnabled;' 'self-protection runtime state fields'
Assert-Match $files.Context 'State->SelfProtectionEnabled\s*=\s*XdowsSelfProtectIsProcessProtected\(clientProcessId\)' 'active guarded PID state query'
Assert-Match $files.Context 'State->ProtectedProcessId\s*=\s*State->SelfProtectionEnabled\s*\?\s*HandleToULong\(clientProcessId\)\s*:\s*0' 'protected PID publication'
Assert-Match $files.Context 'State->StartupProtectionEnabled\s*=\s*XdowsSelfProtectIsStartupProtectionEnabled\(\)' 'startup protection state publication'
Assert-Match $files.Context 'KeReleaseSpinLock\(&g_XdowsDriverContext\.Lock,\s*oldIrql\);(?s:.*?)XdowsSelfProtectIsProcessProtected' 'self-protection query below DISPATCH level'

Write-Host "Self-protection runtime state source smoke passed."
