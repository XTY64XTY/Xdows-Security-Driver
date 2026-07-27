$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Public = Join-Path $repoRoot "Xdows-Security-Driver\Public.h"
    Registry = Join-Path $repoRoot "Xdows-Security-Driver\ModuleRegistry.c"
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

foreach ($module in @('TOKEN_AUTH', 'PROCESS', 'FILE', 'INJECTION', 'SELF_PROTECT', 'BEHAVIOR')) {
    Assert-Match $files.Public "XDOWS_SECURITY_MODULE_$module" "$module module bit"
}

Assert-Match $files.Public 'XDOWS_SECURITY_REQUIRED_MODULES' 'required module mask'
Assert-Match $files.Public 'ULONG\s+ActiveModules;' 'active module state field'
Assert-Match $files.Registry 'XdowsModulesGetActiveMask' 'runtime module mask query'
Assert-Match $files.Context 'State->ActiveModules\s*=\s*XdowsModulesGetActiveMask\(\)' 'state module mask publication'

Write-Host "Driver module health source smoke passed."
