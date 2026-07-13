$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Token = Join-Path $repoRoot "Xdows-Security-Driver\TokenAuth.c"
    TokenHeader = Join-Path $repoRoot "Xdows-Security-Driver\TokenAuth.h"
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

Assert-Match $files.TokenHeader 'XdowsTokenAuthRotate' 'shutdown token rotation API'
Assert-Match $files.Token 'XdowsTokenAuthRotate(?s:.*?)XdowsTokenAuthInvalidate\(\)(?s:.*?)XdowsTokenAuthInitialize\(\)' 'fresh random token rotation'
Assert-Match $files.Context 'XdowsTokenAuthCopyOneTimeToken(?s:.*?)STATUS_NOT_FOUND(?s:.*?)XdowsTokenAuthRotate(?s:.*?)XdowsTokenAuthCopyOneTimeToken' 'token reissue after prior consumption'
Assert-Match $files.Context '!NT_SUCCESS\(tokenStatus\)(?s:.*?)XdowsDisconnectClient\(\)' 'failed token issue registration rollback'

Write-Host "Shutdown token lifecycle source smoke passed."
