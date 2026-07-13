$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$fileProtectPath = Join-Path $repoRoot "Xdows-Security-Driver\FileProtect.c"

if (!(Test-Path -LiteralPath $fileProtectPath)) {
    throw "Required source file missing: $fileProtectPath"
}

$fileProtect = Get-Content -LiteralPath $fileProtectPath -Raw

function Assert-Match([string]$Pattern, [string]$Name) {
    if ($fileProtect -notmatch $Pattern) {
        throw "$Name was not found in $fileProtectPath"
    }
}

function Assert-NotMatch([string]$Pattern, [string]$Name) {
    if ($fileProtect -match $Pattern) {
        throw "$Name is still present in $fileProtectPath"
    }
}

Assert-Match 'MajorFunction\s*=\s*IRP_MJ_WRITE' 'write callback registration'
Assert-Match 'PreOperation\s*=\s*XdowsFilePreWrite' 'write pre-operation callback'
Assert-Match 'XdowsFilePreWrite(?s:.*?)FltSetStreamHandleContext' 'write-time dirty marking'
Assert-NotMatch 'PostOperation\s*=\s*XdowsFilePostCreate' 'write-open dirty approximation'
Assert-Match 'XdowsFilePreSetInformation(?s:.*?)FltGetDestinationFileNameInformation' 'rename destination path resolution'
Assert-Match '!XdowsFileIsScannablePath\(&name->Name\)\s*&&\s*!XdowsFileIsScannablePath\(&destinationName->Name\)' 'source and destination rename filtering'
Assert-Match 'XdowsFilePostCleanup(?s:.*?)FltDoCompletionProcessingWhenSafe(?s:.*?)XdowsFilePostCleanupWhenSafe' 'safe cleanup completion dispatch'
Assert-Match 'XdowsFilePostCleanupWhenSafe(?s:.*?)if\s*\(!NT_SUCCESS\(Data->IoStatus\.Status\)\)' 'safe cleanup status gate'

Write-Host "File protection source smoke passed."
