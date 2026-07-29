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
Assert-Match 'PostOperation\s*=\s*XdowsFilePostCreate' 'boot handle post-create callback'
Assert-Match 'XdowsFilePreCreate(?s:.*?)XdowsFileIsProtectedBootPath(?s:.*?)FLT_PREOP_SUCCESS_WITH_CALLBACK' 'boot-only create completion context'
Assert-Match 'XdowsFilePostCreate(?s:.*?)BootProtected\s*=\s*TRUE(?s:.*?)FltSetStreamHandleContext' 'retained boot path handle context'
Assert-Match 'XdowsFilePostCreate(?s:.*?)FltCancelFileOpen(?s:.*?)STATUS_ACCESS_DENIED' 'boot handle context failure blocks open'
Assert-Match 'XdowsFilePreSetInformation(?s:.*?)FltGetDestinationFileNameInformation' 'rename destination path resolution'
Assert-Match '!XdowsFileIsScannablePath\(&name->Name\)\s*&&\s*!XdowsFileIsScannablePath\(&destinationName->Name\)' 'source and destination rename filtering'
Assert-Match 'InfoClass\s*==\s*FileLinkInformation\s*\|\|(?s:.*?)InfoClass\s*==\s*FileLinkInformationEx' 'hard-link name change coverage'
Assert-Match 'XdowsFilePreCreate(?s:.*?)KeGetCurrentIrql\(\)\s*>\s*APC_LEVEL' 'create callback documented IRQL ceiling'
Assert-Match 'XdowsFilePreSetInformation(?s:.*?)KeGetCurrentIrql\(\)\s*>\s*APC_LEVEL' 'name-change callback documented IRQL ceiling'
Assert-NotMatch 'XdowsFileConsultPolicy(?s:.*?)KeGetCurrentIrql\(\)\s*!=\s*PASSIVE_LEVEL' 'overly strict ordinary file-policy IRQL gate'
Assert-Match 'XdowsFileBootMutationMustBeBlocked(?s:.*?)KeGetCurrentIrql\(\)\s*!=\s*PASSIVE_LEVEL(?s:.*?)STATUS_ACCESS_DENIED' 'boot mutation fail-closed IRQL policy'
Assert-Match 'XdowsFilePostCleanup(?s:.*?)FltDoCompletionProcessingWhenSafe(?s:.*?)XdowsFilePostCleanupWhenSafe' 'safe cleanup completion dispatch'
Assert-Match 'XdowsFilePostCleanupWhenSafe(?s:.*?)if\s*\(!NT_SUCCESS\(Data->IoStatus\.Status\)\)' 'safe cleanup status gate'
Assert-Match 'FltStartFiltering(?s:.*?)FileProtectionEnabled\s*=\s*TRUE' 'active file-module state publication'
Assert-Match 'XdowsFileProtectShutdown(?s:.*?)FileProtectionEnabled\s*=\s*FALSE' 'file-module shutdown state clearing'

Write-Host "File protection source smoke passed."
