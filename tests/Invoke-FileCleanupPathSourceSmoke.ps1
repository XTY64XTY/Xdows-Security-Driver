$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$filePath = Join-Path $repoRoot "Xdows-Security-Driver\FileProtect.c"
$text = Get-Content -LiteralPath $filePath -Raw

function Assert-Match([string]$Pattern, [string]$Name) {
    if ($text -notmatch $Pattern) {
        throw "$Name was not found in $filePath"
    }
}

Assert-Match 'typedef struct _XDOWS_CLEANUP_SCAN_CONTEXT(?s:.*?)OriginatorPid(?s:.*?)Path\[XDOWS_SECURITY_MAX_PATH_CHARS\]' 'owned cleanup scan context'
Assert-Match 'XdowsFilePreCleanup(?s:.*?)XdowsFileAcquireName\(Data,\s*&name\)(?s:.*?)XdowsFileCopyNameInto\(\s*scanContext->Path' 'pre-cleanup stable path capture'
Assert-Match 'XdowsFilePreCleanup(?s:.*?)XdowsFilePassesSizeGate\(FltObjects\)' 'pre-cleanup size gate'
Assert-Match 'XdowsFilePostCleanupWhenSafe(?s:.*?)scanContext->Path(?s:.*?)XdowsSecurityEventFileWrite' 'post-cleanup saved path event'
Assert-Match 'XdowsFilePostCleanupWhenSafe(?s:.*?)ExFreePoolWithTag\(scanContext' 'safe completion context release'
Assert-Match 'FLTFL_POST_OPERATION_DRAINING(?s:.*?)ExFreePoolWithTag\(CompletionContext' 'draining completion context release'
Assert-Match 'Cleanup scan could not be scheduled safely(?s:.*?)ExFreePoolWithTag\(CompletionContext' 'unsafe scheduling completion context release'

$postSafe = [regex]::Match(
    $text,
    'XdowsFilePostCleanupWhenSafe(?<body>(?s:.*?))\r?\n}\r?\n\r?\nstatic\r?\nFLT_POSTOP_CALLBACK_STATUS\r?\nXdowsFilePostCleanup')
if (!$postSafe.Success) {
    throw "Safe cleanup callback body was not found."
}
if ($postSafe.Groups['body'].Value -match 'XdowsFileAcquireName|FltGetStreamHandleContext|FltQueryInformationFile') {
    throw "Post-cleanup still performs unstable file metadata queries."
}

Write-Host "File cleanup stable-path source smoke passed."
