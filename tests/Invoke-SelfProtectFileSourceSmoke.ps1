$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    SelfProtect = Join-Path $repoRoot "Xdows-Security-Driver\SelfProtect.c"
    SelfProtectHeader = Join-Path $repoRoot "Xdows-Security-Driver\SelfProtect.h"
    FileProtect = Join-Path $repoRoot "Xdows-Security-Driver\FileProtect.c"
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

Assert-Match $files.SelfProtect 'PsLookupProcessByProcessId(?s:.*?)SeLocateProcessImageName' 'kernel-derived protected image path'
Assert-Match $files.SelfProtect 'ProtectedDirectory' 'guarded installation directory state'
Assert-Match $files.SelfProtect 'RtlPrefixUnicodeString(?s:.*?)Path->Length\s*==\s*directory\.Length(?s:.*?)Path->Buffer\[directoryChars\]' 'path prefix boundary validation'
Assert-Match $files.SelfProtect 'RequestorProcessId\s*!=\s*g_SelfGuard\.GuardedProcessId' 'external requestor mutation restriction'
Assert-Match $files.SelfProtectHeader 'XdowsSelfProtectShouldBlockFileMutation' 'file mutation authorization API'

Assert-Match $files.FileProtect '#include\s+"selfprotect\.h"' 'self-protection integration'
Assert-Match $files.FileProtect 'XdowsFileDenyProtectedMutation(?s:.*?)XdowsSelfProtectShouldBlockFileMutation' 'kernel file mutation policy call'
Assert-Match $files.FileProtect 'XdowsFilePreCreate(?s:.*?)XdowsFileIsWriteOpen\(Data\)(?s:.*?)XdowsFileDenyProtectedMutation' 'write-open tamper block'
Assert-Match $files.FileProtect 'XdowsFileIsWriteOpen(?s:.*?)DELETE(?s:.*?)FILE_WRITE_ATTRIBUTES' 'delete and metadata mutation access coverage'
Assert-Match $files.FileProtect 'FileDispositionInformation(?s:.*?)FileDispositionInformationEx' 'delete disposition coverage'
Assert-Match $files.FileProtect 'XdowsFilePreSetInformation(?s:.*?)XdowsFileDenyProtectedMutation\(Data,\s*&name->Name' 'source rename or delete protection'
Assert-Match $files.FileProtect 'XdowsFilePreSetInformation(?s:.*?)XdowsFileDenyProtectedMutation\(Data,\s*&destinationName->Name' 'destination replacement protection'
Assert-Match $files.FileProtect 'STATUS_ACCESS_DENIED' 'tamper denial status'

Write-Host "Self-protection file tamper source smoke passed."
