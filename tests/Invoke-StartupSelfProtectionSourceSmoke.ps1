$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Public = Join-Path $repoRoot "Xdows-Security-Driver\Public.h"
    Queue = Join-Path $repoRoot "Xdows-Security-Driver\Queue.c"
    Context = Join-Path $repoRoot "Xdows-Security-Driver\DriverContext.c"
    SelfProtect = Join-Path $repoRoot "Xdows-Security-Driver\SelfProtect.c"
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

Assert-Match $files.SelfProtect '[\\]{2}REGISTRY[\\]{2}MACHINE[\\]{2}SOFTWARE[\\]{2}Microsoft[\\]{2}Windows[\\]{2}CurrentVersion[\\]{2}Run' 'fixed HKLM Run key'
Assert-Match $files.SelfProtect 'Xdows-Security' 'fixed Xdows Security startup value'
Assert-Match $files.SelfProtect 'CmRegisterCallbackEx' 'registry callback registration'
Assert-Match $files.SelfProtect 'CmCallbackGetKeyObjectIDEx' 'registry object path resolution'
Assert-Match $files.SelfProtect 'RegNtPreSetValueKey' 'startup value replacement protection'
Assert-Match $files.SelfProtect 'RegNtPreDeleteValueKey' 'startup value deletion protection'
Assert-Match $files.SelfProtect 'RegNtPreDeleteKey' 'startup key deletion protection'
Assert-Match $files.SelfProtect 'RegNtPreRenameKey' 'startup key rename protection'
Assert-Match $files.SelfProtect 'RegNtPreRestoreKey' 'startup key restore protection'
Assert-Match $files.SelfProtect 'RegNtPreReplaceKey' 'startup key replacement protection'
Assert-Match $files.SelfProtect 'RegNtPreUnLoadKey' 'startup hive unload protection'
Assert-Match $files.SelfProtect 'guardedProcessId\s*==\s*PsGetCurrentProcessId\(\)' 'guarded main process registry exemption'
Assert-Match $files.SelfProtect 'STATUS_ACCESS_DENIED' 'external registry mutation rejection'
Assert-Match $files.SelfProtect 'ZwQueryValueKey' 'startup state restored from registry at driver initialization'
Assert-Match $files.SelfProtect 'XdowsSelfProtectSetStartupProtection' 'startup protection state control'
Assert-Match $files.Context 'SeLocateProcessImageName(?s:.*?)Xdows-Security\.exe' 'registered client image validation'
Assert-Match $files.Public 'IOCTL_XDOWS_SECURITY_SET_STARTUP_PROTECTION' 'startup protection IOCTL'
Assert-Match $files.Queue '(?s)case IOCTL_XDOWS_SECURITY_SET_STARTUP_PROTECTION(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsRequireProtectedClient\(Request' 'startup control protected-client authorization'
Assert-Match $files.Queue '(?s)case IOCTL_XDOWS_SECURITY_SET_STARTUP_PROTECTION(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsSelfProtectSetStartupProtection' 'startup protection state update dispatch'

Write-Host "Startup self-protection source smoke passed."
