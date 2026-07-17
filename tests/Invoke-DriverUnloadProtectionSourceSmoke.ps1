$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Driver = Join-Path $repoRoot "Xdows-Security-Driver\Driver.c"
    DriverHeader = Join-Path $repoRoot "Xdows-Security-Driver\Driver.h"
    FileProtect = Join-Path $repoRoot "Xdows-Security-Driver\FileProtect.c"
    FileProtectHeader = Join-Path $repoRoot "Xdows-Security-Driver\FileProtect.h"
    Queue = Join-Path $repoRoot "Xdows-Security-Driver\Queue.c"
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

Assert-Match $files.FileProtectHeader 'XdowsFileProtectAuthorizeUnload' 'authorized unload API'
Assert-Match $files.FileProtectHeader 'XdowsFileProtectRevokeUnload' 'unload authorization revocation API'
Assert-Match $files.DriverHeader 'XdowsSecurityDriverLockUnload' 'SCM unload lock API'
Assert-Match $files.DriverHeader 'XdowsSecurityDriverAuthorizeUnload' 'SCM unload authorization API'
Assert-Match $files.DriverHeader 'XdowsSecurityDriverRevokeUnload' 'SCM unload authorization revocation API'
Assert-Match $files.Driver 'XdowsSecurityDriverLockUnload(?s:.*?)DriverObject->DriverUnload(?s:.*?)InterlockedExchangePointer(?s:.*?)NULL' 'secure SCM unload default'
Assert-Match $files.Driver 'XdowsSecurityDriverAuthorizeUnload(?s:.*?)InterlockedExchangePointer(?s:.*?)FrameworkUnload' 'token-authorized WDF unload restoration'
Assert-Match $files.Driver 'XdowsSecurityDriverRevokeUnload(?s:.*?)InterlockedExchangePointer(?s:.*?)NULL' 'SCM unload authorization revocation'
Assert-Match $files.Driver 'XdowsSecurityDriverCreateControlDevice(?s:.*?)XdowsSecurityDriverLockUnload\(DriverObject\)' 'SCM unload lock after successful driver initialization'
Assert-Match $files.FileProtect 'XdowsFileFilterUnload(?s:.*?)UnloadPermitted(?s:.*?)STATUS_FLT_DO_NOT_DETACH' 'unauthorized filter unload rejection'
Assert-Match $files.FileProtect 'XdowsFileProtectAuthorizeUnload(?s:.*?)InterlockedExchange' 'atomic authorized unload transition'
Assert-Match $files.FileProtect 'XdowsFileProtectRevokeUnload(?s:.*?)InterlockedExchange' 'atomic unload authorization revocation'
Assert-Match $files.FileProtect 'XdowsFileProtectInitialize(?s:.*?)UnloadPermitted(?s:.*?)0' 'secure unload default'
Assert-Match $files.FileProtect 'XdowsFileProtectShutdown(?s:.*?)UnloadPermitted(?s:.*?)0' 'unload authorization reset'
Assert-Match $files.Queue '(?s)case IOCTL_XDOWS_SECURITY_AUTHORIZED_SHUTDOWN(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsRequireProtectedClient\(Request(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsTokenAuthValidate(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsFileProtectAuthorizeUnload' 'protected token-gated unload authorization'
Assert-Match $files.Queue '(?s)case IOCTL_XDOWS_SECURITY_AUTHORIZED_SHUTDOWN(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsTokenAuthValidate(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsSecurityDriverAuthorizeUnload' 'registered token-gated SCM unload authorization'
Assert-Match $files.Queue '(?s)case IOCTL_XDOWS_SECURITY_REGISTER_CLIENT(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsRegisterClient(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsFileProtectRevokeUnload' 'client registration unload relock'
Assert-Match $files.Queue '(?s)case IOCTL_XDOWS_SECURITY_REGISTER_CLIENT(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsRegisterClient(?:(?!case IOCTL_XDOWS_SECURITY_).)*XdowsSecurityDriverRevokeUnload' 'client registration SCM unload relock'

Write-Host "Driver unload protection source smoke passed."
