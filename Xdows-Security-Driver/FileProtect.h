#pragma once

EXTERN_C_START

NTSTATUS FileProtectInitialize(VOID);
VOID FileProtectShutdown(VOID);
VOID FileProtectAuthorizeUnload(VOID);
VOID FileProtectRevokeUnload(VOID);
BOOLEAN FileProtectIsPathScannable(_In_opt_ PCUNICODE_STRING Path);
NTSTATUS FileProtectConfigureBootProtection(
    _In_ PXDOWS_SECURITY_BOOT_PROTECTION_REQUEST Request);
BOOLEAN FileProtectIsBootProtectionEnabled(VOID);

EXTERN_C_END
