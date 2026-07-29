#pragma once

EXTERN_C_START

NTSTATUS XdowsFileProtectInitialize(VOID);
VOID XdowsFileProtectShutdown(VOID);
VOID XdowsFileProtectAuthorizeUnload(VOID);
VOID XdowsFileProtectRevokeUnload(VOID);
BOOLEAN XdowsFileProtectIsPathScannable(_In_opt_ PCUNICODE_STRING Path);
NTSTATUS XdowsFileProtectConfigureBootProtection(
    _In_ PXDOWS_SECURITY_BOOT_PROTECTION_REQUEST Request);
BOOLEAN XdowsFileProtectIsBootProtectionEnabled(VOID);

EXTERN_C_END
