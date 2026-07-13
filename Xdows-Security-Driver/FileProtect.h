#pragma once

EXTERN_C_START

NTSTATUS XdowsFileProtectInitialize(VOID);
VOID XdowsFileProtectShutdown(VOID);
VOID XdowsFileProtectAuthorizeUnload(VOID);
VOID XdowsFileProtectRevokeUnload(VOID);
BOOLEAN XdowsFileProtectIsPathScannable(_In_opt_ PCUNICODE_STRING Path);

EXTERN_C_END
