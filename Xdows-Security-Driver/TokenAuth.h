#pragma once

EXTERN_C_START

NTSTATUS XdowsTokenAuthInitialize(VOID);
VOID XdowsTokenAuthShutdown(VOID);
NTSTATUS XdowsTokenAuthCopyOneTimeToken(_Out_writes_(TokenChars) PWCHAR Token, _In_ ULONG TokenChars);
BOOLEAN XdowsTokenAuthValidate(_In_reads_z_(XDOWS_SECURITY_TOKEN_CHARS + 1) PCWSTR Token);
VOID XdowsTokenAuthInvalidate(VOID);

EXTERN_C_END
