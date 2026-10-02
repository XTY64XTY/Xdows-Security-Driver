#pragma once

EXTERN_C_START

NTSTATUS TokenAuthInitialize(VOID);
VOID TokenAuthShutdown(VOID);
NTSTATUS TokenAuthCopyOneTimeToken(_Out_writes_(TokenChars) PWCHAR Token, _In_ ULONG TokenChars);
NTSTATUS TokenAuthRotate(VOID);
BOOLEAN TokenAuthValidate(_In_reads_z_(XDOWS_SECURITY_TOKEN_CHARS + 1) PCWSTR Token);
VOID TokenAuthInvalidate(VOID);

EXTERN_C_END
