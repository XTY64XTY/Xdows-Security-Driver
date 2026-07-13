#pragma once

EXTERN_C_START

NTSTATUS XdowsSelfProtectInitialize(VOID);
VOID XdowsSelfProtectShutdown(VOID);
NTSTATUS XdowsSelfProtectRegisterProcess(_In_ ULONG ProcessId, _In_ ULONG MainThreadId, _In_ ULONG Flags);
NTSTATUS XdowsSelfProtectSetVoluntaryExit(_In_ ULONG ProcessId, _In_ BOOLEAN IsVoluntaryExit);
VOID XdowsSelfProtectClearRegistration(VOID);
BOOLEAN XdowsSelfProtectIsProcessProtected(_In_ HANDLE ProcessId);
BOOLEAN XdowsSelfProtectShouldBlockFileMutation(
    _In_ PCUNICODE_STRING Path,
    _In_ HANDLE RequestorProcessId);

EXTERN_C_END
