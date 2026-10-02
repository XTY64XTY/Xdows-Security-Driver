#pragma once

EXTERN_C_START

NTSTATUS SelfProtectInitialize(VOID);
VOID SelfProtectShutdown(VOID);
NTSTATUS SelfProtectRegisterProcess(_In_ ULONG ProcessId, _In_ ULONG MainThreadId, _In_ ULONG Flags);
NTSTATUS SelfProtectSetVoluntaryExit(_In_ ULONG ProcessId, _In_ BOOLEAN IsVoluntaryExit);
VOID SelfProtectClearRegistration(VOID);
BOOLEAN SelfProtectIsProcessProtected(_In_ HANDLE ProcessId);
BOOLEAN SelfProtectIsClientImageAllowed(_In_ PCUNICODE_STRING ImagePath);
NTSTATUS SelfProtectSetStartupProtection(_In_ ULONG ProcessId, _In_ BOOLEAN Enabled);
BOOLEAN SelfProtectIsStartupProtectionEnabled(VOID);
BOOLEAN SelfProtectShouldBlockFileMutation(
    _In_ PCUNICODE_STRING Path,
    _In_ HANDLE RequestorProcessId);

EXTERN_C_END
