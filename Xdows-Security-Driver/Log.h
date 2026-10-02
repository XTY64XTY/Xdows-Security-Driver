#pragma once

#include "public.h"

EXTERN_C_START

NTSTATUS LogInitialize(VOID);
VOID LogShutdown(VOID);
VOID LogWrite(
    _In_ ULONG Severity,
    _In_ ULONGLONG EventId,
    _In_ ULONGLONG CorrelationId,
    _In_z_ PCWSTR Module,
    _In_z_ PCWSTR Message
    );
VOID LogWriteStatus(
    _In_ ULONG Severity,
    _In_ ULONGLONG EventId,
    _In_ ULONGLONG CorrelationId,
    _In_z_ PCWSTR Module,
    _In_z_ PCWSTR Operation,
    _In_ NTSTATUS Status
    );
NTSTATUS LogGetNext(
    _Out_ PXDOWS_SECURITY_LOG_ENTRY Entry
    );

EXTERN_C_END
