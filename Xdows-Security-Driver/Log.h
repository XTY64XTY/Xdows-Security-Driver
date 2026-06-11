#pragma once

#include "public.h"

EXTERN_C_START

NTSTATUS XdowsLogInitialize(VOID);
VOID XdowsLogShutdown(VOID);
VOID XdowsLogWrite(
    _In_ ULONG Severity,
    _In_ ULONGLONG EventId,
    _In_ ULONGLONG CorrelationId,
    _In_z_ PCWSTR Module,
    _In_z_ PCWSTR Message
    );
VOID XdowsLogWriteStatus(
    _In_ ULONG Severity,
    _In_ ULONGLONG EventId,
    _In_ ULONGLONG CorrelationId,
    _In_z_ PCWSTR Module,
    _In_z_ PCWSTR Operation,
    _In_ NTSTATUS Status
    );
NTSTATUS XdowsLogGetNext(
    _Out_ PXDOWS_SECURITY_LOG_ENTRY Entry
    );

EXTERN_C_END
