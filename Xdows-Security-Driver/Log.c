#include "driver.h"
#include <ntstrsafe.h>

#define XDOWS_LOG_CAPACITY 256u
#define XDOWS_LOG_POOL_TAG 'goLX'

typedef struct _XDOWS_LOG_STATE {
    KSPIN_LOCK Lock;
    XDOWS_SECURITY_LOG_ENTRY Entries[XDOWS_LOG_CAPACITY];
    ULONG Head;
    ULONG Count;
    ULONG DroppedCount;
    ULONGLONG NextLogId;
    BOOLEAN Initialized;
} XDOWS_LOG_STATE, *PXDOWS_LOG_STATE;

static XDOWS_LOG_STATE g_LogState;

static
VOID
LogInitializeHeader(
    _Out_ PXDOWS_SECURITY_PROTOCOL_HEADER Header,
    _In_ ULONG Size
    )
{
    Header->Size = Size;
    Header->Version = XDOWS_SECURITY_PROTOCOL_VERSION;
}

static
ULONG
LogNormalizeSeverity(
    _In_ ULONG Severity
    )
{
    return Severity <= XdowsSecurityLogFatal ? Severity : XdowsSecurityLogInfo;
}

NTSTATUS
LogInitialize(
    VOID
    )
{
    RtlZeroMemory(&g_LogState, sizeof(g_LogState));
    KeInitializeSpinLock(&g_LogState.Lock);
    g_LogState.NextLogId = 1;
    g_LogState.Initialized = TRUE;
    LogWrite(XdowsSecurityLogInfo, 0, 0, L"Log", L"Driver log buffer initialized.");
    return STATUS_SUCCESS;
}

VOID
LogShutdown(
    VOID
    )
{
    KIRQL oldIrql;

    if (!g_LogState.Initialized) {
        return;
    }

    KeAcquireSpinLock(&g_LogState.Lock, &oldIrql);
    g_LogState.Initialized = FALSE;
    g_LogState.Head = 0;
    g_LogState.Count = 0;
    KeReleaseSpinLock(&g_LogState.Lock, oldIrql);
}

VOID
LogWrite(
    _In_ ULONG Severity,
    _In_ ULONGLONG EventId,
    _In_ ULONGLONG CorrelationId,
    _In_z_ PCWSTR Module,
    _In_z_ PCWSTR Message
    )
{
    KIRQL oldIrql;
    ULONG index;
    PXDOWS_SECURITY_LOG_ENTRY entry;

    if (!g_LogState.Initialized ||
        KeGetCurrentIrql() > DISPATCH_LEVEL ||
        Module == NULL ||
        Message == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_LogState.Lock, &oldIrql);

    if (g_LogState.Count == XDOWS_LOG_CAPACITY) {
        index = g_LogState.Head;
        g_LogState.Head = (g_LogState.Head + 1) % XDOWS_LOG_CAPACITY;
        g_LogState.DroppedCount++;
    } else {
        index = (g_LogState.Head + g_LogState.Count) % XDOWS_LOG_CAPACITY;
        g_LogState.Count++;
    }

    entry = &g_LogState.Entries[index];
    RtlZeroMemory(entry, sizeof(*entry));
    LogInitializeHeader(&entry->Header, sizeof(*entry));
    entry->EventId = EventId != 0 ? EventId : g_LogState.NextLogId++;
    if (g_LogState.NextLogId == 0) {
        g_LogState.NextLogId = 1;
    }
    entry->CorrelationId = CorrelationId != 0 ? CorrelationId : entry->EventId;
    entry->Severity = LogNormalizeSeverity(Severity);
    entry->DroppedCount = g_LogState.DroppedCount;
    KeQuerySystemTime(&entry->Timestamp);
    (VOID)RtlStringCchCopyW(entry->Module, RTL_NUMBER_OF(entry->Module), Module);
    (VOID)RtlStringCchCopyW(entry->Message, RTL_NUMBER_OF(entry->Message), Message);

    KeReleaseSpinLock(&g_LogState.Lock, oldIrql);
}

VOID
LogWriteStatus(
    _In_ ULONG Severity,
    _In_ ULONGLONG EventId,
    _In_ ULONGLONG CorrelationId,
    _In_z_ PCWSTR Module,
    _In_z_ PCWSTR Operation,
    _In_ NTSTATUS Status
    )
{
    WCHAR message[XDOWS_SECURITY_MAX_LOG_MESSAGE_CHARS];

    if (Operation == NULL) {
        Operation = L"operation";
    }

    (VOID)RtlStringCchPrintfW(
        message,
        RTL_NUMBER_OF(message),
        L"%ws status=0x%08X",
        Operation,
        Status);

    LogWrite(Severity, EventId, CorrelationId, Module, message);
}

NTSTATUS
LogGetNext(
    _Out_ PXDOWS_SECURITY_LOG_ENTRY Entry
    )
{
    KIRQL oldIrql;

    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Entry, sizeof(*Entry));

    if (!g_LogState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&g_LogState.Lock, &oldIrql);
    if (g_LogState.Count == 0) {
        KeReleaseSpinLock(&g_LogState.Lock, oldIrql);
        return STATUS_NO_MORE_ENTRIES;
    }

    RtlCopyMemory(Entry, &g_LogState.Entries[g_LogState.Head], sizeof(*Entry));
    g_LogState.Head = (g_LogState.Head + 1) % XDOWS_LOG_CAPACITY;
    g_LogState.Count--;
    KeReleaseSpinLock(&g_LogState.Lock, oldIrql);
    return STATUS_SUCCESS;
}
