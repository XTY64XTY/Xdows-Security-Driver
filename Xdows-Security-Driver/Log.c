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

static XDOWS_LOG_STATE g_XdowsLogState;

static
VOID
XdowsLogInitializeHeader(
    _Out_ PXDOWS_SECURITY_PROTOCOL_HEADER Header,
    _In_ ULONG Size
    )
{
    Header->Size = Size;
    Header->Version = XDOWS_SECURITY_PROTOCOL_VERSION;
}

static
ULONG
XdowsLogNormalizeSeverity(
    _In_ ULONG Severity
    )
{
    return Severity <= XdowsSecurityLogFatal ? Severity : XdowsSecurityLogInfo;
}

NTSTATUS
XdowsLogInitialize(
    VOID
    )
{
    RtlZeroMemory(&g_XdowsLogState, sizeof(g_XdowsLogState));
    KeInitializeSpinLock(&g_XdowsLogState.Lock);
    g_XdowsLogState.NextLogId = 1;
    g_XdowsLogState.Initialized = TRUE;
    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Log", L"Driver log buffer initialized.");
    return STATUS_SUCCESS;
}

VOID
XdowsLogShutdown(
    VOID
    )
{
    KIRQL oldIrql;

    if (!g_XdowsLogState.Initialized) {
        return;
    }

    KeAcquireSpinLock(&g_XdowsLogState.Lock, &oldIrql);
    g_XdowsLogState.Initialized = FALSE;
    g_XdowsLogState.Head = 0;
    g_XdowsLogState.Count = 0;
    KeReleaseSpinLock(&g_XdowsLogState.Lock, oldIrql);
}

VOID
XdowsLogWrite(
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

    if (!g_XdowsLogState.Initialized ||
        KeGetCurrentIrql() > DISPATCH_LEVEL ||
        Module == NULL ||
        Message == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_XdowsLogState.Lock, &oldIrql);

    if (g_XdowsLogState.Count == XDOWS_LOG_CAPACITY) {
        index = g_XdowsLogState.Head;
        g_XdowsLogState.Head = (g_XdowsLogState.Head + 1) % XDOWS_LOG_CAPACITY;
        g_XdowsLogState.DroppedCount++;
    } else {
        index = (g_XdowsLogState.Head + g_XdowsLogState.Count) % XDOWS_LOG_CAPACITY;
        g_XdowsLogState.Count++;
    }

    entry = &g_XdowsLogState.Entries[index];
    RtlZeroMemory(entry, sizeof(*entry));
    XdowsLogInitializeHeader(&entry->Header, sizeof(*entry));
    entry->EventId = EventId != 0 ? EventId : g_XdowsLogState.NextLogId++;
    if (g_XdowsLogState.NextLogId == 0) {
        g_XdowsLogState.NextLogId = 1;
    }
    entry->CorrelationId = CorrelationId != 0 ? CorrelationId : entry->EventId;
    entry->Severity = XdowsLogNormalizeSeverity(Severity);
    entry->DroppedCount = g_XdowsLogState.DroppedCount;
    KeQuerySystemTime(&entry->Timestamp);
    (VOID)RtlStringCchCopyW(entry->Module, RTL_NUMBER_OF(entry->Module), Module);
    (VOID)RtlStringCchCopyW(entry->Message, RTL_NUMBER_OF(entry->Message), Message);

    KeReleaseSpinLock(&g_XdowsLogState.Lock, oldIrql);
}

VOID
XdowsLogWriteStatus(
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

    XdowsLogWrite(Severity, EventId, CorrelationId, Module, message);
}

NTSTATUS
XdowsLogGetNext(
    _Out_ PXDOWS_SECURITY_LOG_ENTRY Entry
    )
{
    KIRQL oldIrql;

    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Entry, sizeof(*Entry));

    if (!g_XdowsLogState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&g_XdowsLogState.Lock, &oldIrql);
    if (g_XdowsLogState.Count == 0) {
        KeReleaseSpinLock(&g_XdowsLogState.Lock, oldIrql);
        return STATUS_NO_MORE_ENTRIES;
    }

    RtlCopyMemory(Entry, &g_XdowsLogState.Entries[g_XdowsLogState.Head], sizeof(*Entry));
    g_XdowsLogState.Head = (g_XdowsLogState.Head + 1) % XDOWS_LOG_CAPACITY;
    g_XdowsLogState.Count--;
    KeReleaseSpinLock(&g_XdowsLogState.Lock, oldIrql);
    return STATUS_SUCCESS;
}
