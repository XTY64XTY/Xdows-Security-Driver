/*++

Module Name:

    drivercontext.c

Abstract:

    Driver bridge state, pending event queue, and user-mode decisions.

--*/

#include "driver.h"
#include "fileprotect.h"
#include "moduleregistry.h"
#include "selfprotect.h"
#include "tokenauth.h"
#include <ntstrsafe.h>

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

NTKERNELAPI
NTSTATUS
SeLocateProcessImageName(
    _In_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING* pImageFileName
    );

static const UNICODE_STRING g_ClientImageName =
    RTL_CONSTANT_STRING(L"Xdows-Security.exe");

//
// Throttle window (100ns units) and per-type event-rate limits.
//
// Only non-critical event types are limited. Critical types (process launch,
// file rename, handle/thread operations, confirmed behavior, boot writes,
// registry writes) keep every event so protection is never weakened; the
// noise types (file create/write, driver log) are capped per one-second
// window so a build or archive extraction cannot flood the user-mode bridge
// and drive the main program's memory working set upward.
//
#define XDOWS_THROTTLE_WINDOW_100NS (10 * 1000 * 1000)

static const ULONG ThrottleLimitPerType[XDOWS_SECURITY_EVENT_TYPE_COUNT] = {
    0,     /* XdowsSecurityEventNone          */
    0,     /* XdowsSecurityEventProcessCreate critical */
    200,   /* XdowsSecurityEventFileCreate    noise */
    300,   /* XdowsSecurityEventFileWrite     noise */
    0,     /* XdowsSecurityEventFileRename    critical (kernel-interceptable) */
    0,     /* XdowsSecurityEventProcessHandle critical */
    0,     /* XdowsSecurityEventThreadHandle  critical */
    0,     /* XdowsSecurityEventImageLoad     critical */
    100,   /* XdowsSecurityEventDriverLog     noise */
    0,     /* XdowsSecurityEventBehavior      confirmed threat */
    0,     /* XdowsSecurityEventBootWrite     critical */
    0,     /* XdowsSecurityEventRegistryWrite critical */
};

static
NTSTATUS
ValidateClientProcess(
    _In_ ULONG ProcessId
    )
{
    PEPROCESS process = NULL;
    PUNICODE_STRING imagePath = NULL;
    UNICODE_STRING imageName;
    USHORT imageChars;
    USHORT nameStart = 0;
    USHORT i;
    NTSTATUS status;

    status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &process);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    status = SeLocateProcessImageName(process, &imagePath);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status) || imagePath == NULL || imagePath->Buffer == NULL) {
        if (imagePath != NULL) {
            ExFreePool(imagePath);
        }
        return STATUS_ACCESS_DENIED;
    }

    imageChars = imagePath->Length / sizeof(WCHAR);
    for (i = imageChars; i > 0; i--) {
        if (imagePath->Buffer[i - 1] == L'\\') {
            nameStart = i;
            break;
        }
    }

    imageName.Buffer = imagePath->Buffer + nameStart;
    imageName.Length = imagePath->Length - (nameStart * sizeof(WCHAR));
    imageName.MaximumLength = imageName.Length;
    if (!RtlEqualUnicodeString(&imageName, &g_ClientImageName, TRUE) ||
        !SelfProtectIsClientImageAllowed(imagePath)) {
        status = STATUS_ACCESS_DENIED;
    } else {
        status = STATUS_SUCCESS;
    }

    ExFreePool(imagePath);
    return status;
}

static
BOOLEAN
IsCriticalEventType(
    _In_ ULONG EventType
    )
{
    return EventType == XdowsSecurityEventProcessCreate ||
        EventType == XdowsSecurityEventProcessHandle ||
        EventType == XdowsSecurityEventThreadHandle ||
        EventType == XdowsSecurityEventImageLoad ||
        EventType == XdowsSecurityEventBehavior ||
        EventType == XdowsSecurityEventBootWrite ||
        EventType == XdowsSecurityEventRegistryWrite ||
        //
        // FileRename runs in PreSetInformation and can fail the operation
        // with STATUS_VIRUS_INFECTED on a Block verdict (ransomware-style
        // executable renames). It must stay synchronous even in async review
        // mode, otherwise user mode could never block a rename.
        //
        EventType == XdowsSecurityEventFileRename;
}

XDOWS_DRIVER_CONTEXT g_DriverContext;

static
VOID
InitializeHeader(
    _Out_ PXDOWS_SECURITY_PROTOCOL_HEADER Header,
    _In_ ULONG Size
    )
{
    Header->Size = Size;
    Header->Version = XDOWS_SECURITY_PROTOCOL_VERSION;
}

static
BOOLEAN
IsHeaderValid(
    _In_ PXDOWS_SECURITY_PROTOCOL_HEADER Header,
    _In_ ULONG ExpectedSize
    )
{
    return Header->Size == ExpectedSize &&
        Header->Version == XDOWS_SECURITY_PROTOCOL_VERSION;
}

NTSTATUS
InitializeGlobalContext(
    _In_ WDFDEVICE Device
    )
{
    RtlZeroMemory(&g_DriverContext, sizeof(g_DriverContext));
    g_DriverContext.Device = Device;
    KeInitializeSpinLock(&g_DriverContext.Lock);
    KeInitializeEvent(&g_DriverContext.PendingAvailableEvent, SynchronizationEvent, FALSE);
    InitializeListHead(&g_DriverContext.PendingEvents);
    g_DriverContext.NextEventId = 1;
    g_DriverContext.Initialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
ShutdownGlobalContext(
    VOID
    )
{
    KIRQL oldIrql;
    LIST_ENTRY localList;

    if (!g_DriverContext.Initialized) {
        return;
    }

    InitializeListHead(&localList);

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    g_DriverContext.ClientConnected = FALSE;
    g_DriverContext.AsyncReviewEnabled = FALSE;

    while (!IsListEmpty(&g_DriverContext.PendingEvents)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_DriverContext.PendingEvents);
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        pending->Linked = FALSE;
        InsertTailList(&localList, entry);
    }

    g_DriverContext.PendingEventCount = 0;
    g_DriverContext.Initialized = FALSE;
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
    KeSetEvent(&g_DriverContext.PendingAvailableEvent, IO_NO_INCREMENT, FALSE);

    while (!IsListEmpty(&localList)) {
        PLIST_ENTRY entry = RemoveHeadList(&localList);
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        if (pending->Async) {
            //
            // Async-review entries have no waiting thread; release directly.
            //
            ExFreePoolWithTag(pending, 'swDX');
            continue;
        }
        pending->Decision.Header.Size = sizeof(XDOWS_SECURITY_DECISION);
        pending->Decision.Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
        pending->Decision.Decision = XdowsSecurityDecisionAllow;
        KeSetEvent(&pending->DecisionEvent, IO_NO_INCREMENT, FALSE);
    }
}

ULONGLONG
AllocateEventId(
    VOID
    )
{
    KIRQL oldIrql;
    ULONGLONG eventId;

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    eventId = g_DriverContext.NextEventId++;
    if (g_DriverContext.NextEventId == 0) {
        g_DriverContext.NextEventId = 1;
    }
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);

    return eventId;
}

NTSTATUS
RegisterClient(
    _In_ PXDOWS_SECURITY_REGISTER_REQUEST Request,
    _In_ ULONG RequestorProcessId,
    _Out_ PXDOWS_SECURITY_REGISTER_RESPONSE Response
    )
{
    KIRQL oldIrql;
    NTSTATUS tokenStatus;

    if (!IsHeaderValid(&Request->Header, sizeof(*Request))) {
        return STATUS_REVISION_MISMATCH;
    }
    if (RequestorProcessId == 0 ||
        Request->ClientProcessId != RequestorProcessId) {
        return STATUS_ACCESS_DENIED;
    }

    if (!NT_SUCCESS(ValidateClientProcess(RequestorProcessId))) {
        LogWrite(
            XdowsSecurityLogWarning,
            0,
            0,
            L"Bridge",
            L"Client registration denied because the caller image is not trusted.");
        return STATUS_ACCESS_DENIED;
    }

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    if (g_DriverContext.ClientConnected &&
        g_DriverContext.ClientProcessId != ULongToHandle(RequestorProcessId)) {
        KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
        return STATUS_DEVICE_BUSY;
    }
    g_DriverContext.ClientConnected = TRUE;
    g_DriverContext.ClientProcessId = ULongToHandle(RequestorProcessId);
    g_DriverContext.AsyncReviewEnabled =
        (Request->Flags & XDOWS_SECURITY_REGISTER_FLAG_ASYNC_REVIEW) != 0;
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);

    RtlZeroMemory(Response, sizeof(*Response));
    InitializeHeader(&Response->Header, sizeof(*Response));
    Response->Status = STATUS_SUCCESS;
    Response->ProtocolVersion = XDOWS_SECURITY_PROTOCOL_VERSION;
    Response->DefaultKernelWaitTimeoutMs = XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;
    Response->Capabilities = XDOWS_SECURITY_CAPABILITIES;
    Response->DriverBuildId = XDOWS_SECURITY_DRIVER_BUILD_ID;
    tokenStatus = TokenAuthCopyOneTimeToken(
        Response->ShutdownToken,
        RTL_NUMBER_OF(Response->ShutdownToken));
    if (tokenStatus == STATUS_NOT_FOUND) {
        tokenStatus = TokenAuthRotate();
        if (NT_SUCCESS(tokenStatus)) {
            tokenStatus = TokenAuthCopyOneTimeToken(
                Response->ShutdownToken,
                RTL_NUMBER_OF(Response->ShutdownToken));
        }
    }
    if (!NT_SUCCESS(tokenStatus)) {
        Response->Status = tokenStatus;
        DisconnectClient();
        return tokenStatus;
    }

    LogWrite(XdowsSecurityLogInfo, 0, 0, L"Bridge", L"Client registered.");
    return STATUS_SUCCESS;
}

BOOLEAN
IsRegisteredClientProcess(
    _In_ ULONG ProcessId
    )
{
    KIRQL oldIrql;
    BOOLEAN registered;

    if (ProcessId == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    registered = g_DriverContext.Initialized &&
        g_DriverContext.ClientConnected &&
        g_DriverContext.ClientProcessId == ULongToHandle(ProcessId);
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
    return registered;
}

VOID
DisconnectClient(
    VOID
    )
{
    KIRQL oldIrql;
    LIST_ENTRY localList;

    InitializeListHead(&localList);

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    g_DriverContext.ClientConnected = FALSE;
    g_DriverContext.ClientProcessId = NULL;
    g_DriverContext.AsyncReviewEnabled = FALSE;

    while (!IsListEmpty(&g_DriverContext.PendingEvents)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_DriverContext.PendingEvents);
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        pending->Linked = FALSE;
        InsertTailList(&localList, entry);
    }
    g_DriverContext.PendingEventCount = 0;
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
    KeSetEvent(&g_DriverContext.PendingAvailableEvent, IO_NO_INCREMENT, FALSE);

    while (!IsListEmpty(&localList)) {
        PLIST_ENTRY entry = RemoveHeadList(&localList);
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        if (pending->Async) {
            //
            // Async-review entries have no waiting thread; the poller owns
            // the allocation and would free it on read. Release it directly.
            //
            ExFreePoolWithTag(pending, 'swDX');
            continue;
        }
        pending->Decision.Header.Size = sizeof(XDOWS_SECURITY_DECISION);
        pending->Decision.Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
        pending->Decision.EventId = pending->Event.EventId;
        pending->Decision.Decision = XdowsSecurityDecisionTimeout;
        pending->Decision.ResultCode = (ULONG)STATUS_DEVICE_NOT_CONNECTED;
        (VOID)RtlStringCchCopyW(
            pending->Decision.Reason,
            RTL_NUMBER_OF(pending->Decision.Reason),
            L"client-disconnected");
        KeSetEvent(&pending->DecisionEvent, IO_NO_INCREMENT, FALSE);
    }

    LogWrite(XdowsSecurityLogInfo, 0, 0, L"Bridge", L"Client state cleared.");
}

NTSTATUS
Heartbeat(
    _In_ PXDOWS_SECURITY_HEARTBEAT_REQUEST Request
    )
{
    KIRQL oldIrql;
    BOOLEAN connected;

    if (!IsHeaderValid(&Request->Header, sizeof(*Request))) {
        return STATUS_REVISION_MISMATCH;
    }

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    connected = g_DriverContext.ClientConnected &&
        g_DriverContext.ClientProcessId == ULongToHandle(Request->ClientProcessId);
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);

    return connected ? STATUS_SUCCESS : STATUS_DEVICE_NOT_CONNECTED;
}

NTSTATUS
GetNextPendingEvent(
    _Out_ PXDOWS_SECURITY_EVENT Event
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;

    for (;;) {
        KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);

        for (entry = g_DriverContext.PendingEvents.Flink;
             entry != &g_DriverContext.PendingEvents;
             entry = entry->Flink) {
            PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
            if (!pending->Delivered) {
                pending->Delivered = TRUE;
                RtlCopyMemory(Event, &pending->Event, sizeof(*Event));
                if (pending->Async) {
                    //
                    // Async-review entries are owned by the poller: remove
                    // them now and release the allocation outside the lock.
                    //
                    RemoveEntryList(&pending->Link);
                    pending->Linked = FALSE;
                    if (g_DriverContext.PendingEventCount > 0) {
                        g_DriverContext.PendingEventCount--;
                    }
                    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
                    ExFreePoolWithTag(pending, 'swDX');
                } else {
                    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
                }
                return STATUS_SUCCESS;
            }
        }

        KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
        timeout.QuadPart = -(LONGLONG)1000 * 10000LL;
        waitStatus = KeWaitForSingleObject(
            &g_DriverContext.PendingAvailableEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
        if (waitStatus != STATUS_SUCCESS) {
            return STATUS_NO_MORE_ENTRIES;
        }
    }
}

NTSTATUS
GetNextPendingEventsBatch(
    _Out_ PXDOWS_SECURITY_EVENT_BATCH Batch,
    _In_ ULONG OutputBufferLength
    )
/*++

Routine Description:

    Drains up to XDOWS_SECURITY_EVENT_BATCH_SIZE undelivered events into the
    caller-provided buffer. Sync-review entries are marked Delivered and stay
    queued until their decision completes; async-review entries are removed
    from the queue and released, because no origin thread is waiting on them.

    This call never blocks. The client paces itself (e.g. one drain every
    500 ms) and keeps the events it needs; the kernel queue remains bounded
    by XDOWS_SECURITY_MAX_PENDING_EVENTS.

--*/
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PXDOWS_PENDING_EVENT pending;
    LIST_ENTRY freeList;
    ULONG capacity;
    ULONG count = 0;
    ULONG removed = 0;

    if (Batch == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (OutputBufferLength <
        (ULONG)sizeof(XDOWS_SECURITY_PROTOCOL_HEADER) +
        (ULONG)sizeof(XDOWS_SECURITY_EVENT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    capacity = (OutputBufferLength - (ULONG)sizeof(XDOWS_SECURITY_PROTOCOL_HEADER))
        / (ULONG)sizeof(XDOWS_SECURITY_EVENT);
    if (capacity > XDOWS_SECURITY_EVENT_BATCH_SIZE) {
        capacity = XDOWS_SECURITY_EVENT_BATCH_SIZE;
    }

    RtlZeroMemory(&Batch->Header, sizeof(Batch->Header));
    Batch->Count = 0;
    Batch->Reserved = 0;
    InitializeHeader(&Batch->Header, sizeof(*Batch));
    InitializeListHead(&freeList);

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);

    entry = g_DriverContext.PendingEvents.Flink;
    while (entry != &g_DriverContext.PendingEvents && count < capacity) {
        next = entry->Flink;
        pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        if (!pending->Delivered) {
            pending->Delivered = TRUE;
            RtlCopyMemory(&Batch->Events[count], &pending->Event, sizeof(pending->Event));
            count++;
            if (pending->Async) {
                RemoveEntryList(&pending->Link);
                pending->Linked = FALSE;
                removed++;
                InsertTailList(&freeList, &pending->Link);
            }
        }
        entry = next;
    }

    if (removed > 0) {
        if (g_DriverContext.PendingEventCount >= removed) {
            g_DriverContext.PendingEventCount -= removed;
        } else {
            g_DriverContext.PendingEventCount = 0;
        }
    }
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);

    while (!IsListEmpty(&freeList)) {
        entry = RemoveHeadList(&freeList);
        pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        ExFreePoolWithTag(pending, 'swDX');
    }

    Batch->Count = count;
    return STATUS_SUCCESS;
}

NTSTATUS
SubmitDecision(
    _In_ PXDOWS_SECURITY_DECISION Decision
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    if (!IsHeaderValid(&Decision->Header, sizeof(*Decision))) {
        return STATUS_REVISION_MISMATCH;
    }

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);

    for (entry = g_DriverContext.PendingEvents.Flink;
         entry != &g_DriverContext.PendingEvents;
         entry = entry->Flink) {
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        if (pending->Event.EventId == Decision->EventId) {
            if (Decision->Decision == XdowsSecurityDecisionPending) {
                if (pending->UserDecisionPending || pending->FinalDecisionSubmitted) {
                    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
                    return STATUS_INVALID_DEVICE_STATE;
                }
                pending->UserDecisionPending = TRUE;
            } else {
                if (pending->FinalDecisionSubmitted) {
                    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
                    return STATUS_INVALID_DEVICE_STATE;
                }
                pending->FinalDecisionSubmitted = TRUE;
            }
            RtlCopyMemory(&pending->Decision, Decision, sizeof(*Decision));
            KeSetEvent(&pending->DecisionEvent, IO_NO_INCREMENT, FALSE);
            KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
    return STATUS_NOT_FOUND;
}

NTSTATUS
QueueEventAndWait(
    _Inout_ PXDOWS_SECURITY_EVENT Event,
    _Out_ PXDOWS_SECURITY_DECISION Decision
    )
{
    KIRQL oldIrql;
    LARGE_INTEGER timeout;
    NTSTATUS status;
    PXDOWS_PENDING_EVENT pending;
    BOOLEAN linked = FALSE;
    BOOLEAN userDecisionPending = FALSE;
    BOOLEAN async = FALSE;

    RtlZeroMemory(Decision, sizeof(*Decision));
    InitializeHeader(&Decision->Header, sizeof(*Decision));
    Decision->Decision = XdowsSecurityDecisionAllow;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
        g_DriverContext.ReceivedByType[Event->EventType]++;
    }

    //
    // Sliding-window rate limit for non-critical noise types. A throttle
    // drop is silent (no log entry, no user-mode event): the flood is
    // bounded without churning the 256-entry log ring or the bridge.
    //
    if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
        ULONG limit = ThrottleLimitPerType[Event->EventType];
        if (limit != 0) {
            ULONGLONG now = KeQueryInterruptTime();
            PXDOWS_THROTTLE_SLOT slot = &g_DriverContext.Throttle[Event->EventType];
            if (slot->Count == 0 ||
                now - slot->WindowStart100ns >= XDOWS_THROTTLE_WINDOW_100NS) {
                slot->WindowStart100ns = now;
                slot->Count = 1;
            } else if (slot->Count >= limit) {
                g_DriverContext.DroppedEventCount++;
                g_DriverContext.DroppedByType[Event->EventType]++;
                KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
                return STATUS_NO_MORE_ENTRIES;
            } else {
                slot->Count++;
            }
        }
    }

    if (!g_DriverContext.ClientConnected) {
        g_DriverContext.DroppedEventCount++;
        if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
            g_DriverContext.DroppedByType[Event->EventType]++;
        }
        KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
        LogWrite(XdowsSecurityLogWarning, Event->EventId, Event->CorrelationId, L"Queue", L"Event dropped because client is not connected.");
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    if (g_DriverContext.PendingEventCount >= XDOWS_SECURITY_MAX_PENDING_EVENTS) {
        g_DriverContext.DroppedEventCount++;
        if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
            g_DriverContext.DroppedByType[Event->EventType]++;
        }
        KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
        LogWrite(XdowsSecurityLogWarning, Event->EventId, Event->CorrelationId, L"Queue", L"Event dropped because pending queue is full.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);

    pending = (PXDOWS_PENDING_EVENT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*pending),
        'swDX');
    if (pending == NULL) {
        LogWrite(XdowsSecurityLogError, Event->EventId, Event->CorrelationId, L"Queue", L"Event allocation failed.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pending, sizeof(*pending));
    InitializeHeader(&Event->Header, sizeof(*Event));
    if (Event->EventId == 0) {
        Event->EventId = AllocateEventId();
    }
    if (Event->CorrelationId == 0) {
        Event->CorrelationId = Event->EventId;
    }
    if (Event->KernelWaitTimeoutMs == 0 ||
        Event->KernelWaitTimeoutMs > XDOWS_SECURITY_MAX_KERNEL_WAIT_TIMEOUT_MS) {
        Event->KernelWaitTimeoutMs = XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;
    }

    RtlCopyMemory(&pending->Event, Event, sizeof(*Event));
    KeInitializeEvent(&pending->DecisionEvent, NotificationEvent, FALSE);
    //
    // Async review mode: non-critical events are queued for the poller but
    // the origin thread returns immediately with the default Allow decision.
    // The poller removes and releases the entry on read.
    //
    pending->Async = g_DriverContext.AsyncReviewEnabled &&
        !IsCriticalEventType(Event->EventType);

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    if (g_DriverContext.ClientConnected &&
        g_DriverContext.PendingEventCount < XDOWS_SECURITY_MAX_PENDING_EVENTS) {
        if (IsCriticalEventType(Event->EventType)) {
            PLIST_ENTRY insertionPoint = g_DriverContext.PendingEvents.Flink;
            while (insertionPoint != &g_DriverContext.PendingEvents) {
                PXDOWS_PENDING_EVENT existing = CONTAINING_RECORD(insertionPoint, XDOWS_PENDING_EVENT, Link);
                if (!IsCriticalEventType(existing->Event.EventType)) {
                    break;
                }
                insertionPoint = insertionPoint->Flink;
            }
            InsertTailList(insertionPoint, &pending->Link);
        } else {
            InsertTailList(&g_DriverContext.PendingEvents, &pending->Link);
        }
        pending->Linked = TRUE;
        linked = TRUE;
        g_DriverContext.PendingEventCount++;
        KeSetEvent(&g_DriverContext.PendingAvailableEvent, IO_NO_INCREMENT, FALSE);
    } else {
        g_DriverContext.DroppedEventCount++;
        if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
            g_DriverContext.DroppedByType[Event->EventType]++;
        }
    }
    //
    // Capture under the lock: once the entry is linked, the poller may
    // remove and free an async entry immediately after we release.
    //
    async = pending->Async;
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);

    if (!linked) {
        ExFreePoolWithTag(pending, 'swDX');
        LogWrite(XdowsSecurityLogWarning, Event->EventId, Event->CorrelationId, L"Queue", L"Event dropped before delivery.");
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    if (async) {
        //
        // Async review mode: no thread waits on DecisionEvent. The entry
        // stays queued until the poller reads it (and frees it). Callers
        // see the default Allow decision.
        //
        return STATUS_SUCCESS;
    }

    for (;;) {
        ULONG waitTimeoutMs = userDecisionPending
            ? XDOWS_SECURITY_USER_DECISION_TIMEOUT_MS
            : Event->KernelWaitTimeoutMs;

        timeout.QuadPart = -(LONGLONG)waitTimeoutMs * 10000LL;
        status = KeWaitForSingleObject(
            &pending->DecisionEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout);

        if (status != STATUS_SUCCESS) {
            break;
        }

        // SubmitDecision uses the same lock, so copying the verdict and
        // resetting the notification event while holding it cannot lose a
        // final decision that arrives immediately after Pending.
        KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
        RtlCopyMemory(Decision, &pending->Decision, sizeof(*Decision));
        userDecisionPending = pending->UserDecisionPending;
        if (Decision->Decision == XdowsSecurityDecisionPending) {
            KeResetEvent(&pending->DecisionEvent);
            KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
            LogWrite(
                XdowsSecurityLogInfo,
                Event->EventId,
                Event->CorrelationId,
                L"Decision",
                L"Confirmed threat is waiting for a user decision.");
            continue;
        }
        KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
        break;
    }

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    if (pending->Linked) {
        RemoveEntryList(&pending->Link);
        pending->Linked = FALSE;
        if (g_DriverContext.PendingEventCount > 0) {
            g_DriverContext.PendingEventCount--;
        }
    }
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);

    if (status == STATUS_SUCCESS) {
        if (userDecisionPending &&
            Decision->Decision == XdowsSecurityDecisionTimeout) {
            Decision->Decision = XdowsSecurityDecisionBlock;
            Decision->ResultCode = (ULONG)STATUS_TIMEOUT;
            (VOID)RtlStringCchCopyW(
                Decision->Reason,
                RTL_NUMBER_OF(Decision->Reason),
                L"user-decision-timeout-blocked");
            LogWrite(
                XdowsSecurityLogWarning,
                Event->EventId,
                Event->CorrelationId,
                L"Decision",
                L"User decision ended without a verdict; operation blocked.");
        }
        // Successful traffic is represented by state counters. Avoid writing
        // another hot-path log entry for every benign decision.
    } else {
        Decision->EventId = Event->EventId;
        Decision->Decision = userDecisionPending
            ? XdowsSecurityDecisionBlock
            : XdowsSecurityDecisionTimeout;
        Decision->ResultCode = (ULONG)status;
        (VOID)RtlStringCchCopyW(
            Decision->Reason,
            RTL_NUMBER_OF(Decision->Reason),
            userDecisionPending
                ? L"user-decision-timeout-blocked"
                : L"infrastructure-timeout-allow");
        KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
        if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
            g_DriverContext.TimedOutByType[Event->EventType]++;
        }
        KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);
        if (userDecisionPending) {
            LogWriteStatus(
                XdowsSecurityLogWarning,
                Event->EventId,
                Event->CorrelationId,
                L"Decision",
                L"User decision timed out; operation blocked",
                status);
        } else {
            LogWriteStatus(
                XdowsSecurityLogWarning,
                Event->EventId,
                Event->CorrelationId,
                L"Queue",
                L"Event wait timed out; infrastructure policy allows",
                status);
        }
    }

    ExFreePoolWithTag(pending, 'swDX');
    return status;
}

VOID
GetState(
    _Out_ PXDOWS_SECURITY_STATE State
    )
{
    KIRQL oldIrql;
    HANDLE clientProcessId;

    RtlZeroMemory(State, sizeof(*State));
    InitializeHeader(&State->Header, sizeof(*State));

    KeAcquireSpinLock(&g_DriverContext.Lock, &oldIrql);
    State->ClientConnected = g_DriverContext.ClientConnected ? 1 : 0;
    State->PendingEventCount = g_DriverContext.PendingEventCount;
    State->DroppedEventCount = g_DriverContext.DroppedEventCount;
    State->ProcessProtectionEnabled = g_DriverContext.ProcessProtectionEnabled ? 1 : 0;
    State->FileProtectionEnabled = g_DriverContext.FileProtectionEnabled ? 1 : 0;
    clientProcessId = g_DriverContext.ClientProcessId;
    State->ActiveModules = ModulesGetActiveMask();
    State->ProtocolVersion = XDOWS_SECURITY_PROTOCOL_VERSION;
    State->Capabilities = XDOWS_SECURITY_CAPABILITIES;
    State->DriverBuildId = XDOWS_SECURITY_DRIVER_BUILD_ID;
    RtlCopyMemory(State->ReceivedByType, g_DriverContext.ReceivedByType, sizeof(State->ReceivedByType));
    RtlCopyMemory(State->DroppedByType, g_DriverContext.DroppedByType, sizeof(State->DroppedByType));
    RtlCopyMemory(State->TimedOutByType, g_DriverContext.TimedOutByType, sizeof(State->TimedOutByType));
    KeReleaseSpinLock(&g_DriverContext.Lock, oldIrql);

    State->SelfProtectionEnabled = SelfProtectIsProcessProtected(clientProcessId) ? 1 : 0;
    State->ProtectedProcessId = State->SelfProtectionEnabled
        ? HandleToULong(clientProcessId)
        : 0;
    State->StartupProtectionEnabled =
        SelfProtectIsStartupProtectionEnabled() ? 1 : 0;
    State->BootProtectionEnabled =
        FileProtectIsBootProtectionEnabled() ? 1 : 0;
}
