/*++

Module Name:

    drivercontext.c

Abstract:

    Driver bridge state, pending event queue, and user-mode decisions.

--*/

#include "driver.h"
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

static const UNICODE_STRING g_XdowsClientImageName =
    RTL_CONSTANT_STRING(L"Xdows-Security.exe");

static
NTSTATUS
XdowsValidateClientProcess(
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
    if (!RtlEqualUnicodeString(&imageName, &g_XdowsClientImageName, TRUE) ||
        !XdowsSelfProtectIsClientImageAllowed(imagePath)) {
        status = STATUS_ACCESS_DENIED;
    } else {
        status = STATUS_SUCCESS;
    }

    ExFreePool(imagePath);
    return status;
}

static
BOOLEAN
XdowsIsCriticalEventType(
    _In_ ULONG EventType
    )
{
    return EventType == XdowsSecurityEventProcessCreate ||
        EventType == XdowsSecurityEventProcessHandle ||
        EventType == XdowsSecurityEventThreadHandle ||
        EventType == XdowsSecurityEventImageLoad;
}

XDOWS_DRIVER_CONTEXT g_XdowsDriverContext;

static
VOID
XdowsInitializeHeader(
    _Out_ PXDOWS_SECURITY_PROTOCOL_HEADER Header,
    _In_ ULONG Size
    )
{
    Header->Size = Size;
    Header->Version = XDOWS_SECURITY_PROTOCOL_VERSION;
}

static
BOOLEAN
XdowsIsHeaderValid(
    _In_ PXDOWS_SECURITY_PROTOCOL_HEADER Header,
    _In_ ULONG ExpectedSize
    )
{
    return Header->Size == ExpectedSize &&
        Header->Version == XDOWS_SECURITY_PROTOCOL_VERSION;
}

NTSTATUS
XdowsInitializeGlobalContext(
    _In_ WDFDEVICE Device
    )
{
    RtlZeroMemory(&g_XdowsDriverContext, sizeof(g_XdowsDriverContext));
    g_XdowsDriverContext.Device = Device;
    KeInitializeSpinLock(&g_XdowsDriverContext.Lock);
    KeInitializeEvent(&g_XdowsDriverContext.PendingAvailableEvent, SynchronizationEvent, FALSE);
    InitializeListHead(&g_XdowsDriverContext.PendingEvents);
    g_XdowsDriverContext.NextEventId = 1;
    g_XdowsDriverContext.Initialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
XdowsShutdownGlobalContext(
    VOID
    )
{
    KIRQL oldIrql;
    LIST_ENTRY localList;

    if (!g_XdowsDriverContext.Initialized) {
        return;
    }

    InitializeListHead(&localList);

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    g_XdowsDriverContext.ClientConnected = FALSE;

    while (!IsListEmpty(&g_XdowsDriverContext.PendingEvents)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_XdowsDriverContext.PendingEvents);
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        pending->Linked = FALSE;
        InsertTailList(&localList, entry);
    }

    g_XdowsDriverContext.PendingEventCount = 0;
    g_XdowsDriverContext.Initialized = FALSE;
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
    KeSetEvent(&g_XdowsDriverContext.PendingAvailableEvent, IO_NO_INCREMENT, FALSE);

    while (!IsListEmpty(&localList)) {
        PLIST_ENTRY entry = RemoveHeadList(&localList);
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        pending->Decision.Header.Size = sizeof(XDOWS_SECURITY_DECISION);
        pending->Decision.Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
        pending->Decision.Decision = XdowsSecurityDecisionAllow;
        KeSetEvent(&pending->DecisionEvent, IO_NO_INCREMENT, FALSE);
    }
}

ULONGLONG
XdowsAllocateEventId(
    VOID
    )
{
    KIRQL oldIrql;
    ULONGLONG eventId;

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    eventId = g_XdowsDriverContext.NextEventId++;
    if (g_XdowsDriverContext.NextEventId == 0) {
        g_XdowsDriverContext.NextEventId = 1;
    }
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);

    return eventId;
}

NTSTATUS
XdowsRegisterClient(
    _In_ PXDOWS_SECURITY_REGISTER_REQUEST Request,
    _In_ ULONG RequestorProcessId,
    _Out_ PXDOWS_SECURITY_REGISTER_RESPONSE Response
    )
{
    KIRQL oldIrql;
    NTSTATUS tokenStatus;

    if (!XdowsIsHeaderValid(&Request->Header, sizeof(*Request))) {
        return STATUS_REVISION_MISMATCH;
    }
    if (RequestorProcessId == 0 ||
        Request->ClientProcessId != RequestorProcessId) {
        return STATUS_ACCESS_DENIED;
    }

    if (!NT_SUCCESS(XdowsValidateClientProcess(RequestorProcessId))) {
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            0,
            0,
            L"Bridge",
            L"Client registration denied because the caller image is not trusted.");
        return STATUS_ACCESS_DENIED;
    }

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    if (g_XdowsDriverContext.ClientConnected &&
        g_XdowsDriverContext.ClientProcessId != ULongToHandle(RequestorProcessId)) {
        KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
        return STATUS_DEVICE_BUSY;
    }
    g_XdowsDriverContext.ClientConnected = TRUE;
    g_XdowsDriverContext.ClientProcessId = ULongToHandle(RequestorProcessId);
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);

    RtlZeroMemory(Response, sizeof(*Response));
    XdowsInitializeHeader(&Response->Header, sizeof(*Response));
    Response->Status = STATUS_SUCCESS;
    Response->ProtocolVersion = XDOWS_SECURITY_PROTOCOL_VERSION;
    Response->DefaultKernelWaitTimeoutMs = XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;
    Response->Capabilities = XDOWS_SECURITY_CAP_PRIORITY_QUEUE |
        XDOWS_SECURITY_CAP_DIRTY_WRITE_COALESCING |
        XDOWS_SECURITY_CAP_BUILD_ID |
        XDOWS_SECURITY_CAP_STARTUP_SELF_PROTECT |
        XDOWS_SECURITY_CAP_USER_DECISION_HOLD;
    Response->DriverBuildId = XDOWS_SECURITY_DRIVER_BUILD_ID;
    tokenStatus = XdowsTokenAuthCopyOneTimeToken(
        Response->ShutdownToken,
        RTL_NUMBER_OF(Response->ShutdownToken));
    if (tokenStatus == STATUS_NOT_FOUND) {
        tokenStatus = XdowsTokenAuthRotate();
        if (NT_SUCCESS(tokenStatus)) {
            tokenStatus = XdowsTokenAuthCopyOneTimeToken(
                Response->ShutdownToken,
                RTL_NUMBER_OF(Response->ShutdownToken));
        }
    }
    if (!NT_SUCCESS(tokenStatus)) {
        Response->Status = tokenStatus;
        XdowsDisconnectClient();
        return tokenStatus;
    }

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Bridge", L"Client registered.");
    return STATUS_SUCCESS;
}

BOOLEAN
XdowsIsRegisteredClientProcess(
    _In_ ULONG ProcessId
    )
{
    KIRQL oldIrql;
    BOOLEAN registered;

    if (ProcessId == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    registered = g_XdowsDriverContext.Initialized &&
        g_XdowsDriverContext.ClientConnected &&
        g_XdowsDriverContext.ClientProcessId == ULongToHandle(ProcessId);
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
    return registered;
}

VOID
XdowsDisconnectClient(
    VOID
    )
{
    KIRQL oldIrql;
    LIST_ENTRY localList;

    InitializeListHead(&localList);

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    g_XdowsDriverContext.ClientConnected = FALSE;
    g_XdowsDriverContext.ClientProcessId = NULL;

    while (!IsListEmpty(&g_XdowsDriverContext.PendingEvents)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_XdowsDriverContext.PendingEvents);
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        pending->Linked = FALSE;
        InsertTailList(&localList, entry);
    }
    g_XdowsDriverContext.PendingEventCount = 0;
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
    KeSetEvent(&g_XdowsDriverContext.PendingAvailableEvent, IO_NO_INCREMENT, FALSE);

    while (!IsListEmpty(&localList)) {
        PLIST_ENTRY entry = RemoveHeadList(&localList);
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
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

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Bridge", L"Client state cleared.");
}

NTSTATUS
XdowsHeartbeat(
    _In_ PXDOWS_SECURITY_HEARTBEAT_REQUEST Request
    )
{
    KIRQL oldIrql;
    BOOLEAN connected;

    if (!XdowsIsHeaderValid(&Request->Header, sizeof(*Request))) {
        return STATUS_REVISION_MISMATCH;
    }

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    connected = g_XdowsDriverContext.ClientConnected &&
        g_XdowsDriverContext.ClientProcessId == ULongToHandle(Request->ClientProcessId);
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);

    return connected ? STATUS_SUCCESS : STATUS_DEVICE_NOT_CONNECTED;
}

NTSTATUS
XdowsGetNextPendingEvent(
    _Out_ PXDOWS_SECURITY_EVENT Event
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;

    for (;;) {
        KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);

        for (entry = g_XdowsDriverContext.PendingEvents.Flink;
             entry != &g_XdowsDriverContext.PendingEvents;
             entry = entry->Flink) {
            PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
            if (!pending->Delivered) {
                pending->Delivered = TRUE;
                RtlCopyMemory(Event, &pending->Event, sizeof(*Event));
                KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
                return STATUS_SUCCESS;
            }
        }

        KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
        timeout.QuadPart = -(LONGLONG)1000 * 10000LL;
        waitStatus = KeWaitForSingleObject(
            &g_XdowsDriverContext.PendingAvailableEvent,
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
XdowsSubmitDecision(
    _In_ PXDOWS_SECURITY_DECISION Decision
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    if (!XdowsIsHeaderValid(&Decision->Header, sizeof(*Decision))) {
        return STATUS_REVISION_MISMATCH;
    }

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);

    for (entry = g_XdowsDriverContext.PendingEvents.Flink;
         entry != &g_XdowsDriverContext.PendingEvents;
         entry = entry->Flink) {
        PXDOWS_PENDING_EVENT pending = CONTAINING_RECORD(entry, XDOWS_PENDING_EVENT, Link);
        if (pending->Event.EventId == Decision->EventId) {
            if (Decision->Decision == XdowsSecurityDecisionPending) {
                if (pending->UserDecisionPending || pending->FinalDecisionSubmitted) {
                    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
                    return STATUS_INVALID_DEVICE_STATE;
                }
                pending->UserDecisionPending = TRUE;
            } else {
                if (pending->FinalDecisionSubmitted) {
                    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
                    return STATUS_INVALID_DEVICE_STATE;
                }
                pending->FinalDecisionSubmitted = TRUE;
            }
            RtlCopyMemory(&pending->Decision, Decision, sizeof(*Decision));
            KeSetEvent(&pending->DecisionEvent, IO_NO_INCREMENT, FALSE);
            KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
    return STATUS_NOT_FOUND;
}

NTSTATUS
XdowsQueueEventAndWait(
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

    RtlZeroMemory(Decision, sizeof(*Decision));
    XdowsInitializeHeader(&Decision->Header, sizeof(*Decision));
    Decision->Decision = XdowsSecurityDecisionAllow;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
        g_XdowsDriverContext.ReceivedByType[Event->EventType]++;
    }
    if (!g_XdowsDriverContext.ClientConnected) {
        g_XdowsDriverContext.DroppedEventCount++;
        if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
            g_XdowsDriverContext.DroppedByType[Event->EventType]++;
        }
        KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
        XdowsLogWrite(XdowsSecurityLogWarning, Event->EventId, Event->CorrelationId, L"Queue", L"Event dropped because client is not connected.");
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    if (g_XdowsDriverContext.PendingEventCount >= XDOWS_SECURITY_MAX_PENDING_EVENTS) {
        g_XdowsDriverContext.DroppedEventCount++;
        if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
            g_XdowsDriverContext.DroppedByType[Event->EventType]++;
        }
        KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
        XdowsLogWrite(XdowsSecurityLogWarning, Event->EventId, Event->CorrelationId, L"Queue", L"Event dropped because pending queue is full.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);

    pending = (PXDOWS_PENDING_EVENT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*pending),
        'swDX');
    if (pending == NULL) {
        XdowsLogWrite(XdowsSecurityLogError, Event->EventId, Event->CorrelationId, L"Queue", L"Event allocation failed.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pending, sizeof(*pending));
    XdowsInitializeHeader(&Event->Header, sizeof(*Event));
    if (Event->EventId == 0) {
        Event->EventId = XdowsAllocateEventId();
    }
    if (Event->CorrelationId == 0) {
        Event->CorrelationId = Event->EventId;
    }
    if (Event->KernelWaitTimeoutMs == 0) {
        Event->KernelWaitTimeoutMs = XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;
    }

    RtlCopyMemory(&pending->Event, Event, sizeof(*Event));
    KeInitializeEvent(&pending->DecisionEvent, NotificationEvent, FALSE);

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    if (g_XdowsDriverContext.ClientConnected &&
        g_XdowsDriverContext.PendingEventCount < XDOWS_SECURITY_MAX_PENDING_EVENTS) {
        if (XdowsIsCriticalEventType(Event->EventType)) {
            PLIST_ENTRY insertionPoint = g_XdowsDriverContext.PendingEvents.Flink;
            while (insertionPoint != &g_XdowsDriverContext.PendingEvents) {
                PXDOWS_PENDING_EVENT existing = CONTAINING_RECORD(insertionPoint, XDOWS_PENDING_EVENT, Link);
                if (!XdowsIsCriticalEventType(existing->Event.EventType)) {
                    break;
                }
                insertionPoint = insertionPoint->Flink;
            }
            InsertTailList(insertionPoint, &pending->Link);
        } else {
            InsertTailList(&g_XdowsDriverContext.PendingEvents, &pending->Link);
        }
        pending->Linked = TRUE;
        linked = TRUE;
        g_XdowsDriverContext.PendingEventCount++;
        KeSetEvent(&g_XdowsDriverContext.PendingAvailableEvent, IO_NO_INCREMENT, FALSE);
    } else {
        g_XdowsDriverContext.DroppedEventCount++;
        if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
            g_XdowsDriverContext.DroppedByType[Event->EventType]++;
        }
    }
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);

    if (!linked) {
        ExFreePoolWithTag(pending, 'swDX');
        XdowsLogWrite(XdowsSecurityLogWarning, Event->EventId, Event->CorrelationId, L"Queue", L"Event dropped before delivery.");
        return STATUS_DEVICE_NOT_CONNECTED;
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
        KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
        RtlCopyMemory(Decision, &pending->Decision, sizeof(*Decision));
        userDecisionPending = pending->UserDecisionPending;
        if (Decision->Decision == XdowsSecurityDecisionPending) {
            KeResetEvent(&pending->DecisionEvent);
            KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
            XdowsLogWrite(
                XdowsSecurityLogInfo,
                Event->EventId,
                Event->CorrelationId,
                L"Decision",
                L"Confirmed threat is waiting for a user decision.");
            continue;
        }
        KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
        break;
    }

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    if (pending->Linked) {
        RemoveEntryList(&pending->Link);
        pending->Linked = FALSE;
        if (g_XdowsDriverContext.PendingEventCount > 0) {
            g_XdowsDriverContext.PendingEventCount--;
        }
    }
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);

    if (status == STATUS_SUCCESS) {
        if (userDecisionPending &&
            Decision->Decision == XdowsSecurityDecisionTimeout) {
            Decision->Decision = XdowsSecurityDecisionBlock;
            Decision->ResultCode = (ULONG)STATUS_TIMEOUT;
            (VOID)RtlStringCchCopyW(
                Decision->Reason,
                RTL_NUMBER_OF(Decision->Reason),
                L"user-decision-timeout-blocked");
            XdowsLogWrite(
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
        KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
        if (Event->EventType < XDOWS_SECURITY_EVENT_TYPE_COUNT) {
            g_XdowsDriverContext.TimedOutByType[Event->EventType]++;
        }
        KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);
        if (userDecisionPending) {
            XdowsLogWriteStatus(
                XdowsSecurityLogWarning,
                Event->EventId,
                Event->CorrelationId,
                L"Decision",
                L"User decision timed out; operation blocked",
                status);
        } else {
            XdowsLogWriteStatus(
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
XdowsGetState(
    _Out_ PXDOWS_SECURITY_STATE State
    )
{
    KIRQL oldIrql;
    HANDLE clientProcessId;

    RtlZeroMemory(State, sizeof(*State));
    XdowsInitializeHeader(&State->Header, sizeof(*State));

    KeAcquireSpinLock(&g_XdowsDriverContext.Lock, &oldIrql);
    State->ClientConnected = g_XdowsDriverContext.ClientConnected ? 1 : 0;
    State->PendingEventCount = g_XdowsDriverContext.PendingEventCount;
    State->DroppedEventCount = g_XdowsDriverContext.DroppedEventCount;
    State->ProcessProtectionEnabled = g_XdowsDriverContext.ProcessProtectionEnabled ? 1 : 0;
    State->FileProtectionEnabled = g_XdowsDriverContext.FileProtectionEnabled ? 1 : 0;
    clientProcessId = g_XdowsDriverContext.ClientProcessId;
    State->ActiveModules = XdowsModulesGetActiveMask();
    State->ProtocolVersion = XDOWS_SECURITY_PROTOCOL_VERSION;
    State->Capabilities = XDOWS_SECURITY_CAP_PRIORITY_QUEUE |
        XDOWS_SECURITY_CAP_DIRTY_WRITE_COALESCING |
        XDOWS_SECURITY_CAP_BUILD_ID |
        XDOWS_SECURITY_CAP_STARTUP_SELF_PROTECT |
        XDOWS_SECURITY_CAP_USER_DECISION_HOLD;
    State->DriverBuildId = XDOWS_SECURITY_DRIVER_BUILD_ID;
    RtlCopyMemory(State->ReceivedByType, g_XdowsDriverContext.ReceivedByType, sizeof(State->ReceivedByType));
    RtlCopyMemory(State->DroppedByType, g_XdowsDriverContext.DroppedByType, sizeof(State->DroppedByType));
    RtlCopyMemory(State->TimedOutByType, g_XdowsDriverContext.TimedOutByType, sizeof(State->TimedOutByType));
    KeReleaseSpinLock(&g_XdowsDriverContext.Lock, oldIrql);

    State->SelfProtectionEnabled = XdowsSelfProtectIsProcessProtected(clientProcessId) ? 1 : 0;
    State->ProtectedProcessId = State->SelfProtectionEnabled
        ? HandleToULong(clientProcessId)
        : 0;
    State->StartupProtectionEnabled =
        XdowsSelfProtectIsStartupProtectionEnabled() ? 1 : 0;
}
