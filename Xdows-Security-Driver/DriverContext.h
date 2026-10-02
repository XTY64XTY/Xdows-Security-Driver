/*++

Module Name:

    drivercontext.h

Abstract:

    Global bridge state shared by KMDF IOCTL handling and protection modules.

--*/

#pragma once

#include "public.h"

EXTERN_C_START

#define XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS 5000u
#define XDOWS_FILE_CREATE_KERNEL_WAIT_TIMEOUT_MS 1000u
#define XDOWS_SECURITY_USER_DECISION_TIMEOUT_MS 25000u
//
// Upper bound for user-mode-supplied kernel wait timeouts. Must stay above
// XDOWS_SECURITY_USER_DECISION_TIMEOUT_MS (25 s) so interactive prompts are
// never clamped, but small enough that a malicious or malformed request
// cannot pin a kernel thread for days.
//
#define XDOWS_SECURITY_MAX_KERNEL_WAIT_TIMEOUT_MS 30000u
#define XDOWS_SECURITY_MAX_PENDING_EVENTS 128

//
// Per-event-type sliding-window throttle. Only non-critical event types are
// rate limited; the window is one second of interrupt time (100ns units).
//
typedef struct _XDOWS_THROTTLE_SLOT {
    ULONGLONG WindowStart100ns;
    ULONG Count;
    ULONG Reserved;
} XDOWS_THROTTLE_SLOT, *PXDOWS_THROTTLE_SLOT;

typedef struct _XDOWS_PENDING_EVENT {
    LIST_ENTRY Link;
    XDOWS_SECURITY_EVENT Event;
    XDOWS_SECURITY_DECISION Decision;
    KEVENT DecisionEvent;
    BOOLEAN Delivered;
    BOOLEAN Linked;
    BOOLEAN UserDecisionPending;
    BOOLEAN FinalDecisionSubmitted;
    BOOLEAN Async;
} XDOWS_PENDING_EVENT, *PXDOWS_PENDING_EVENT;

typedef struct _XDOWS_DRIVER_CONTEXT {
    WDFDEVICE Device;
    KSPIN_LOCK Lock;
    KEVENT PendingAvailableEvent;
    LIST_ENTRY PendingEvents;
    ULONG PendingEventCount;
    ULONG DroppedEventCount;
    ULONG ReceivedByType[XDOWS_SECURITY_EVENT_TYPE_COUNT];
    ULONG DroppedByType[XDOWS_SECURITY_EVENT_TYPE_COUNT];
    ULONG TimedOutByType[XDOWS_SECURITY_EVENT_TYPE_COUNT];
    ULONG64 NextEventId;
    XDOWS_THROTTLE_SLOT Throttle[XDOWS_SECURITY_EVENT_TYPE_COUNT];
    //
    // Read lock-free by protection modules (e.g. InjectionProtect's trusted-
    // source check). Marked volatile so the compiler does not cache a stale
    // register copy across the Ob callback's fast-exit chain. Writes still
    // happen under Lock, so volatile only affects readers.
    //
    volatile HANDLE ClientProcessId;
    BOOLEAN ClientConnected;
    BOOLEAN Initialized;
    BOOLEAN ProcessProtectionEnabled;
    BOOLEAN FileProtectionEnabled;
    //
    // Set from the REGISTER_REQUEST Flags when the client opts into async
    // review. Read lock-free by the event-queue path; benign if a racing
    // register flips it one event late.
    //
    volatile BOOLEAN AsyncReviewEnabled;
} XDOWS_DRIVER_CONTEXT, *PXDOWS_DRIVER_CONTEXT;

extern XDOWS_DRIVER_CONTEXT g_DriverContext;

NTSTATUS
InitializeGlobalContext(
    _In_ WDFDEVICE Device
    );

VOID
ShutdownGlobalContext(
    VOID
    );

NTSTATUS
RegisterClient(
    _In_ PXDOWS_SECURITY_REGISTER_REQUEST Request,
    _In_ ULONG RequestorProcessId,
    _Out_ PXDOWS_SECURITY_REGISTER_RESPONSE Response
    );

BOOLEAN
IsRegisteredClientProcess(
    _In_ ULONG ProcessId
    );

VOID
DisconnectClient(
    VOID
    );

NTSTATUS
Heartbeat(
    _In_ PXDOWS_SECURITY_HEARTBEAT_REQUEST Request
    );

NTSTATUS
GetNextPendingEvent(
    _Out_ PXDOWS_SECURITY_EVENT Event
    );

NTSTATUS
GetNextPendingEventsBatch(
    _Out_ PXDOWS_SECURITY_EVENT_BATCH Batch,
    _In_ ULONG OutputBufferLength
    );

NTSTATUS
SubmitDecision(
    _In_ PXDOWS_SECURITY_DECISION Decision
    );

NTSTATUS
QueueEventAndWait(
    _Inout_ PXDOWS_SECURITY_EVENT Event,
    _Out_ PXDOWS_SECURITY_DECISION Decision
    );

VOID
GetState(
    _Out_ PXDOWS_SECURITY_STATE State
    );

ULONGLONG
AllocateEventId(
    VOID
    );

EXTERN_C_END
