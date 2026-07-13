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
#define XDOWS_SECURITY_MAX_PENDING_EVENTS 128

typedef struct _XDOWS_PENDING_EVENT {
    LIST_ENTRY Link;
    XDOWS_SECURITY_EVENT Event;
    XDOWS_SECURITY_DECISION Decision;
    KEVENT DecisionEvent;
    BOOLEAN Delivered;
    BOOLEAN Linked;
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
} XDOWS_DRIVER_CONTEXT, *PXDOWS_DRIVER_CONTEXT;

extern XDOWS_DRIVER_CONTEXT g_XdowsDriverContext;

NTSTATUS
XdowsInitializeGlobalContext(
    _In_ WDFDEVICE Device
    );

VOID
XdowsShutdownGlobalContext(
    VOID
    );

NTSTATUS
XdowsRegisterClient(
    _In_ PXDOWS_SECURITY_REGISTER_REQUEST Request,
    _Out_ PXDOWS_SECURITY_REGISTER_RESPONSE Response
    );

VOID
XdowsDisconnectClient(
    VOID
    );

NTSTATUS
XdowsHeartbeat(
    _In_ PXDOWS_SECURITY_HEARTBEAT_REQUEST Request
    );

NTSTATUS
XdowsGetNextPendingEvent(
    _Out_ PXDOWS_SECURITY_EVENT Event
    );

NTSTATUS
XdowsSubmitDecision(
    _In_ PXDOWS_SECURITY_DECISION Decision
    );

NTSTATUS
XdowsQueueEventAndWait(
    _Inout_ PXDOWS_SECURITY_EVENT Event,
    _Out_ PXDOWS_SECURITY_DECISION Decision
    );

VOID
XdowsGetState(
    _Out_ PXDOWS_SECURITY_STATE State
    );

ULONGLONG
XdowsAllocateEventId(
    VOID
    );

EXTERN_C_END
