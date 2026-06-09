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
    LIST_ENTRY PendingEvents;
    ULONG PendingEventCount;
    ULONG DroppedEventCount;
    ULONG64 NextEventId;
    HANDLE ClientProcessId;
    BOOLEAN ClientConnected;
    BOOLEAN Initialized;
    BOOLEAN ProcessProtectionEnabled;
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
