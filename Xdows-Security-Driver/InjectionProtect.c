#include "driver.h"
#include <ntstrsafe.h>

//
// PsGetThreadProcess is declared only in ntifs.h, which this driver does not
// include. Forward-declare it here; the function is exported by ntoskrnl.lib.
//
NTKERNELAPI PEPROCESS PsGetThreadProcess(_In_ PETHREAD Thread);

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif

#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif

//
// Core dangerous process access rights for injection: CreateRemoteThread,
// WriteProcessMemory, and DuplicateHandle into the target process form the
// classic DLL injection primitive. Each is suspicious on its own.
//
#define XDOWS_INJECTION_PROCESS_ACCESS_CORE \
    (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | \
     PROCESS_DUP_HANDLE)

//
// PROCESS_SUSPEND_RESUME alone is widely used by job objects, profilers, and
// debuggers, producing high false positives. Treat it as suspicious only when
// requested together with PROCESS_VM_WRITE (suspend target then write memory
// is a typical injection prefix).
//
#define XDOWS_INJECTION_PROCESS_SUSPEND_RESUME_ACCESS \
    (PROCESS_SUSPEND_RESUME)

#define XDOWS_INJECTION_PROCESS_VM_WRITE_ACCESS \
    (PROCESS_VM_WRITE)

//
// Thread context modification is the core of SetThreadContext-based injection
// and is suspicious on its own.
//
#define XDOWS_INJECTION_THREAD_ACCESS_CORE \
    (THREAD_SET_CONTEXT)

//
// THREAD_SUSPEND_RESUME alone is legitimate and frequent (debuggers, samplers,
// task manager). Treat it as suspicious only when requested together with
// THREAD_SET_CONTEXT (suspend thread then modify its context is a typical
// injection prefix).
//
#define XDOWS_INJECTION_THREAD_SUSPEND_RESUME_ACCESS \
    (THREAD_SUSPEND_RESUME)

//
// Synchronous handle-decision wait timeout. The previous 3000ms value would
// stall every cross-process handle operation for 3 seconds when user mode was
// unresponsive, making the system feel frozen. 500ms covers normal user-mode
// round trips.
//
#define XDOWS_INJECTION_KERNEL_WAIT_TIMEOUT_MS 500u

//
// Short-lived Allow decision cache. Repeated handle requests from the same
// source to the same target (e.g. explorer enumerating processes) should not
// repeatedly prompt user mode. Only Allow is cached; Block/Timeout are not.
// TTL matches the spec's "explicit threat release" value of 5 minutes.
// The cache key includes the target process creation time to resist PID reuse.
//
#define XDOWS_INJECTION_CACHE_CAPACITY 64u
#define XDOWS_INJECTION_CACHE_TTL_MS (5u * 60u * 1000u)
#define XDOWS_INJECTION_CACHE_TTL_100NS ((LONGLONG)XDOWS_INJECTION_CACHE_TTL_MS * 10000LL)

typedef struct _XDOWS_INJECTION_CACHE_ENTRY {
    ULONG SourceProcessId;
    ULONG TargetProcessId;
    ULONGLONG TargetProcessCreateTime;
    ACCESS_MASK AllowedDangerousMask;
    LARGE_INTEGER AllowTime;
    BOOLEAN InUse;
} XDOWS_INJECTION_CACHE_ENTRY, *PXDOWS_INJECTION_CACHE_ENTRY;

static PVOID g_InjectionObRegistration;
static XDOWS_INJECTION_CACHE_ENTRY g_InjectionCache[XDOWS_INJECTION_CACHE_CAPACITY];
static KSPIN_LOCK g_InjectionCacheLock;

static
ACCESS_MASK*
XdowsInjectionDesiredAccess(
    _Inout_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        return &Info->Parameters->CreateHandleInformation.DesiredAccess;
    }

    if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        return &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    return NULL;
}

//
// Allow cache lookup. Uses (source PID, target PID, target creation time)
// superset matching: a hit occurs when the cached allowed dangerous set
// covers all dangerous bits of the current request. Expired entries are
// lazily cleared.
//
static
BOOLEAN
XdowsInjectionCacheLookup(
    _In_ ULONG SourceProcessId,
    _In_ ULONG TargetProcessId,
    _In_ ULONGLONG TargetProcessCreateTime,
    _In_ ACCESS_MASK RequestedDangerous
    )
{
    KIRQL oldIrql;
    LARGE_INTEGER now;
    BOOLEAN hit = FALSE;
    ULONG i;

    KeQuerySystemTime(&now);
    KeAcquireSpinLock(&g_InjectionCacheLock, &oldIrql);
    for (i = 0; i < XDOWS_INJECTION_CACHE_CAPACITY; i++) {
        PXDOWS_INJECTION_CACHE_ENTRY entry = &g_InjectionCache[i];
        if (!entry->InUse) {
            continue;
        }
        if (entry->SourceProcessId != SourceProcessId ||
            entry->TargetProcessId != TargetProcessId ||
            entry->TargetProcessCreateTime != TargetProcessCreateTime) {
            continue;
        }
        if (now.QuadPart - entry->AllowTime.QuadPart > XDOWS_INJECTION_CACHE_TTL_100NS) {
            entry->InUse = FALSE;
            continue;
        }
        if ((RequestedDangerous & ~entry->AllowedDangerousMask) == 0) {
            hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_InjectionCacheLock, oldIrql);
    return hit;
}

//
// Record an Allow decision. If an existing (source, target, creation time)
// entry is found, merge the rights and refresh the time; otherwise take a
// free slot or replace the oldest entry.
//
static
VOID
XdowsInjectionCacheRecordAllow(
    _In_ ULONG SourceProcessId,
    _In_ ULONG TargetProcessId,
    _In_ ULONGLONG TargetProcessCreateTime,
    _In_ ACCESS_MASK AllowedDangerous
    )
{
    KIRQL oldIrql;
    LARGE_INTEGER now;
    PXDOWS_INJECTION_CACHE_ENTRY target = NULL;
    PXDOWS_INJECTION_CACHE_ENTRY oldest = NULL;
    LONGLONG oldestTime = 0x7FFFFFFFFFFFFFFFLL;
    ULONG i;

    KeQuerySystemTime(&now);
    KeAcquireSpinLock(&g_InjectionCacheLock, &oldIrql);

    for (i = 0; i < XDOWS_INJECTION_CACHE_CAPACITY; i++) {
        PXDOWS_INJECTION_CACHE_ENTRY entry = &g_InjectionCache[i];
        if (entry->InUse &&
            entry->SourceProcessId == SourceProcessId &&
            entry->TargetProcessId == TargetProcessId &&
            entry->TargetProcessCreateTime == TargetProcessCreateTime) {
            target = entry;
            break;
        }
    }

    if (target != NULL) {
        target->AllowedDangerousMask |= AllowedDangerous;
        target->AllowTime = now;
    } else {
        for (i = 0; i < XDOWS_INJECTION_CACHE_CAPACITY; i++) {
            PXDOWS_INJECTION_CACHE_ENTRY entry = &g_InjectionCache[i];
            if (!entry->InUse) {
                target = entry;
                break;
            }
            if (entry->AllowTime.QuadPart < oldestTime) {
                oldestTime = entry->AllowTime.QuadPart;
                oldest = entry;
            }
        }
        if (target == NULL) {
            target = oldest;
        }
        target->SourceProcessId = SourceProcessId;
        target->TargetProcessId = TargetProcessId;
        target->TargetProcessCreateTime = TargetProcessCreateTime;
        target->AllowedDangerousMask = AllowedDangerous;
        target->AllowTime = now;
        target->InUse = TRUE;
    }

    KeReleaseSpinLock(&g_InjectionCacheLock, oldIrql);
}

static
BOOLEAN
XdowsInjectionAskUser(
    _In_ ULONG EventType,
    _In_ ULONG TargetProcessId,
    _In_ ULONG TargetThreadId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PULONGLONG EventId,
    _Out_opt_ PULONGLONG CorrelationId
    )
{
    XDOWS_SECURITY_EVENT event;
    XDOWS_SECURITY_DECISION decision;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.Header.Size = sizeof(event);
    event.Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
    event.EventId = XdowsAllocateEventId();
    event.CorrelationId = event.EventId;
    event.EventType = EventType;
    event.Flags = XdowsSecurityEventFlagUserModeRequired;
    event.ProcessId = TargetProcessId;
    event.CreatingProcessId = HandleToULong(PsGetCurrentProcessId());
    event.CreatingThreadId = HandleToULong(PsGetCurrentThreadId());
    event.ParentProcessId = TargetThreadId;
    event.KernelWaitTimeoutMs = XDOWS_INJECTION_KERNEL_WAIT_TIMEOUT_MS;

    (VOID)RtlStringCchPrintfW(
        event.CommandLine,
        RTL_NUMBER_OF(event.CommandLine),
        L"desired-access=0x%08X",
        DesiredAccess);

    if (EventId != NULL) {
        *EventId = event.EventId;
    }
    if (CorrelationId != NULL) {
        *CorrelationId = event.CorrelationId;
    }

    status = XdowsQueueEventAndWait(&event, &decision);
    if (!NT_SUCCESS(status)) {
        XdowsLogWriteStatus(
            XdowsSecurityLogWarning,
            event.EventId,
            event.CorrelationId,
            L"Injection",
            L"Sensitive handle decision failed",
            status);
        return FALSE;
    }

    return decision.Decision == XdowsSecurityDecisionAllow;
}

static
OB_PREOP_CALLBACK_STATUS
XdowsInjectionPreOperation(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    ACCESS_MASK* desiredAccess;
    ACCESS_MASK dangerousMask;
    ACCESS_MASK requestedMask;
    ACCESS_MASK effectiveDangerous;
    HANDLE targetProcessId;
    HANDLE targetThreadId = NULL;
    ULONG eventType;
    ULONG sourcePid;
    ULONG targetPid;
    ULONGLONG targetCreateTime = 0;
    ULONGLONG eventId = 0;
    ULONGLONG correlationId = 0;

    UNREFERENCED_PARAMETER(RegistrationContext);

    desiredAccess = XdowsInjectionDesiredAccess(Info);
    if (desiredAccess == NULL || *desiredAccess == 0) {
        return OB_PREOP_SUCCESS;
    }

    requestedMask = *desiredAccess;

    if (Info->ObjectType == *PsProcessType) {
        PEPROCESS targetProcess = (PEPROCESS)Info->Object;
        targetProcessId = PsGetProcessId(targetProcess);
        eventType = XdowsSecurityEventProcessHandle;
        dangerousMask = XDOWS_INJECTION_PROCESS_ACCESS_CORE;
        // PROCESS_SUSPEND_RESUME is suspicious only together with PROCESS_VM_WRITE
        if ((requestedMask & XDOWS_INJECTION_PROCESS_SUSPEND_RESUME_ACCESS) &&
            (requestedMask & XDOWS_INJECTION_PROCESS_VM_WRITE_ACCESS)) {
            dangerousMask |= XDOWS_INJECTION_PROCESS_SUSPEND_RESUME_ACCESS;
        }
        targetCreateTime = PsGetProcessCreateTimeQuadPart(targetProcess);
    } else if (Info->ObjectType == *PsThreadType) {
        PETHREAD targetThread = (PETHREAD)Info->Object;
        targetProcessId = PsGetThreadProcessId(targetThread);
        targetThreadId = PsGetThreadId(targetThread);
        eventType = XdowsSecurityEventThreadHandle;
        dangerousMask = XDOWS_INJECTION_THREAD_ACCESS_CORE;
        // THREAD_SUSPEND_RESUME is suspicious only together with THREAD_SET_CONTEXT
        if ((requestedMask & XDOWS_INJECTION_THREAD_SUSPEND_RESUME_ACCESS) &&
            (requestedMask & XDOWS_INJECTION_THREAD_ACCESS_CORE)) {
            dangerousMask |= XDOWS_INJECTION_THREAD_SUSPEND_RESUME_ACCESS;
        }
        targetCreateTime = PsGetProcessCreateTimeQuadPart(PsGetThreadProcess(targetThread));
    } else {
        return OB_PREOP_SUCCESS;
    }

    effectiveDangerous = requestedMask & dangerousMask;

    if (targetProcessId == NULL ||
        targetProcessId == PsGetCurrentProcessId() ||
        effectiveDangerous == 0) {
        return OB_PREOP_SUCCESS;
    }

    sourcePid = HandleToULong(PsGetCurrentProcessId());
    targetPid = HandleToULong(targetProcessId);

    // Cache hit: skip user-mode prompt for repeated requests
    if (XdowsInjectionCacheLookup(sourcePid, targetPid, targetCreateTime, effectiveDangerous)) {
        return OB_PREOP_SUCCESS;
    }

    if (XdowsInjectionAskUser(
        eventType,
        targetPid,
        HandleToULong(targetThreadId),
        effectiveDangerous,
        &eventId,
        &correlationId)) {
        // User allowed: record in cache for subsequent repeated requests
        XdowsInjectionCacheRecordAllow(sourcePid, targetPid, targetCreateTime, effectiveDangerous);
        return OB_PREOP_SUCCESS;
    }

    *desiredAccess &= ~dangerousMask;
    XdowsLogWrite(
        XdowsSecurityLogWarning,
        eventId,
        correlationId,
        L"Injection",
        L"Dangerous handle permissions stripped.");
    return OB_PREOP_SUCCESS;
}

NTSTATUS
XdowsInjectionProtectInitialize(
    VOID
    )
{
    OB_OPERATION_REGISTRATION operations[2];
    OB_CALLBACK_REGISTRATION registration;
    UNICODE_STRING altitude;
    NTSTATUS status;

    if (g_InjectionObRegistration != NULL) {
        return STATUS_SUCCESS;
    }

    KeInitializeSpinLock(&g_InjectionCacheLock);
    RtlZeroMemory(g_InjectionCache, sizeof(g_InjectionCache));

    RtlZeroMemory(operations, sizeof(operations));
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = XdowsInjectionPreOperation;

    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = XdowsInjectionPreOperation;

    RtlInitUnicodeString(&altitude, L"370031.20");
    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = RTL_NUMBER_OF(operations);
    registration.Altitude = altitude;
    registration.OperationRegistration = operations;

    status = ObRegisterCallbacks(&registration, &g_InjectionObRegistration);
    if (!NT_SUCCESS(status)) {
        g_InjectionObRegistration = NULL;
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"Injection", L"OB callback registration failed", status);
        return status;
    }

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Injection", L"Injection callbacks registered.");
    return STATUS_SUCCESS;
}

VOID
XdowsInjectionProtectShutdown(
    VOID
    )
{
    PVOID handle = g_InjectionObRegistration;
    g_InjectionObRegistration = NULL;

    if (handle != NULL) {
        ObUnRegisterCallbacks(handle);
    }

    // ObUnRegisterCallbacks synchronously waits for all in-flight callbacks,
    // so clearing the cache here without the lock is safe.
    RtlZeroMemory(g_InjectionCache, sizeof(g_InjectionCache));

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Injection", L"Injection callbacks unregistered.");
}
