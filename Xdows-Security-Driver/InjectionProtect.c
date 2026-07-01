/*++

Module Name:

    injectionprotect.c

Abstract:

    Cross-process injection prevention for arbitrary target processes.

    Unlike SelfProtect (which guards the Xdows Security process itself), this
    module watches handle opens to *any* process or thread and consults
    user-mode policy when dangerous access rights are requested. An Allow
    verdict is cached per (source, target, target-creation-time) tuple so
    repeated handle requests (e.g. explorer enumerating processes) do not
    flood user mode. Block verdicts strip the dangerous rights in place.

    This module is self-contained: it depends only on the kernel object
    callback API, the bridge queue, and the shared log facility. A failure
    here never affects other protection modules.

    Synchronization: all entry points run at PASSIVE_LEVEL (Ob pre-operation
    callbacks and IOCTL/Initialize/Shutdown alike), so an EX_PUSH_LOCK guards
    the verdict cache instead of a spin lock, keeping the hot path off
    DISPATCH_LEVEL.

Environment:

    Kernel-mode Driver Framework

--*/

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
// Primary injection primitive: remote thread creation, memory writes, and
// handle duplication into the target. Each is dangerous on its own.
//
#define XDOWS_INJECTION_PROCESS_PRIMARY_MASK    \
    (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | \
     PROCESS_DUP_HANDLE)

//
// PROCESS_SUSPEND_RESUME is benign alone (jobs, profilers, debuggers) and
// produces high false-positive rates. It is treated as a threat only when
// paired with PROCESS_VM_WRITE, which forms the classic "suspend then write"
// injection prefix.
//
#define XDOWS_INJECTION_PROCESS_SUSPEND_RESUME_MASK    (PROCESS_SUSPEND_RESUME)
#define XDOWS_INJECTION_PROCESS_VM_WRITE_MASK          (PROCESS_VM_WRITE)

//
// Thread-context modification is the SetThreadContext injection primitive and
// is dangerous on its own.
//
#define XDOWS_INJECTION_THREAD_PRIMARY_MASK    (THREAD_SET_CONTEXT)

//
// THREAD_SUSPEND_RESUME alone is legitimate (debuggers, samplers). It is a
// threat only when paired with THREAD_SET_CONTEXT ("suspend then hijack").
//
#define XDOWS_INJECTION_THREAD_SUSPEND_RESUME_MASK   (THREAD_SUSPEND_RESUME)
#define XDOWS_INJECTION_THREAD_SET_CONTEXT_MASK       (THREAD_SET_CONTEXT)

//
// Synchronous user-mode consultation timeout. 500ms covers normal round
// trips; a longer value would freeze every cross-process handle open when
// user mode is unresponsive.
//
#define XDOWS_INJECTION_CONSULT_TIMEOUT_MS    500u

//
// Short-lived Allow verdict cache. Only Allow is cached; Block/Timeout are
// not. The cache key includes the target process creation time to resist PID
// reuse. TTL matches the spec's "explicit threat release" value.
//
#define XDOWS_INJECTION_VERDICT_SLOTS         64u
#define XDOWS_INJECTION_VERDICT_TTL_MS       (5u * 60u * 1000u)
#define XDOWS_INJECTION_VERDICT_TTL_100NS     ((LONGLONG)XDOWS_INJECTION_VERDICT_TTL_MS * 10000LL)

//
// A single verdict slot. InUse=FALSE means the slot is free.
//
typedef struct _XDOWS_INJECTION_VERDICT_SLOT {
    ULONG          SourceProcessId;
    ULONG          TargetProcessId;
    ULONGLONG      TargetCreateTime;
    ACCESS_MASK    GrantedMask;
    LARGE_INTEGER  GrantedAt;
    BOOLEAN        InUse;
} XDOWS_INJECTION_VERDICT_SLOT, *PXDOWS_INJECTION_VERDICT_SLOT;

typedef struct _XDOWS_INJECTION_CONTEXT {
    EX_PUSH_LOCK                 Lock;
    XDOWS_INJECTION_VERDICT_SLOT Verdicts[XDOWS_INJECTION_VERDICT_SLOTS];
    PVOID                        CallbackHandle;
} XDOWS_INJECTION_CONTEXT, *PXDOWS_INJECTION_CONTEXT;

static XDOWS_INJECTION_CONTEXT g_Injection;

//
// Description of a single handle-open target, produced by ResolveTarget.
//
typedef struct _XDOWS_INJECTION_TARGET {
    HANDLE     TargetProcessId;
    ULONG      TargetThreadId;
    ULONG      EventType;
    ULONGLONG  TargetCreateTime;
    ACCESS_MASK PrimaryMask;
    ACCESS_MASK ConditionalMask;
    ACCESS_MASK ConditionalTrigger;
} XDOWS_INJECTION_TARGET, *PXDOWS_INJECTION_TARGET;

typedef const XDOWS_INJECTION_TARGET *PCXDOWS_INJECTION_TARGET;

static
ACCESS_MASK*
XdowsInjectionDesiredAccessField(
    _In_ POB_PRE_OPERATION_INFORMATION Info
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
// Resolve the object into a target descriptor. ConditionalMask bits are only
// counted as dangerous when the request also contains ConditionalTrigger
// (e.g. SUSPEND_RESUME only matters together with VM_WRITE).
//
static
BOOLEAN
XdowsInjectionResolveTarget(
    _In_ POB_PRE_OPERATION_INFORMATION Info,
    _Out_ PXDOWS_INJECTION_TARGET Target
    )
{
    RtlZeroMemory(Target, sizeof(*Target));

    if (Info->ObjectType == *PsProcessType) {
        PEPROCESS proc = (PEPROCESS)Info->Object;
        Target->TargetProcessId = PsGetProcessId(proc);
        Target->EventType = XdowsSecurityEventProcessHandle;
        Target->TargetCreateTime = PsGetProcessCreateTimeQuadPart(proc);
        Target->PrimaryMask = XDOWS_INJECTION_PROCESS_PRIMARY_MASK;
        Target->ConditionalMask = XDOWS_INJECTION_PROCESS_SUSPEND_RESUME_MASK;
        Target->ConditionalTrigger = XDOWS_INJECTION_PROCESS_VM_WRITE_MASK;
        return TRUE;
    }

    if (Info->ObjectType == *PsThreadType) {
        PETHREAD thd = (PETHREAD)Info->Object;
        Target->TargetProcessId = PsGetThreadProcessId(thd);
        Target->TargetThreadId = HandleToULong(PsGetThreadId(thd));
        Target->EventType = XdowsSecurityEventThreadHandle;
        Target->TargetCreateTime = PsGetProcessCreateTimeQuadPart(PsGetThreadProcess(thd));
        Target->PrimaryMask = XDOWS_INJECTION_THREAD_PRIMARY_MASK;
        Target->ConditionalMask = XDOWS_INJECTION_THREAD_SUSPEND_RESUME_MASK;
        Target->ConditionalTrigger = XDOWS_INJECTION_THREAD_SET_CONTEXT_MASK;
        return TRUE;
    }

    return FALSE;
}

//
// Compute the effective dangerous mask for this request. Primary bits are
// always dangerous; conditional bits only when their trigger is also present.
//
static
ACCESS_MASK
XdowsInjectionComputeThreatMask(
    _In_ PCXDOWS_INJECTION_TARGET Target,
    _In_ ACCESS_MASK RequestedMask
    )
{
    ACCESS_MASK mask = Target->PrimaryMask;

    if ((RequestedMask & Target->ConditionalMask) &&
        (RequestedMask & Target->ConditionalTrigger)) {
        mask |= Target->ConditionalMask;
    }
    return mask;
}

//
// Verdict cache lookup. A hit requires an exact (source, target, creation
// time) match, an unexpired entry, and the cached GrantedMask covering all
// requested dangerous bits. Expired entries are lazily invalidated.
//
// Exclusive (not shared) access is taken because expired slots are invalidated
// in place. The 64-slot linear scan is O(1)-ish and never blocks on I/O, so
// exclusive access keeps the cache consistent without measurable latency.
//
static
BOOLEAN
XdowsInjectionLookupVerdict(
    _In_ ULONG SourceProcessId,
    _In_ ULONG TargetProcessId,
    _In_ ULONGLONG TargetCreateTime,
    _In_ ACCESS_MASK RequestedDangerous
    )
{
    LARGE_INTEGER now;
    BOOLEAN hit = FALSE;
    ULONG i;

    KeQuerySystemTime(&now);
    ExAcquirePushLockExclusive(&g_Injection.Lock);

    for (i = 0; i < XDOWS_INJECTION_VERDICT_SLOTS; i++) {
        PXDOWS_INJECTION_VERDICT_SLOT slot = &g_Injection.Verdicts[i];
        if (!slot->InUse) {
            continue;
        }
        if (slot->SourceProcessId != SourceProcessId ||
            slot->TargetProcessId != TargetProcessId ||
            slot->TargetCreateTime != TargetCreateTime) {
            continue;
        }
        if (now.QuadPart - slot->GrantedAt.QuadPart > XDOWS_INJECTION_VERDICT_TTL_100NS) {
            slot->InUse = FALSE;
            continue;
        }
        if ((RequestedDangerous & ~slot->GrantedMask) == 0) {
            hit = TRUE;
            break;
        }
    }

    ExReleasePushLockExclusive(&g_Injection.Lock);
    return hit;
}

//
// Record an Allow verdict. An existing matching entry merges the rights and
// refreshes the timestamp; otherwise the first free slot (or the oldest) is
// taken. Requires exclusive access.
//
static
VOID
XdowsInjectionRecordVerdict(
    _In_ ULONG SourceProcessId,
    _In_ ULONG TargetProcessId,
    _In_ ULONGLONG TargetCreateTime,
    _In_ ACCESS_MASK GrantedDangerous
    )
{
    LARGE_INTEGER now;
    PXDOWS_INJECTION_VERDICT_SLOT chosen = NULL;
    PXDOWS_INJECTION_VERDICT_SLOT oldest = NULL;
    LONGLONG oldestTime = 0x7FFFFFFFFFFFFFFFLL;
    ULONG i;

    KeQuerySystemTime(&now);
    ExAcquirePushLockExclusive(&g_Injection.Lock);

    for (i = 0; i < XDOWS_INJECTION_VERDICT_SLOTS; i++) {
        PXDOWS_INJECTION_VERDICT_SLOT slot = &g_Injection.Verdicts[i];
        if (slot->InUse &&
            slot->SourceProcessId == SourceProcessId &&
            slot->TargetProcessId == TargetProcessId &&
            slot->TargetCreateTime == TargetCreateTime) {
            chosen = slot;
            break;
        }
    }

    if (chosen != NULL) {
        chosen->GrantedMask |= GrantedDangerous;
        chosen->GrantedAt = now;
    } else {
        for (i = 0; i < XDOWS_INJECTION_VERDICT_SLOTS; i++) {
            PXDOWS_INJECTION_VERDICT_SLOT slot = &g_Injection.Verdicts[i];
            if (!slot->InUse) {
                chosen = slot;
                break;
            }
            if (slot->GrantedAt.QuadPart < oldestTime) {
                oldestTime = slot->GrantedAt.QuadPart;
                oldest = slot;
            }
        }
        if (chosen == NULL) {
            chosen = oldest;
        }
        chosen->SourceProcessId = SourceProcessId;
        chosen->TargetProcessId = TargetProcessId;
        chosen->TargetCreateTime = TargetCreateTime;
        chosen->GrantedMask = GrantedDangerous;
        chosen->GrantedAt = now;
        chosen->InUse = TRUE;
    }

    ExReleasePushLockExclusive(&g_Injection.Lock);
}

//
// Ask user-mode policy for a decision on the dangerous handle request.
// Returns TRUE on Allow, FALSE on Block/Timeout/error.
//
static
BOOLEAN
XdowsInjectionConsultUser(
    _In_ PCXDOWS_INJECTION_TARGET Target,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG SourceProcessId,
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
    event.EventType = Target->EventType;
    event.Flags = XdowsSecurityEventFlagUserModeRequired;
    event.ProcessId = HandleToULong(Target->TargetProcessId);
    event.ParentProcessId = Target->TargetThreadId;
    event.CreatingProcessId = SourceProcessId;
    event.CreatingThreadId = HandleToULong(PsGetCurrentThreadId());
    event.KernelWaitTimeoutMs = XDOWS_INJECTION_CONSULT_TIMEOUT_MS;

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
            L"User-mode consultation failed",
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
    ACCESS_MASK requestedMask;
    ACCESS_MASK threatMask;
    ACCESS_MASK effectiveDangerous;
    XDOWS_INJECTION_TARGET target;
    HANDLE callerProcessId;
    ULONG sourcePid;
    ULONGLONG eventId = 0;
    ULONGLONG correlationId = 0;

    UNREFERENCED_PARAMETER(RegistrationContext);

    desiredAccess = XdowsInjectionDesiredAccessField(Info);
    if (desiredAccess == NULL || *desiredAccess == 0) {
        return OB_PREOP_SUCCESS;
    }

    requestedMask = *desiredAccess;

    if (!XdowsInjectionResolveTarget(Info, &target)) {
        return OB_PREOP_SUCCESS;
    }

    threatMask = XdowsInjectionComputeThreatMask(&target, requestedMask);
    effectiveDangerous = requestedMask & threatMask;

    //
    // Fast exit: no target, self-targeted, or nothing dangerous. Lock-free.
    //
    callerProcessId = PsGetCurrentProcessId();
    if (target.TargetProcessId == NULL ||
        target.TargetProcessId == callerProcessId ||
        effectiveDangerous == 0) {
        return OB_PREOP_SUCCESS;
    }

    sourcePid = HandleToULong(callerProcessId);

    //
    // Cache hit: skip user-mode consultation for repeated allow requests.
    //
    if (XdowsInjectionLookupVerdict(
            sourcePid,
            HandleToULong(target.TargetProcessId),
            target.TargetCreateTime,
            effectiveDangerous)) {
        return OB_PREOP_SUCCESS;
    }

    if (XdowsInjectionConsultUser(
            &target,
            effectiveDangerous,
            sourcePid,
            &eventId,
            &correlationId)) {
        XdowsInjectionRecordVerdict(
            sourcePid,
            HandleToULong(target.TargetProcessId),
            target.TargetCreateTime,
            effectiveDangerous);
        return OB_PREOP_SUCCESS;
    }

    *desiredAccess &= ~threatMask;
    XdowsLogWrite(
        XdowsSecurityLogWarning,
        eventId,
        correlationId,
        L"Injection",
        L"Injection handle rights stripped.");
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

    if (g_Injection.CallbackHandle != NULL) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_Injection, sizeof(g_Injection));
    ExInitializePushLock(&g_Injection.Lock);

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

    status = ObRegisterCallbacks(&registration, &g_Injection.CallbackHandle);
    if (!NT_SUCCESS(status)) {
        g_Injection.CallbackHandle = NULL;
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"Injection",
            L"Object callback registration failed", status);
        return status;
    }

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Injection",
        L"Injection protection callbacks registered.");
    return STATUS_SUCCESS;
}

VOID
XdowsInjectionProtectShutdown(
    VOID
    )
{
    PVOID handle;

    handle = g_Injection.CallbackHandle;
    g_Injection.CallbackHandle = NULL;

    if (handle != NULL) {
        //
        // ObUnRegisterCallbacks drains in-flight callbacks, so clearing the
        // verdict cache afterward without the lock is safe.
        //
        ObUnRegisterCallbacks(handle);
    }

    RtlZeroMemory(g_Injection.Verdicts, sizeof(g_Injection.Verdicts));

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Injection",
        L"Injection protection callbacks unregistered.");
}
