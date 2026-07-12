/*++

Module Name:

    selfprotect.c

Abstract:

    Self-protection for the Xdows Security user-mode service process.

    The module registers ObRegisterCallbacks for process and thread object
    types. When an external caller opens a handle to the guarded process (or
    to a thread owned by it) with dangerous access rights, the pre-operation
    callback strips those rights in place. Voluntary-exit semantics let the
    guarded process request temporary relief (e.g. for a self-initiated
    shutdown) without disabling the whole guard.

    This module is self-contained: it depends only on the kernel object
    callback API and the shared log facility. It holds no references to other
    protection modules and any failure here is confined to self-protection.

    Synchronization: all entry points run at PASSIVE_LEVEL (Ob pre-operation
    callbacks and IOCTL handlers alike), so an EX_PUSH_LOCK is used instead of
    a spin lock. This avoids raising IRQL to DISPATCH_LEVEL on the handle-open
    hot path, keeping scheduling latency low.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "selfprotect.h"

//
// Dangerous process access rights. Stripping these prevents a third party from
// terminating, injecting into, duplicating, or reconfiguring the guarded
// process. Values mirror the documented PROCESS_* masks; the header guards
// tolerate older WDK headers that omit some of them.
//
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_SET_SESSIONID
#define PROCESS_SET_SESSIONID 0x0004
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
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

//
// Dangerous thread access rights. Stripping these prevents remote thread
// hijacking via SetThreadContext / thread termination / token replacement.
//
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN 0x0080
#endif

#define XDOWS_GUARD_PROCESS_RESTRICTED_MASK                              \
    (PROCESS_TERMINATE        | PROCESS_CREATE_THREAD     |               \
     PROCESS_SET_SESSIONID    | PROCESS_VM_OPERATION      |               \
     PROCESS_VM_WRITE         | PROCESS_DUP_HANDLE         |               \
     PROCESS_SET_INFORMATION  | PROCESS_SUSPEND_RESUME)

#define XDOWS_GUARD_THREAD_RESTRICTED_MASK                                \
    (THREAD_TERMINATE      | THREAD_SET_CONTEXT         |                \
     THREAD_SUSPEND_RESUME | THREAD_SET_INFORMATION     |                \
     THREAD_SET_THREAD_TOKEN)

//
// Single source of truth for the guarded process state. A snapshot is read
// under the shared lock in one shot, so the callback never observes a torn
// (ProcessId updated but ExitPermitted stale) view.
//
typedef struct _XDOWS_GUARD_SNAPSHOT {
    BOOLEAN Active;
    BOOLEAN ExitPermitted;
    HANDLE  ProcessId;
} XDOWS_GUARD_SNAPSHOT, *PXDOWS_GUARD_SNAPSHOT;

typedef struct _XDOWS_GUARD_CONTEXT {
    EX_PUSH_LOCK Lock;
    volatile BOOLEAN Active;
    volatile BOOLEAN ExitPermitted;
    volatile HANDLE  GuardedProcessId;
    PVOID            CallbackHandle;
} XDOWS_GUARD_CONTEXT, *PXDOWS_GUARD_CONTEXT;

static XDOWS_GUARD_CONTEXT g_SelfGuard;

//
// Read the entire guard state in one locked critical section. Callers then
// branch on the immutable snapshot, eliminating the double-lock pattern used
// by the previous implementation.
//
static
VOID
XdowsSelfProtectSnapshotGuard(
    _Out_ PXDOWS_GUARD_SNAPSHOT Snapshot
    )
{
    Snapshot->Active = FALSE;
    Snapshot->ExitPermitted = FALSE;
    Snapshot->ProcessId = NULL;

    ExAcquirePushLockShared(&g_SelfGuard.Lock);
    Snapshot->Active = g_SelfGuard.Active;
    Snapshot->ExitPermitted = g_SelfGuard.ExitPermitted;
    Snapshot->ProcessId = g_SelfGuard.GuardedProcessId;
    ExReleasePushLockShared(&g_SelfGuard.Lock);
}

//
// Resolve the object type into a (target process id, restricted mask) pair.
// Returns FALSE for object types this module does not handle.
//
static
BOOLEAN
XdowsSelfProtectResolveTarget(
    _In_ POB_PRE_OPERATION_INFORMATION Info,
    _Out_ PHANDLE TargetProcessId,
    _Out_ ACCESS_MASK* RestrictedMask
    )
{
    if (Info->ObjectType == *PsProcessType) {
        *TargetProcessId = PsGetProcessId((PEPROCESS)Info->Object);
        *RestrictedMask = XDOWS_GUARD_PROCESS_RESTRICTED_MASK;
        return TRUE;
    }

    if (Info->ObjectType == *PsThreadType) {
        *TargetProcessId = PsGetThreadProcessId((PETHREAD)Info->Object);
        *RestrictedMask = XDOWS_GUARD_THREAD_RESTRICTED_MASK;
        return TRUE;
    }

    return FALSE;
}

static
ACCESS_MASK*
XdowsSelfProtectLocateDesiredAccess(
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
// Apply the restriction in place and report whether any bits were stripped.
//
static
BOOLEAN
XdowsSelfProtectStripAccess(
    _Inout_ ACCESS_MASK* DesiredAccess,
    _In_ ACCESS_MASK RestrictedMask
    )
{
    ACCESS_MASK before = *DesiredAccess;

    *DesiredAccess &= ~RestrictedMask;
    return (*DesiredAccess != before);
}

static
OB_PREOP_CALLBACK_STATUS
XdowsSelfProtectPreOperation(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    ACCESS_MASK* desiredAccess;
    ACCESS_MASK restrictedMask = 0;
    HANDLE targetProcessId = NULL;
    HANDLE callerProcessId;
    XDOWS_GUARD_SNAPSHOT snapshot;

    UNREFERENCED_PARAMETER(RegistrationContext);

    desiredAccess = XdowsSelfProtectLocateDesiredAccess(Info);
    if (desiredAccess == NULL || *desiredAccess == 0) {
        return OB_PREOP_SUCCESS;
    }

    if (!XdowsSelfProtectResolveTarget(Info, &targetProcessId, &restrictedMask)) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Fast exit: no target, self-targeted, or nothing dangerous requested.
    // These checks need no lock and keep the hot path lock-free.
    //
    callerProcessId = PsGetCurrentProcessId();
    if (targetProcessId == NULL ||
        targetProcessId == callerProcessId ||
        (*desiredAccess & restrictedMask) == 0) {
        return OB_PREOP_SUCCESS;
    }

    XdowsSelfProtectSnapshotGuard(&snapshot);

    if (!snapshot.Active ||
        snapshot.ExitPermitted ||
        snapshot.ProcessId != targetProcessId) {
        return OB_PREOP_SUCCESS;
    }

    if (XdowsSelfProtectStripAccess(desiredAccess, restrictedMask)) {
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            0,
            0,
            L"SelfProtect",
            L"Restricted handle rights stripped from guarded process.");
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS
XdowsSelfProtectInitialize(
    VOID
    )
{
    OB_OPERATION_REGISTRATION operations[2];
    OB_CALLBACK_REGISTRATION registration;
    UNICODE_STRING altitude;
    NTSTATUS status;

    RtlZeroMemory(&g_SelfGuard, sizeof(g_SelfGuard));
    ExInitializePushLock(&g_SelfGuard.Lock);
    g_SelfGuard.Active = FALSE;
    g_SelfGuard.ExitPermitted = FALSE;
    g_SelfGuard.GuardedProcessId = NULL;
    g_SelfGuard.CallbackHandle = NULL;

    RtlZeroMemory(operations, sizeof(operations));
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = XdowsSelfProtectPreOperation;

    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = XdowsSelfProtectPreOperation;

    RtlInitUnicodeString(&altitude, L"370031.10");
    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = RTL_NUMBER_OF(operations);
    registration.Altitude = altitude;
    registration.OperationRegistration = operations;

    status = ObRegisterCallbacks(&registration, &g_SelfGuard.CallbackHandle);
    if (!NT_SUCCESS(status)) {
        g_SelfGuard.CallbackHandle = NULL;
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"SelfProtect",
            L"Object callback registration failed", status);
        return status;
    }

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect",
        L"Self-protection callbacks registered.");
    return STATUS_SUCCESS;
}

VOID
XdowsSelfProtectShutdown(
    VOID
    )
{
    PVOID handle;

    handle = g_SelfGuard.CallbackHandle;
    g_SelfGuard.CallbackHandle = NULL;

    if (handle != NULL) {
        //
        // ObUnRegisterCallbacks drains in-flight callbacks, so it is safe to
        // clear the registration state afterward without extra locking.
        //
        ObUnRegisterCallbacks(handle);
        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect",
            L"Self-protection callbacks unregistered.");
    }

    XdowsSelfProtectClearRegistration();
}

NTSTATUS
XdowsSelfProtectRegisterProcess(
    _In_ ULONG ProcessId,
    _In_ ULONG MainThreadId,
    _In_ ULONG Flags
    )
{
    UNREFERENCED_PARAMETER(MainThreadId);
    UNREFERENCED_PARAMETER(Flags);

    //
    // Reject the idle/System (PID 4) pseudo-process and the invalid zero PID.
    // MainThreadId is optional because thread handles are protected by resolving
    // every target thread to its owning guarded process in the object callback.
    //
    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&g_SelfGuard.Lock);
    g_SelfGuard.GuardedProcessId = ULongToHandle(ProcessId);
    g_SelfGuard.ExitPermitted = FALSE;
    g_SelfGuard.Active = TRUE;
    ExReleasePushLockExclusive(&g_SelfGuard.Lock);

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect",
        L"Guarded process registered.");
    return STATUS_SUCCESS;
}

NTSTATUS
XdowsSelfProtectSetVoluntaryExit(
    _In_ ULONG ProcessId,
    _In_ BOOLEAN IsVoluntaryExit
    )
{
    NTSTATUS status = STATUS_NOT_FOUND;

    ExAcquirePushLockExclusive(&g_SelfGuard.Lock);
    if (g_SelfGuard.Active &&
        g_SelfGuard.GuardedProcessId == ULongToHandle(ProcessId)) {
        g_SelfGuard.ExitPermitted = IsVoluntaryExit;
        status = STATUS_SUCCESS;
    }
    ExReleasePushLockExclusive(&g_SelfGuard.Lock);

    if (NT_SUCCESS(status)) {
        XdowsLogWrite(
            XdowsSecurityLogInfo,
            0,
            0,
            L"SelfProtect",
            IsVoluntaryExit ? L"Voluntary exit acknowledged."
                             : L"Voluntary exit revoked.");
    }
    return status;
}

VOID
XdowsSelfProtectClearRegistration(
    VOID
    )
{
    ExAcquirePushLockExclusive(&g_SelfGuard.Lock);
    g_SelfGuard.Active = FALSE;
    g_SelfGuard.ExitPermitted = FALSE;
    g_SelfGuard.GuardedProcessId = NULL;
    ExReleasePushLockExclusive(&g_SelfGuard.Lock);

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect",
        L"Guarded process registration cleared.");
}

BOOLEAN
XdowsSelfProtectIsProcessProtected(
    _In_ HANDLE ProcessId
    )
{
    XDOWS_GUARD_SNAPSHOT snapshot;

    XdowsSelfProtectSnapshotGuard(&snapshot);
    return snapshot.Active &&
           !snapshot.ExitPermitted &&
           snapshot.ProcessId == ProcessId;
}
