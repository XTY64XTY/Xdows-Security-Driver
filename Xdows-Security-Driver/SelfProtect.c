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
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
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
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
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
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE 0x0100
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

#define XDOWS_GUARD_PROCESS_RESTRICTED_MASK                              \
    (PROCESS_TERMINATE        | PROCESS_CREATE_THREAD     |               \
     PROCESS_SET_SESSIONID    | PROCESS_VM_OPERATION      |               \
     PROCESS_VM_READ          | PROCESS_VM_WRITE           |               \
     PROCESS_DUP_HANDLE       | PROCESS_SET_QUOTA          |               \
     PROCESS_SET_INFORMATION  | PROCESS_SUSPEND_RESUME)

#define XDOWS_GUARD_THREAD_RESTRICTED_MASK                                \
    (THREAD_TERMINATE          | THREAD_SET_CONTEXT             |          \
     THREAD_SUSPEND_RESUME     | THREAD_SET_INFORMATION         |          \
     THREAD_SET_THREAD_TOKEN   | THREAD_IMPERSONATE             |          \
     THREAD_DIRECT_IMPERSONATION | THREAD_SET_LIMITED_INFORMATION)

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
    USHORT           ProtectedDirectoryLength;
    WCHAR            ProtectedDirectory[XDOWS_SECURITY_MAX_PATH_CHARS];
    PVOID            CallbackHandle;
} XDOWS_GUARD_CONTEXT, *PXDOWS_GUARD_CONTEXT;

static XDOWS_GUARD_CONTEXT g_SelfGuard;

static
NTSTATUS
XdowsSelfProtectResolveDirectory(
    _In_ ULONG ProcessId,
    _Out_writes_(DirectoryChars) PWCHAR Directory,
    _In_ USHORT DirectoryChars,
    _Out_ PUSHORT DirectoryLength
    )
{
    PEPROCESS process = NULL;
    PUNICODE_STRING imagePath = NULL;
    USHORT imageChars;
    USHORT directoryChars = 0;
    USHORT i;
    NTSTATUS status;

    *DirectoryLength = 0;
    if (Directory == NULL || DirectoryChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    Directory[0] = UNICODE_NULL;

    status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SeLocateProcessImageName(process, &imagePath);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (imagePath == NULL || imagePath->Buffer == NULL || imagePath->Length == 0) {
        status = STATUS_OBJECT_PATH_NOT_FOUND;
        goto Exit;
    }

    imageChars = imagePath->Length / sizeof(WCHAR);
    for (i = imageChars; i > 0; i--) {
        if (imagePath->Buffer[i - 1] == L'\\') {
            directoryChars = i - 1;
            break;
        }
    }

    if (directoryChars == 0 || directoryChars >= DirectoryChars) {
        status = STATUS_NAME_TOO_LONG;
        goto Exit;
    }

    RtlCopyMemory(Directory, imagePath->Buffer, directoryChars * sizeof(WCHAR));
    Directory[directoryChars] = UNICODE_NULL;
    *DirectoryLength = directoryChars * sizeof(WCHAR);
    status = STATUS_SUCCESS;

Exit:
    if (imagePath != NULL) {
        ExFreePool(imagePath);
    }
    return status;
}

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
    HANDLE callerProcessId = PsGetCurrentProcessId();
    HANDLE targetProcessId = NULL;
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
    // Fast exit: no target, nothing dangerous requested, or a handle opened by
    // the guarded process itself. Blocking self-handles breaks legitimate CLR,
    // DLL loader, and native runtime operations. Ob callbacks enforce the
    // external-process boundary; in-process integrity requires a different
    // trust boundary and cannot be isolated reliably by stripping self-handles.
    // These checks need no lock and keep the hot path lock-free.
    //
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
    WCHAR protectedDirectory[XDOWS_SECURITY_MAX_PATH_CHARS];
    USHORT protectedDirectoryLength;
    NTSTATUS status;

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

    status = XdowsSelfProtectResolveDirectory(
        ProcessId,
        protectedDirectory,
        RTL_NUMBER_OF(protectedDirectory),
        &protectedDirectoryLength);
    if (!NT_SUCCESS(status)) {
        XdowsLogWriteStatus(
            XdowsSecurityLogError,
            0,
            0,
            L"SelfProtect",
            L"Guarded process directory resolution failed",
            status);
        return status;
    }

    ExAcquirePushLockExclusive(&g_SelfGuard.Lock);
    g_SelfGuard.GuardedProcessId = ULongToHandle(ProcessId);
    g_SelfGuard.ProtectedDirectoryLength = protectedDirectoryLength;
    RtlCopyMemory(
        g_SelfGuard.ProtectedDirectory,
        protectedDirectory,
        protectedDirectoryLength + sizeof(WCHAR));
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
    g_SelfGuard.ProtectedDirectoryLength = 0;
    RtlSecureZeroMemory(
        g_SelfGuard.ProtectedDirectory,
        sizeof(g_SelfGuard.ProtectedDirectory));
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

BOOLEAN
XdowsSelfProtectShouldBlockFileMutation(
    _In_ PCUNICODE_STRING Path,
    _In_ HANDLE RequestorProcessId
    )
{
    UNICODE_STRING directory;
    USHORT directoryChars;
    BOOLEAN block = FALSE;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return FALSE;
    }

    ExAcquirePushLockShared(&g_SelfGuard.Lock);
    if (g_SelfGuard.Active &&
        !g_SelfGuard.ExitPermitted &&
        RequestorProcessId != g_SelfGuard.GuardedProcessId &&
        g_SelfGuard.ProtectedDirectoryLength > 0 &&
        Path->Length >= g_SelfGuard.ProtectedDirectoryLength) {
        directory.Buffer = g_SelfGuard.ProtectedDirectory;
        directory.Length = g_SelfGuard.ProtectedDirectoryLength;
        directory.MaximumLength = g_SelfGuard.ProtectedDirectoryLength;
        directoryChars = directory.Length / sizeof(WCHAR);

        if (RtlPrefixUnicodeString(&directory, (PUNICODE_STRING)Path, TRUE) &&
            (Path->Length == directory.Length ||
             Path->Buffer[directoryChars] == L'\\')) {
            block = TRUE;
        }
    }
    ExReleasePushLockShared(&g_SelfGuard.Lock);
    return block;
}
