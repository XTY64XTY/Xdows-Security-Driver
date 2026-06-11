#include "driver.h"
#include "selfprotect.h"

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

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

#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN 0x0080
#endif

#define XDOWS_PROCESS_DANGEROUS_ACCESS \
    (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | \
     PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | \
     PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME)

#define XDOWS_THREAD_DANGEROUS_ACCESS \
    (THREAD_TERMINATE | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | \
     THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN)

typedef struct _XDOWS_SELF_PROTECT_STATE {
    KSPIN_LOCK Lock;
    HANDLE ProcessId;
    HANDLE MainThreadId;
    BOOLEAN VoluntaryExit;
    PVOID ObRegistrationHandle;
} XDOWS_SELF_PROTECT_STATE, *PXDOWS_SELF_PROTECT_STATE;

static XDOWS_SELF_PROTECT_STATE g_SelfProtectState;

static
ACCESS_MASK*
XdowsSelfProtectDesiredAccess(
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

BOOLEAN
XdowsSelfProtectIsProcessProtected(
    _In_ HANDLE ProcessId
    )
{
    KIRQL oldIrql;
    BOOLEAN isProtected;

    KeAcquireSpinLock(&g_SelfProtectState.Lock, &oldIrql);
    isProtected = g_SelfProtectState.ProcessId != NULL &&
        g_SelfProtectState.ProcessId == ProcessId &&
        !g_SelfProtectState.VoluntaryExit;
    KeReleaseSpinLock(&g_SelfProtectState.Lock, oldIrql);

    return isProtected;
}

static
BOOLEAN
XdowsSelfProtectShouldProtectTarget(
    _In_ HANDLE TargetProcessId,
    _Out_ PBOOLEAN VoluntaryExit
    )
{
    KIRQL oldIrql;
    BOOLEAN shouldProtect;

    KeAcquireSpinLock(&g_SelfProtectState.Lock, &oldIrql);
    *VoluntaryExit = g_SelfProtectState.VoluntaryExit;
    shouldProtect = g_SelfProtectState.ProcessId != NULL &&
        g_SelfProtectState.ProcessId == TargetProcessId;
    KeReleaseSpinLock(&g_SelfProtectState.Lock, oldIrql);

    return shouldProtect;
}

static
OB_PREOP_CALLBACK_STATUS
XdowsSelfProtectPreOperation(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    ACCESS_MASK* desiredAccess;
    ACCESS_MASK maskToRemove = 0;
    HANDLE targetProcessId = NULL;
    HANDLE currentProcessId = PsGetCurrentProcessId();
    BOOLEAN voluntaryExit = FALSE;
    ACCESS_MASK originalAccess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    desiredAccess = XdowsSelfProtectDesiredAccess(Info);
    if (desiredAccess == NULL || *desiredAccess == 0) {
        return OB_PREOP_SUCCESS;
    }

    if (Info->ObjectType == *PsProcessType) {
        targetProcessId = PsGetProcessId((PEPROCESS)Info->Object);
        maskToRemove = XDOWS_PROCESS_DANGEROUS_ACCESS;
    } else if (Info->ObjectType == *PsThreadType) {
        targetProcessId = PsGetThreadProcessId((PETHREAD)Info->Object);
        maskToRemove = XDOWS_THREAD_DANGEROUS_ACCESS;
    } else {
        return OB_PREOP_SUCCESS;
    }

    if (targetProcessId == NULL ||
        targetProcessId == currentProcessId ||
        !XdowsSelfProtectShouldProtectTarget(targetProcessId, &voluntaryExit) ||
        voluntaryExit) {
        return OB_PREOP_SUCCESS;
    }

    originalAccess = *desiredAccess;
    *desiredAccess &= ~maskToRemove;
    if (*desiredAccess != originalAccess) {
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            0,
            0,
            L"SelfProtect",
            L"Dangerous handle permissions stripped from protected process.");
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

    RtlZeroMemory(&g_SelfProtectState, sizeof(g_SelfProtectState));
    KeInitializeSpinLock(&g_SelfProtectState.Lock);

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

    status = ObRegisterCallbacks(&registration, &g_SelfProtectState.ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        g_SelfProtectState.ObRegistrationHandle = NULL;
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"SelfProtect", L"Self-protect callback registration failed", status);
    } else {
        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect", L"Self-protect callbacks registered.");
    }

    return status;
}

VOID
XdowsSelfProtectShutdown(
    VOID
    )
{
    PVOID handle = g_SelfProtectState.ObRegistrationHandle;
    g_SelfProtectState.ObRegistrationHandle = NULL;

    if (handle != NULL) {
        ObUnRegisterCallbacks(handle);
        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect", L"Self-protect callbacks unregistered.");
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
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(Flags);

    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_SelfProtectState.Lock, &oldIrql);
    g_SelfProtectState.ProcessId = ULongToHandle(ProcessId);
    g_SelfProtectState.MainThreadId = ULongToHandle(MainThreadId);
    g_SelfProtectState.VoluntaryExit = FALSE;
    KeReleaseSpinLock(&g_SelfProtectState.Lock, oldIrql);

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect", L"Protected process registered.");
    return STATUS_SUCCESS;
}

NTSTATUS
XdowsSelfProtectSetVoluntaryExit(
    _In_ ULONG ProcessId,
    _In_ BOOLEAN IsVoluntaryExit
    )
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;

    KeAcquireSpinLock(&g_SelfProtectState.Lock, &oldIrql);
    if (g_SelfProtectState.ProcessId == ULongToHandle(ProcessId)) {
        g_SelfProtectState.VoluntaryExit = IsVoluntaryExit;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&g_SelfProtectState.Lock, oldIrql);

    if (NT_SUCCESS(status)) {
        XdowsLogWrite(
            XdowsSecurityLogInfo,
            0,
            0,
            L"SelfProtect",
            IsVoluntaryExit ? L"Voluntary exit enabled." : L"Voluntary exit disabled.");
    }
    return status;
}

VOID
XdowsSelfProtectClearRegistration(
    VOID
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_SelfProtectState.Lock, &oldIrql);
    g_SelfProtectState.ProcessId = NULL;
    g_SelfProtectState.MainThreadId = NULL;
    g_SelfProtectState.VoluntaryExit = FALSE;
    KeReleaseSpinLock(&g_SelfProtectState.Lock, oldIrql);

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect", L"Protected process registration cleared.");
}
