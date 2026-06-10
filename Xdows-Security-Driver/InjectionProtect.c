#include "driver.h"
#include <ntstrsafe.h>

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN 0x0080
#endif

#define XDOWS_INJECTION_PROCESS_ACCESS \
    (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | \
     PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME)

#define XDOWS_INJECTION_THREAD_ACCESS \
    (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_INFORMATION | \
     THREAD_SET_THREAD_TOKEN)

static PVOID g_InjectionObRegistration;
static BOOLEAN g_ImageLoadCallbackRegistered;

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

static
BOOLEAN
XdowsInjectionAskUser(
    _In_ ULONG EventType,
    _In_ ULONG TargetProcessId,
    _In_ ULONG TargetThreadId,
    _In_ ACCESS_MASK DesiredAccess
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
    event.KernelWaitTimeoutMs = 3000;

    (VOID)RtlStringCchPrintfW(
        event.CommandLine,
        RTL_NUMBER_OF(event.CommandLine),
        L"desired-access=0x%08X",
        DesiredAccess);

    status = XdowsQueueEventAndWait(&event, &decision);
    if (!NT_SUCCESS(status)) {
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
    HANDLE targetProcessId;
    HANDLE targetThreadId = NULL;
    ULONG eventType;

    UNREFERENCED_PARAMETER(RegistrationContext);

    desiredAccess = XdowsInjectionDesiredAccess(Info);
    if (desiredAccess == NULL || *desiredAccess == 0) {
        return OB_PREOP_SUCCESS;
    }

    if (Info->ObjectType == *PsProcessType) {
        targetProcessId = PsGetProcessId((PEPROCESS)Info->Object);
        dangerousMask = XDOWS_INJECTION_PROCESS_ACCESS;
        eventType = XdowsSecurityEventProcessHandle;
    } else if (Info->ObjectType == *PsThreadType) {
        targetProcessId = PsGetThreadProcessId((PETHREAD)Info->Object);
        targetThreadId = PsGetThreadId((PETHREAD)Info->Object);
        dangerousMask = XDOWS_INJECTION_THREAD_ACCESS;
        eventType = XdowsSecurityEventThreadHandle;
    } else {
        return OB_PREOP_SUCCESS;
    }

    if (targetProcessId == NULL ||
        targetProcessId == PsGetCurrentProcessId() ||
        ((*desiredAccess) & dangerousMask) == 0) {
        return OB_PREOP_SUCCESS;
    }

    if (XdowsInjectionAskUser(
        eventType,
        HandleToULong(targetProcessId),
        HandleToULong(targetThreadId),
        (*desiredAccess) & dangerousMask)) {
        return OB_PREOP_SUCCESS;
    }

    *desiredAccess &= ~dangerousMask;
    return OB_PREOP_SUCCESS;
}

static
VOID
XdowsInjectionImageLoadNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    XDOWS_SECURITY_EVENT event;
    XDOWS_SECURITY_DECISION decision;
    size_t charsToCopy;

    UNREFERENCED_PARAMETER(ImageInfo);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FullImageName == NULL ||
        FullImageName->Buffer == NULL ||
        ProcessId == NULL ||
        ProcessId == PsGetCurrentProcessId()) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.Header.Size = sizeof(event);
    event.Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
    event.EventId = XdowsAllocateEventId();
    event.CorrelationId = event.EventId;
    event.EventType = XdowsSecurityEventImageLoad;
    event.Flags = XdowsSecurityEventFlagUserModeRequired | XdowsSecurityEventFlagFileOpenNameAvailable;
    event.ProcessId = HandleToULong(ProcessId);
    event.CreatingProcessId = HandleToULong(PsGetCurrentProcessId());
    event.KernelWaitTimeoutMs = 1000;

    charsToCopy = FullImageName->Length / sizeof(WCHAR);
    if (charsToCopy >= RTL_NUMBER_OF(event.ImagePath)) {
        charsToCopy = RTL_NUMBER_OF(event.ImagePath) - 1;
    }

    if (charsToCopy > 0) {
        RtlStringCchCopyNW(event.ImagePath, RTL_NUMBER_OF(event.ImagePath), FullImageName->Buffer, charsToCopy);
        event.ImagePath[charsToCopy] = UNICODE_NULL;
    }

    (VOID)XdowsQueueEventAndWait(&event, &decision);
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
        return status;
    }

    status = PsSetLoadImageNotifyRoutine(XdowsInjectionImageLoadNotify);
    if (NT_SUCCESS(status)) {
        g_ImageLoadCallbackRegistered = TRUE;
    }

    return STATUS_SUCCESS;
}

VOID
XdowsInjectionProtectShutdown(
    VOID
    )
{
    PVOID handle = g_InjectionObRegistration;
    g_InjectionObRegistration = NULL;

    if (g_ImageLoadCallbackRegistered) {
        PsRemoveLoadImageNotifyRoutine(XdowsInjectionImageLoadNotify);
        g_ImageLoadCallbackRegistered = FALSE;
    }

    if (handle != NULL) {
        ObUnRegisterCallbacks(handle);
    }
}
