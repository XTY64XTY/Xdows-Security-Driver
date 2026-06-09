/*++

Module Name:

    processprotect.c

Abstract:

    Process creation events bridged to user-mode scanning and decisions.

--*/

#include "driver.h"
#include <ntstrsafe.h>

static BOOLEAN g_ProcessCallbackRegistered;

static
VOID
XdowsCopyUnicodeStringToBuffer(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ size_t DestinationChars,
    _In_opt_ PCUNICODE_STRING Source
    )
{
    size_t charsToCopy;

    if (DestinationChars == 0) {
        return;
    }

    Destination[0] = UNICODE_NULL;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    charsToCopy = Source->Length / sizeof(WCHAR);
    if (charsToCopy >= DestinationChars) {
        charsToCopy = DestinationChars - 1;
    }

    if (charsToCopy == 0) {
        return;
    }

    RtlStringCchCopyNW(Destination, DestinationChars, Source->Buffer, charsToCopy);
    Destination[charsToCopy] = UNICODE_NULL;
}

static
VOID
XdowsProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    XDOWS_SECURITY_EVENT event;
    XDOWS_SECURITY_DECISION decision;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        return;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.Header.Size = sizeof(event);
    event.Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
    event.EventId = XdowsAllocateEventId();
    event.CorrelationId = event.EventId;
    event.EventType = XdowsSecurityEventProcessCreate;
    event.Flags = XdowsSecurityEventFlagUserModeRequired;
    event.ProcessId = HandleToULong(ProcessId);
    event.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
    event.CreatingProcessId = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);
    event.CreatingThreadId = HandleToULong(CreateInfo->CreatingThreadId.UniqueThread);
    event.KernelWaitTimeoutMs = XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;

    if (CreateInfo->FileOpenNameAvailable) {
        event.Flags |= XdowsSecurityEventFlagFileOpenNameAvailable;
    }

    XdowsCopyUnicodeStringToBuffer(
        event.ImagePath,
        XDOWS_SECURITY_MAX_PATH_CHARS,
        CreateInfo->ImageFileName);

    XdowsCopyUnicodeStringToBuffer(
        event.CommandLine,
        XDOWS_SECURITY_MAX_COMMAND_CHARS,
        CreateInfo->CommandLine);

    status = XdowsQueueEventAndWait(&event, &decision);
    if (!NT_SUCCESS(status)) {
        return;
    }

    if (decision.Decision == XdowsSecurityDecisionBlock ||
        decision.Decision == XdowsSecurityDecisionTimeout) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }
}

NTSTATUS
XdowsProcessProtectInitialize(
    VOID
    )
{
    NTSTATUS status;

    if (g_ProcessCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(XdowsProcessNotifyRoutine, FALSE);
    if (NT_SUCCESS(status)) {
        g_ProcessCallbackRegistered = TRUE;
        g_XdowsDriverContext.ProcessProtectionEnabled = TRUE;
    } else {
        g_XdowsDriverContext.ProcessProtectionEnabled = FALSE;
    }

    return status;
}

VOID
XdowsProcessProtectShutdown(
    VOID
    )
{
    if (!g_ProcessCallbackRegistered) {
        return;
    }

    PsSetCreateProcessNotifyRoutineEx(XdowsProcessNotifyRoutine, TRUE);
    g_ProcessCallbackRegistered = FALSE;
    g_XdowsDriverContext.ProcessProtectionEnabled = FALSE;
}
