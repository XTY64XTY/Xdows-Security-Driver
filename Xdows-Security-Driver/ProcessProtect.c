/*++

Module Name:

    processprotect.c

Abstract:

    Process-launch interception bridge.

    Registers a PsSetCreateProcessNotifyRoutineEx callback. For each new
    process, the callback assembles an XDOWS_SECURITY_EVENT describing the
    launch (image path, command line, parent/creator identities) and asks
    user-mode policy for a verdict within a bounded wait. A Block verdict
    fails the launch by setting CreateInfo->CreationStatus to
    STATUS_VIRUS_INFECTED, which surfaces to the caller as the Windows shell
    message "Operation did not complete successfully because the file contains
    a virus or potentially unwanted software."

    This module is self-contained: it depends only on the process-notify
    kernel API, the bridge queue, and the shared log facility. A failure here
    never affects other protection modules.

    The initial kernel wait is bounded to the bridge default (5s). If the
    model confirms a threat, user mode submits Pending and the bridge switches
    to a separate 25s user-decision phase that fails closed on timeout.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "BehaviorRules.h"
#include "RansomwareMonitor.h"
#include "selfprotect.h"
#include <ntstrsafe.h>

//
// STATUS_VIRUS_INFECTED surfaces to the shell as the virus/potentially
// unwanted software message. Some older WDK headers may not define it.
//
#ifndef STATUS_VIRUS_INFECTED
#define STATUS_VIRUS_INFECTED ((NTSTATUS)0xC0000222L)
#endif

//
// Synchronous user-mode verdict timeout for process-launch decisions.
// See module header for the rationale behind the shorter-than-default value.
//
#define XDOWS_PROCESS_LAUNCH_VERDICT_TIMEOUT_MS 5000u

typedef struct _XDOWS_PROCESS_CONTEXT {
    volatile BOOLEAN CallbackRegistered;
    volatile BOOLEAN ProtectionActive;
} XDOWS_PROCESS_CONTEXT, *PXDOWS_PROCESS_CONTEXT;

static XDOWS_PROCESS_CONTEXT g_ProcessGuard;

//
// Copy a UNICODE_STRING into a fixed-width wide buffer with NUL termination.
// Truncation is silent: the user-mode scanner treats a truncated path as a
// best-effort hint, not a failure.
//
// Implemented via byte-level RtlCopyMemory rather than RtlStringCchCopyNW so
// the user-mode scanner never receives a partially validated string: we copy
// the exact byte count the source reports and then force a NUL terminator.
//
static
VOID
XdowsProcessCopyUnicodeInto(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ SIZE_T DestinationChars,
    _In_opt_ PCUNICODE_STRING Source
    )
{
    SIZE_T byteCapacity;
    SIZE_T byteCount;

    if (DestinationChars == 0) {
        return;
    }

    Destination[0] = UNICODE_NULL;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    byteCapacity = (DestinationChars - 1) * sizeof(WCHAR);
    byteCount = Source->Length;
    if (byteCount > byteCapacity) {
        byteCount = byteCapacity;
    }

    if (byteCount == 0) {
        return;
    }

    RtlCopyMemory(Destination, Source->Buffer, byteCount);
    Destination[byteCount / sizeof(WCHAR)] = UNICODE_NULL;
}

//
// Assemble a launch event from the create-notify info. Returns FALSE if the
// caller should skip the event entirely (e.g. wrong IRQL or exit notification).
//
static
BOOLEAN
XdowsProcessBuildLaunchEvent(
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
    _Out_ PXDOWS_SECURITY_EVENT Event
    )
{
    RtlZeroMemory(Event, sizeof(*Event));

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }

    Event->Header.Size = sizeof(*Event);
    Event->Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
    Event->EventId = XdowsAllocateEventId();
    Event->CorrelationId = Event->EventId;
    Event->EventType = XdowsSecurityEventProcessCreate;
    Event->Flags = XdowsSecurityEventFlagUserModeRequired;
    Event->ProcessId = HandleToULong(ProcessId);
    Event->ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
    Event->CreatingProcessId = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);
    Event->CreatingThreadId = HandleToULong(CreateInfo->CreatingThreadId.UniqueThread);
    Event->KernelWaitTimeoutMs = XDOWS_PROCESS_LAUNCH_VERDICT_TIMEOUT_MS;

    if (CreateInfo->FileOpenNameAvailable) {
        Event->Flags |= XdowsSecurityEventFlagFileOpenNameAvailable;
    }

    XdowsProcessCopyUnicodeInto(
        Event->ImagePath,
        XDOWS_SECURITY_MAX_PATH_CHARS,
        CreateInfo->ImageFileName);

    XdowsProcessCopyUnicodeInto(
        Event->CommandLine,
        XDOWS_SECURITY_MAX_COMMAND_CHARS,
        CreateInfo->CommandLine);

    return TRUE;
}

//
// Apply the user-mode verdict to the create-notify info. Only an explicit
// Block verdict fails the launch with STATUS_VIRUS_INFECTED; anything else
// (Allow/Timeout/bridge-error) lets the launch proceed.
//
// IMPORTANT: Only an explicit Block verdict fails the launch.
// XdowsSecurityDecisionTimeout is excluded: STATUS_TIMEOUT (0x00000102) is
// NT_SUCCESS, so it is NOT a bridge-failure. A timeout means the user-mode
// scanner was too busy to answer -- failing the launch would prevent any
// program from starting when the scanner is congested. See spec R02.
//
static
VOID
XdowsProcessApplyVerdict(
    _In_ PXDOWS_SECURITY_EVENT Event,
    _In_ PXDOWS_SECURITY_DECISION Decision,
    _Inout_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    if (Decision->Decision != XdowsSecurityDecisionBlock) {
        return;
    }

    XdowsLogWrite(
        XdowsSecurityLogWarning,
        Event->EventId,
        Event->CorrelationId,
        L"Process",
        L"Process launch blocked by user-mode verdict.");

    CreateInfo->CreationStatus = STATUS_VIRUS_INFECTED;
}

//
// Route a confirmed command-line behavior hit through the shared user-decision
// queue. The behavior module is fail-closed for the five high-confidence
// attack rules when user mode is unavailable, preserving the protection the
// old immediate-block path provided. PolicyBypass remains fail-open only for
// infrastructure failures because it is also used by legitimate management
// tooling; an explicit user block or user-decision timeout still blocks it.
//
static
BOOLEAN
XdowsProcessApplyBehaviorPolicy(
    _Inout_ PXDOWS_SECURITY_EVENT Event,
    _Inout_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNICODE_STRING commandLine;
    XDOWS_SECURITY_BEHAVIOR_TYPE behavior;
    XDOWS_SECURITY_DECISION decision;
    NTSTATUS status;
    BOOLEAN infrastructureFailure;

    if (!XdowsBehaviorProtectIsEnabled()) {
        return FALSE;
    }

    RtlInitEmptyUnicodeString(
        &commandLine,
        Event->CommandLine,
        XDOWS_SECURITY_MAX_COMMAND_CHARS * sizeof(WCHAR));
    commandLine.Length = (USHORT)(wcslen(Event->CommandLine) * sizeof(WCHAR));

    behavior = XdowsBehaviorInspectCommandLine(&commandLine);
    if (behavior == XdowsSecurityBehaviorNone) {
        return FALSE;
    }

    Event->EventType = XdowsSecurityEventBehavior;
    Event->BehaviorType = (ULONG)behavior;
    Event->Flags |= XdowsSecurityEventFlagThreatConfirmed;

    XdowsLogWrite(
        XdowsSecurityLogWarning,
        Event->EventId,
        Event->CorrelationId,
        L"Behavior",
        XdowsBehaviorTypeName(behavior));

    status = XdowsQueueEventAndWait(Event, &decision);
    infrastructureFailure = !NT_SUCCESS(status) ||
        decision.Decision == XdowsSecurityDecisionTimeout;

    if (infrastructureFailure) {
        if (behavior != XdowsSecurityBehaviorPolicyBypass) {
            CreateInfo->CreationStatus = STATUS_VIRUS_INFECTED;
            XdowsLogWriteStatus(
                XdowsSecurityLogWarning,
                Event->EventId,
                Event->CorrelationId,
                L"Behavior",
                L"Confirmed behavior blocked because user decision was unavailable",
                status);
        } else {
            XdowsLogWriteStatus(
                XdowsSecurityLogWarning,
                Event->EventId,
                Event->CorrelationId,
                L"Behavior",
                L"Policy bypass allowed because user decision infrastructure was unavailable",
                status);
        }
        return TRUE;
    }

    if (decision.Decision == XdowsSecurityDecisionBlock) {
        CreateInfo->CreationStatus = STATUS_VIRUS_INFECTED;
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            Event->EventId,
            Event->CorrelationId,
            L"Behavior",
            L"Confirmed behavior blocked by user decision.");
    } else {
        XdowsLogWrite(
            XdowsSecurityLogInfo,
            Event->EventId,
            Event->CorrelationId,
            L"Behavior",
            L"Confirmed behavior released by user decision.");
    }

    return TRUE;
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

    //
    // CreateInfo is NULL for process-exit notifications. We do not gate on
    // exit, but we must reclaim the ransomware monitor slot so the table
    // does not fill up with dead PIDs. Without this, after 64 distinct
    // document-writing processes the monitor would stop tracking new PIDs.
    //
    if (CreateInfo == NULL) {
        XdowsRansomwareMonitorResetProcess(HandleToULong(ProcessId));
        if (XdowsIsRegisteredClientProcess(HandleToULong(ProcessId))) {
            XdowsSelfProtectClearRegistration();
            XdowsDisconnectClient();
        }
        return;
    }

    if (!XdowsProcessBuildLaunchEvent(ProcessId, CreateInfo, &event)) {
        return;
    }

    if (XdowsProcessApplyBehaviorPolicy(&event, CreateInfo)) {
        return;
    }

    status = XdowsQueueEventAndWait(&event, &decision);
    if (!NT_SUCCESS(status)) {
        //
        // Bridge failure: per spec R02, allow the launch so the system stays
        // usable. Record the condition locally so it surfaces in the driver
        // log even if the bridge could not accept the event.
        //
        XdowsLogWriteStatus(
            XdowsSecurityLogWarning,
            event.EventId,
            event.CorrelationId,
            L"Process",
            L"Bridge queue failed; launch allowed",
            status);
        return;
    }

    XdowsProcessApplyVerdict(&event, &decision, CreateInfo);
}

NTSTATUS
XdowsProcessProtectInitialize(
    VOID
    )
{
    NTSTATUS status;

    if (g_ProcessGuard.CallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(XdowsProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        g_ProcessGuard.ProtectionActive = FALSE;
        g_XdowsDriverContext.ProcessProtectionEnabled = FALSE;
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"Process",
            L"Process-notify registration failed", status);
        return status;
    }

    g_ProcessGuard.CallbackRegistered = TRUE;
    g_ProcessGuard.ProtectionActive = TRUE;
    g_XdowsDriverContext.ProcessProtectionEnabled = TRUE;
    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Process",
        L"Process-launch interception active.");
    return STATUS_SUCCESS;
}

VOID
XdowsProcessProtectShutdown(
    VOID
    )
{
    if (!g_ProcessGuard.CallbackRegistered) {
        return;
    }

    PsSetCreateProcessNotifyRoutineEx(XdowsProcessNotifyRoutine, TRUE);
    g_ProcessGuard.CallbackRegistered = FALSE;
    g_ProcessGuard.ProtectionActive = FALSE;
    g_XdowsDriverContext.ProcessProtectionEnabled = FALSE;
    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Process",
        L"Process-launch interception stopped.");
}
