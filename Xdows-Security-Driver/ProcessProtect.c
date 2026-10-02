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
// PsGetProcessImageFileName and PsLookupProcessByProcessId are declared in
// ntifs.h only; forward-declared here. Both are exported by ntoskrnl.lib.
//
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

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
ProcessCopyUnicodeInto(
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
ProcessBuildLaunchEvent(
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
    Event->EventId = AllocateEventId();
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

    ProcessCopyUnicodeInto(
        Event->ImagePath,
        XDOWS_SECURITY_MAX_PATH_CHARS,
        CreateInfo->ImageFileName);

    ProcessCopyUnicodeInto(
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
ProcessApplyVerdict(
    _In_ PXDOWS_SECURITY_EVENT Event,
    _In_ PXDOWS_SECURITY_DECISION Decision,
    _Inout_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    if (Decision->Decision != XdowsSecurityDecisionBlock) {
        return;
    }

    LogWrite(
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
ProcessApplyBehaviorPolicy(
    _Inout_ PXDOWS_SECURITY_EVENT Event,
    _Inout_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNICODE_STRING commandLine;
    UNICODE_STRING childImage;
    XDOWS_SECURITY_BEHAVIOR_TYPE behavior;
    XDOWS_SECURITY_DECISION decision;
    NTSTATUS status;
    BOOLEAN infrastructureFailure;
    BOOLEAN failOpenOnInfrastructureFailure;
    BOOLEAN customRuleMatched = FALSE;
    ULONG matchedRuleId = 0;
    ULONG matchedRuleFlags = 0;
    ULONG matchedBehaviorType = 0;

    if (!BehaviorProtectIsEnabled()) {
        return FALSE;
    }

    RtlInitEmptyUnicodeString(
        &commandLine,
        Event->CommandLine,
        XDOWS_SECURITY_MAX_COMMAND_CHARS * sizeof(WCHAR));
    commandLine.Length = (USHORT)(wcslen(Event->CommandLine) * sizeof(WCHAR));

    behavior = BehaviorInspectCommandLine(&commandLine);
    if (behavior == XdowsSecurityBehaviorNone) {
        //
        // Parent-process-chain rule: a document viewer / browser / mail
        // client parent spawning a script host child. Checked only after the
        // command-line rules miss so the common case stays on the fast path.
        //
        RtlInitEmptyUnicodeString(
            &childImage,
            Event->ImagePath,
            XDOWS_SECURITY_MAX_PATH_CHARS * sizeof(WCHAR));
        childImage.Length = (USHORT)(wcslen(Event->ImagePath) * sizeof(WCHAR));

        behavior = BehaviorInspectParentChain(
            Event->ParentProcessId,
            &childImage);
    }

    //
    // Declarative rule set (capability 0x1000). Evaluated only when no fixed
    // rule matched, so the fixed high-confidence rules keep their established
    // fail-open/fail-closed classification.
    //
    // On a launch event the acting process is the image being created, so the
    // Initiator axis is matched against the launched image: its EPROCESS leaf
    // name and, for path-suffix patterns, its full path. The Target axis does
    // not apply to a launch (no path is being operated on yet).
    //
    if (behavior == XdowsSecurityBehaviorNone) {
        UNICODE_STRING actorPath;
        PEPROCESS actorProcess = NULL;
        PCSTR actorImageName = NULL;
        BOOLEAN actorExcluded;

        RtlInitEmptyUnicodeString(
            &actorPath,
            Event->ImagePath,
            XDOWS_SECURITY_MAX_PATH_CHARS * sizeof(WCHAR));
        actorPath.Length = (USHORT)(wcslen(Event->ImagePath) * sizeof(WCHAR));

        if (Event->ProcessId != 0 &&
            NT_SUCCESS(PsLookupProcessByProcessId(
                ULongToHandle(Event->ProcessId),
                &actorProcess)) &&
            actorProcess != NULL) {
            actorImageName = PsGetProcessImageFileName(actorProcess);
        }

        actorExcluded = BehaviorIsInitiatorExcluded(
            XDOWS_SECURITY_EXCLUSION_SCOPE_PROCESS,
            &actorPath,
            actorImageName);

        if (!actorExcluded &&
            BehaviorEvaluateCustomRules(
                &actorPath,
                actorImageName,
                &commandLine,
                NULL,
                XDOWS_SECURITY_RULE_OPERATION_PROCESS_CREATE,
                Event->ProcessId,
                &matchedRuleId,
                &matchedRuleFlags,
                &matchedBehaviorType)) {
            behavior = (XDOWS_SECURITY_BEHAVIOR_TYPE)matchedBehaviorType;
            customRuleMatched = TRUE;
        }

        if (actorProcess != NULL) {
            ObDereferenceObject(actorProcess);
        }
    }

    if (behavior == XdowsSecurityBehaviorNone) {
        return FALSE;
    }

    //
    // The ownership/ACL and system-state command rules flag legitimate admin
    // commands (takeown, icacls, shutdown, net user, rd /s /q). When the
    // user-mode bridge is unavailable these must fail OPEN: blocking every
    // shutdown while the scanner is down would break the system. The
    // parent-chain rule stays fail-CLOSED (confirmed exploit chain), and so
    // do the EFI-mount and sysprep-reset rules (16/17): both are destructive
    // persistence/reset primitives with essentially no recurring legitimate
    // use, so an unavailable bridge must not silently release them.
    //
    // A declarative rule carries its own classification: it fails open on
    // infrastructure failure unless it was configured with FAIL_CLOSED.
    //
    failOpenOnInfrastructureFailure = customRuleMatched
        ? ((matchedRuleFlags & XDOWS_SECURITY_RULE_FLAG_FAIL_CLOSED) == 0)
        : (behavior == XdowsSecurityBehaviorOwnershipEscalation ||
           behavior == XdowsSecurityBehaviorSystemControlCommand ||
           behavior == XdowsSecurityBehaviorDestructiveDirectoryDelete);

    Event->EventType = XdowsSecurityEventBehavior;
    Event->BehaviorType = (ULONG)behavior;
    Event->Flags |= XdowsSecurityEventFlagThreatConfirmed;

    if (customRuleMatched) {
        WCHAR ruleMessage[128];

        if (NT_SUCCESS(RtlStringCchPrintfW(
                ruleMessage,
                RTL_NUMBER_OF(ruleMessage),
                L"Declarative rule %lu matched at launch: %s",
                matchedRuleId,
                BehaviorTypeName(behavior)))) {
            LogWrite(
                XdowsSecurityLogWarning,
                Event->EventId,
                Event->CorrelationId,
                L"Behavior",
                ruleMessage);
        }
    } else {
        LogWrite(
            XdowsSecurityLogWarning,
            Event->EventId,
            Event->CorrelationId,
            L"Behavior",
            BehaviorTypeName(behavior));
    }

    status = QueueEventAndWait(Event, &decision);
    infrastructureFailure = !NT_SUCCESS(status) ||
        decision.Decision == XdowsSecurityDecisionTimeout;

    if (infrastructureFailure) {
        if (failOpenOnInfrastructureFailure) {
            LogWriteStatus(
                XdowsSecurityLogWarning,
                Event->EventId,
                Event->CorrelationId,
                L"Behavior",
                L"Command flagged but allowed because user decision infrastructure was unavailable",
                status);
        } else {
            CreateInfo->CreationStatus = STATUS_VIRUS_INFECTED;
            LogWriteStatus(
                XdowsSecurityLogWarning,
                Event->EventId,
                Event->CorrelationId,
                L"Behavior",
                L"Confirmed behavior blocked because user decision was unavailable",
                status);
        }
        return TRUE;
    }

    if (decision.Decision == XdowsSecurityDecisionBlock) {
        CreateInfo->CreationStatus = STATUS_VIRUS_INFECTED;
        LogWrite(
            XdowsSecurityLogWarning,
            Event->EventId,
            Event->CorrelationId,
            L"Behavior",
            L"Confirmed behavior blocked by user decision.");
    } else {
        LogWrite(
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
ProcessNotifyRoutine(
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
        RansomwareMonitorResetProcess(HandleToULong(ProcessId));
        if (IsRegisteredClientProcess(HandleToULong(ProcessId))) {
            SelfProtectClearRegistration();
            DisconnectClient();
        }
        return;
    }

    if (!ProcessBuildLaunchEvent(ProcessId, CreateInfo, &event)) {
        return;
    }

    if (ProcessApplyBehaviorPolicy(&event, CreateInfo)) {
        return;
    }

    status = QueueEventAndWait(&event, &decision);
    if (!NT_SUCCESS(status)) {
        //
        // Bridge failure: per spec R02, allow the launch so the system stays
        // usable. Record the condition locally so it surfaces in the driver
        // log even if the bridge could not accept the event.
        //
        LogWriteStatus(
            XdowsSecurityLogWarning,
            event.EventId,
            event.CorrelationId,
            L"Process",
            L"Bridge queue failed; launch allowed",
            status);
        return;
    }

    ProcessApplyVerdict(&event, &decision, CreateInfo);
}

NTSTATUS
ProcessProtectInitialize(
    VOID
    )
{
    NTSTATUS status;

    if (g_ProcessGuard.CallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        g_ProcessGuard.ProtectionActive = FALSE;
        g_DriverContext.ProcessProtectionEnabled = FALSE;
        LogWriteStatus(XdowsSecurityLogError, 0, 0, L"Process",
            L"Process-notify registration failed", status);
        return status;
    }

    g_ProcessGuard.CallbackRegistered = TRUE;
    g_ProcessGuard.ProtectionActive = TRUE;
    g_DriverContext.ProcessProtectionEnabled = TRUE;
    LogWrite(XdowsSecurityLogInfo, 0, 0, L"Process",
        L"Process-launch interception active.");
    return STATUS_SUCCESS;
}

VOID
ProcessProtectShutdown(
    VOID
    )
{
    if (!g_ProcessGuard.CallbackRegistered) {
        return;
    }

    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutine, TRUE);
    g_ProcessGuard.CallbackRegistered = FALSE;
    g_ProcessGuard.ProtectionActive = FALSE;
    g_DriverContext.ProcessProtectionEnabled = FALSE;
    LogWrite(XdowsSecurityLogInfo, 0, 0, L"Process",
        L"Process-launch interception stopped.");
}
