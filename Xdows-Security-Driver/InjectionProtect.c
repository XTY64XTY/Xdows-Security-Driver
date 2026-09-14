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
#include "BehaviorRules.h"
#include "CodeIntegrity.h"
#include "selfprotect.h"
#include <ntstrsafe.h>

//
// PsGetThreadProcess is declared only in ntifs.h, which this driver does not
// include. Forward-declare it here; the function is exported by ntoskrnl.lib.
//
NTKERNELAPI PEPROCESS PsGetThreadProcess(_In_ PETHREAD Thread);

//
// PsLookupProcessByProcessId is declared in ntifs.h only; forward-declared
// here like the other NT exports this file uses. Exported by ntoskrnl.lib.
//
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

//
// SeLocateProcessImageName is likewise declared in ntifs.h only. It returns
// the cached image path (\Device\... form) of a process without touching the
// file system, so it is safe here at PASSIVE_LEVEL even with kernel APCs
// disabled.
//
NTKERNELAPI
NTSTATUS
SeLocateProcessImageName(
    _In_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING* pImageFileName
    );

//
// PsGetProcessImageFileName is declared in ntifs.h only. It returns the
// truncated (15-char) image file name cached in the EPROCESS. Used by the
// system-actor fast-allow gate below; matches the usage in CodeIntegrity.c.
//
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

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
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

//
// Critical system processes that must never be injected into, torn open for
// credential access, or terminated. These are the highest-value Windows
// targets. The registered client and CI-trusted actors may still open them;
// every other source is gated through user mode and the dangerous rights are
// stripped on a Block verdict. Matched against the EPROCESS cached image
// name (truncated to 15 chars), the same convention as the known-system-actor
// gate below.
//
#define XDOWS_INJECTION_CRITICAL_PROCESS_COUNT 6u
static const PCSTR XdowsInjectionCriticalProcesses[XDOWS_INJECTION_CRITICAL_PROCESS_COUNT] = {
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "wininit.exe",
    "services.exe",
    "smss.exe"
};
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

//
// High-confidence injection primitives. Remote thread creation and remote
// memory writes are actionable on their own. PROCESS_VM_OPERATION and
// PROCESS_DUP_HANDLE are intentionally excluded: debuggers, profilers,
// service hosts and security products request them routinely, and neither
// one alone proves code injection.
//
#define XDOWS_INJECTION_PROCESS_PRIMARY_MASK    \
    (PROCESS_CREATE_THREAD | PROCESS_VM_WRITE)

//
// PROCESS_VM_OPERATION and PROCESS_SUSPEND_RESUME are benign alone. Treat
// them as supporting indicators only when the same handle also requests
// PROCESS_VM_WRITE.
//
#define XDOWS_INJECTION_PROCESS_CONDITIONAL_MASK    \
    (PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME)
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
// XDOWS_DECISION_RESULT_KILL_ACTOR (the ResultCode sentinel that asks the
// driver to counter-kill the acting process) is defined once in Public.h so
// the injection, handle, and registry gates all decode the same value.
//
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
        Target->ConditionalMask = XDOWS_INJECTION_PROCESS_CONDITIONAL_MASK;
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
// Capture the acting process image path (\Device\... form) into the consult
// event. User-mode PID-based resolution fails for protected processes
// (MainModule is inaccessible) and for actors that exit before the decision
// pipeline runs, which previously degraded the signer-trust gate to useless
// "PID n" prompts. The kernel-side cached name has neither limitation.
//
static
VOID
XdowsInjectionCopyActorImagePath(
    _Out_writes_(PathChars) PWCHAR Path,
    _In_ ULONG PathChars
    )
{
    PUNICODE_STRING imageName = NULL;
    NTSTATUS status;

    if (Path == NULL || PathChars == 0) {
        return;
    }
    Path[0] = UNICODE_NULL;

    status = SeLocateProcessImageName(PsGetCurrentProcess(), &imageName);
    if (!NT_SUCCESS(status) || imageName == NULL ||
        imageName->Buffer == NULL ||
        imageName->Length == 0 ||
        imageName->Length >= PathChars * sizeof(WCHAR)) {
        if (imageName != NULL) {
            ExFreePool(imageName);
        }
        return;
    }

    RtlCopyMemory(Path, imageName->Buffer, imageName->Length);
    Path[imageName->Length / sizeof(WCHAR)] = UNICODE_NULL;
    ExFreePool(imageName);
}

//
// Ask user-mode policy for a decision on the dangerous handle request.
// Returns TRUE on Allow, FALSE on Block/Timeout/error.
//
// BehaviorTypeOverride: when non-None, emitted instead of the generic
// ProcessInjection/ThreadInjection type. Used for the sensitive-process and
// protected-process-terminate gates so user mode can route to the right
// prompt and request an actor kill via Decision->ResultCode.
//
static
BOOLEAN
XdowsInjectionConsultUser(
    _In_ PCXDOWS_INJECTION_TARGET Target,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG SourceProcessId,
    _In_ XDOWS_SECURITY_BEHAVIOR_TYPE BehaviorTypeOverride,
    _Out_opt_ PXDOWS_SECURITY_DECISION OutDecision,
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
    if (XdowsBehaviorProtectIsEnabled() ||
        BehaviorTypeOverride != XdowsSecurityBehaviorNone) {
        event.EventType = XdowsSecurityEventBehavior;
        event.BehaviorType = (BehaviorTypeOverride != XdowsSecurityBehaviorNone)
            ? BehaviorTypeOverride
            : (Target->EventType == XdowsSecurityEventProcessHandle
                ? XdowsSecurityBehaviorProcessInjection
                : XdowsSecurityBehaviorThreadInjection);
        event.Flags = XdowsSecurityEventFlagUserModeRequired |
            XdowsSecurityEventFlagThreatConfirmed;
    } else {
        event.EventType = Target->EventType;
        event.Flags = XdowsSecurityEventFlagUserModeRequired;
    }
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

    XdowsInjectionCopyActorImagePath(
        event.ActorImagePath,
        RTL_NUMBER_OF(event.ActorImagePath));

    if (EventId != NULL) {
        *EventId = event.EventId;
    }
    if (CorrelationId != NULL) {
        *CorrelationId = event.CorrelationId;
    }

    status = XdowsQueueEventAndWait(&event, &decision);
    if (!NT_SUCCESS(status) ||
        decision.Decision == XdowsSecurityDecisionTimeout) {
        //
        // Bridge failure (client not connected, queue full, allocation
        // failure) OR kernel wait timeout. Per spec R02, fail OPEN: allow
        // the handle request rather than stripping permissions. Failing
        // closed breaks every system service that opens cross-process
        // handles during startup (before the client connects) or during
        // scanner congestion, rendering the system unusable.
        //
        // NOTE: STATUS_TIMEOUT (0x00000102) is NT_SUCCESS, so the first
        // check alone does not catch it; the Decision==Timeout check does.
        //
        XdowsLogWriteStatus(
            XdowsSecurityLogWarning,
            event.EventId,
            event.CorrelationId,
            L"Injection",
            L"Bridge failed or timed out; handle allowed (fail-open per R02)",
            status);
        if (OutDecision != NULL) {
            RtlCopyMemory(OutDecision, &decision, sizeof(*OutDecision));
        }
        return TRUE;
    }

    //
    // Treat anything that is not an explicit Block as allow. Per R02, the
    // bridge is the source of truth; if the verdict is malformed (not
    // Allow/Block/Timeout) we fail-open rather than stripping permissions,
    // which would otherwise break legitimate handle requests.
    //
    if (OutDecision != NULL) {
        RtlCopyMemory(OutDecision, &decision, sizeof(*OutDecision));
    }
    return decision.Decision != XdowsSecurityDecisionBlock;
}

//
// Case-insensitive ASCII comparison capped at the EPROCESS image-name
// truncation length (15 chars). PsGetProcessImageFileName reports the
// truncated prefix for long names, so known names are matched by their
// truncated prefix, which is exactly what the kernel returns.
//
#define XDOWS_INJECTION_IMAGE_NAME_MAX_CHARS 15u

static
BOOLEAN
XdowsInjectionImageNameEquals(
    _In_ PCSTR ImageName,
    _In_ PCSTR KnownName
    )
{
    ULONG i;

    for (i = 0; i < XDOWS_INJECTION_IMAGE_NAME_MAX_CHARS; i++) {
        CHAR left = ImageName[i];
        CHAR right = KnownName[i];
        CHAR upperL;
        CHAR upperR;

        if (left == 0 || right == 0) {
            return left == right;
        }

        upperL = (left >= 'a' && left <= 'z')
            ? (CHAR)(left - ('a' - 'A'))
            : left;
        upperR = (right >= 'a' && right <= 'z')
            ? (CHAR)(right - ('a' - 'A'))
            : right;
        if (upperL != upperR) {
            return FALSE;
        }
    }

    return TRUE;
}

//
// Beta convergence: well-known OS/shell images are allowed without user-mode
// consultation. During startup, system processes (svchost, services, lsass,
// the shell) open dangerous cross-process handles routinely; each one used to
// block on the 500ms synchronous consultation, stalling application launch
// while the user sat through "confirmed threat" prompts that then failed
// open. The kernel-cached image name identifies these actors cheaply. The
// list is deliberately conservative and only covers OS/shell images, never
// third-party binaries. CI-trusted signatures (checked before this gate)
// remain the primary trust signal.
//
static
BOOLEAN
XdowsInjectionIsKnownSystemActor(
    VOID
    )
{
    static const PCSTR knownActors[] = {
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "dwm.exe",
        "explorer.exe",
        "SearchHost.exe",
        "RuntimeBroker.exe",
        "ApplicationFrameHost.exe",
        "ShellExperienceHost.exe",
        "StartMenuExperienceHost.exe",
        "Registry",
        "smss.exe",
        "fontdrvhost.exe",
        "conhost.exe",
        "WmiPrvSE.exe",
        "taskhostw.exe",
        "spoolsv.exe",
        "audiodg.exe",
        "System",
        "Secure System"
    };
    PCSTR imageName;
    SIZE_T i;

    imageName = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (imageName == NULL) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(knownActors); i++) {
        if (XdowsInjectionImageNameEquals(imageName, knownActors[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Log the fast-allow at most once per 5 seconds. System actors open handles
// continuously; logging every hit would flood the event ring.
//
static volatile LONGLONG s_LastSystemActorAllowLog = 0;

static
VOID
XdowsInjectionLogSystemActorAllow(
    VOID
    )
{
    ULONGLONG now;
    LONGLONG last;

    now = KeQueryInterruptTime();
    last = InterlockedCompareExchange64(&s_LastSystemActorAllowLog, 0, 0);

    if (now - (ULONGLONG)last < 50000000ULL) {
        return;
    }

    if (InterlockedCompareExchange64(
            &s_LastSystemActorAllowLog,
            (LONGLONG)now,
            last) != last) {
        return;
    }

    XdowsLogWrite(
        XdowsSecurityLogInfo,
        0,
        0,
        L"Injection",
        L"Known system actor handle request allowed (Beta fast-allow).");
}

//
// True when the target process image is one of the critical system processes
// that must never be injected into or torn open. Uses the EPROCESS cached
// name; the list mirrors XdowsInjectionCriticalProcesses above.
//
static
BOOLEAN
XdowsInjectionIsCriticalTarget(
    _In_ PEPROCESS TargetProcess
    )
{
    PCSTR imageName;
    SIZE_T i;

    if (TargetProcess == NULL) {
        return FALSE;
    }

    imageName = PsGetProcessImageFileName(TargetProcess);
    if (imageName == NULL) {
        return FALSE;
    }

    for (i = 0; i < XDOWS_INJECTION_CRITICAL_PROCESS_COUNT; i++) {
        if (XdowsInjectionImageNameEquals(
                imageName,
                XdowsInjectionCriticalProcesses[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Counter-kill: terminate the acting process that attempted a dangerous
// handle request against a critical system process or a protected process,
// after the user chose the "block and kill actor" verdict. The actor must
// not be the registered client itself, another critical system process, or
// PID <= 4 (System). Fails silently on any error; the handle strip in the
// callback is the primary protection, the kill is best-effort follow-up.
//
// Shared with the registry gate (RegistryProtect.c), which escalates a
// confirmed Block on a critical persistence key to the same counter-kill.
//
NTSTATUS
XdowsInjectionKillActor(
    _In_ ULONG ActorProcessId
    )
{
    HANDLE processHandle = NULL;
    PEPROCESS actorProcess = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    NTSTATUS status;

    if (ActorProcessId == 0 ||
        ActorProcessId <= 4 ||
        ActorProcessId == HandleToULong(g_XdowsDriverContext.ClientProcessId) ||
        XdowsSelfProtectIsProcessProtected(ULongToHandle(ActorProcessId))) {
        return STATUS_ACCESS_DENIED;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(ActorProcessId), &actorProcess);
    if (!NT_SUCCESS(status) || actorProcess == NULL) {
        return status;
    }

    if (XdowsInjectionIsCriticalTarget(actorProcess)) {
        ObDereferenceObject(actorProcess);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(&clientId, sizeof(clientId));
    clientId.UniqueProcess = ULongToHandle(ActorProcessId);
    RtlZeroMemory(&objectAttributes, sizeof(objectAttributes));
    InitializeObjectAttributes(
        &objectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenProcess(
        &processHandle,
        PROCESS_TERMINATE,
        &objectAttributes,
        &clientId);
    ObDereferenceObject(actorProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwTerminateProcess(processHandle, STATUS_VIRUS_INFECTED);
    ZwClose(processHandle);
    return status;
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
    BOOLEAN signatureKnown;
    BOOLEAN sourceTrusted = FALSE;

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
    // Fast exit: no target, self-targeted, nothing dangerous, or the request
    // originates from the connected Xdows Security client process itself.
    // The client (Xdows Security main process) needs VM/handle access to
    // perform memory scanning and hook detection; gating it would stall the
    // scanner and flood the user with consultation pop-ups. SelfProtect
    // already prevents injection into the client, so trusting its origin is
    // safe. Lock-free.
    //
    callerProcessId = PsGetCurrentProcessId();
    if (target.TargetProcessId == NULL ||
        target.TargetProcessId == callerProcessId ||
        callerProcessId == g_XdowsDriverContext.ClientProcessId ||
        effectiveDangerous == 0) {
        return OB_PREOP_SUCCESS;
    }

    sourcePid = HandleToULong(callerProcessId);

    //
    // Protected-process terminate gate. Runs BEFORE the CI/known-system-actor
    // fast-allow gates: no signed system component legitimately terminates
    // the protected Xdows Security process, and the AV-killer primitive is
    // exactly a signed or system-looking binary holding PROCESS_TERMINATE.
    // The registered client is already exempted by the fast exit above.
    // Consult user mode; on anything but an explicit Allow, strip the right
    // and optionally counter-kill the actor.
    //
    if (target.EventType == XdowsSecurityEventProcessHandle &&
        (requestedMask & PROCESS_TERMINATE) &&
        XdowsSelfProtectIsProcessProtected(target.TargetProcessId)) {
        XDOWS_SECURITY_DECISION decision;
        BOOLEAN allowed;

        RtlZeroMemory(&decision, sizeof(decision));
        allowed = XdowsInjectionConsultUser(
            &target,
            PROCESS_TERMINATE,
            sourcePid,
            XdowsSecurityBehaviorProtectedProcessTerminate,
            &decision,
            &eventId,
            &correlationId);

        //
        // Fail-CLOSED for protected-process terminate: strip unless the
        // user explicitly allowed. A kernel or user timeout must not hand a
        // PROCESS_TERMINATE right to an unknown actor.
        //
        if (!allowed || decision.Decision != XdowsSecurityDecisionAllow) {
            *desiredAccess &= ~PROCESS_TERMINATE;
            XdowsLogWrite(
                XdowsSecurityLogWarning,
                eventId,
                correlationId,
                L"SelfProtect",
                L"Protected process terminate request denied; rights stripped.");

            if (decision.ResultCode == XDOWS_DECISION_RESULT_KILL_ACTOR) {
                NTSTATUS killStatus = XdowsInjectionKillActor(sourcePid);
                XdowsLogWriteStatus(
                    XdowsSecurityLogWarning,
                    eventId,
                    correlationId,
                    L"SelfProtect",
                    L"Protected-process terminate actor counter-kill",
                    killStatus);
            }
        }
        return OB_PREOP_SUCCESS;
    }

    //
    // ci.dll validation is performed asynchronously outside this Ob callback
    // because normal kernel APCs are disabled here. A trusted cached signer
    // verdict suppresses the noisy user-mode path; unknown and unsigned
    // sources continue through the existing policy unchanged.
    //
    signatureKnown = XdowsCodeIntegrityQueryProcessTrust(
        PsGetCurrentProcess(),
        &sourceTrusted);
    if (signatureKnown && sourceTrusted) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Beta convergence: well-known OS/shell images are allowed without
    // user-mode consultation. The CI gate above covers signed actors once
    // the async cache warms; this name gate additionally covers system
    // processes whose signature is not yet resolved (cold cache right after
    // driver load, when most startup handle traffic happens). This trades a
    // small amount of detection coverage for startup responsiveness.
    //
    if (XdowsInjectionIsKnownSystemActor()) {
        XdowsInjectionLogSystemActorAllow();
        return OB_PREOP_SUCCESS;
    }

    //
    // Sensitive-process handle gate. Opening a critical system process
    // (lsass, csrss, winlogon, ...) for a dangerous right is the classic
    // credential-theft / injection primitive. Consult user mode; on anything
    // but an explicit Allow, strip the dangerous rights and optionally kill
    // the actor.
    //
    if (target.EventType == XdowsSecurityEventProcessHandle &&
        XdowsInjectionIsCriticalTarget(
            (PEPROCESS)Info->Object) &&
        effectiveDangerous != 0) {
        XDOWS_SECURITY_DECISION decision;
        BOOLEAN allowed;

        RtlZeroMemory(&decision, sizeof(decision));
        allowed = XdowsInjectionConsultUser(
            &target,
            effectiveDangerous,
            sourcePid,
            XdowsSecurityBehaviorSensitiveProcessHandle,
            &decision,
            &eventId,
            &correlationId);

        if (!allowed || decision.Decision != XdowsSecurityDecisionAllow) {
            *desiredAccess &= ~threatMask;
            XdowsLogWrite(
                XdowsSecurityLogWarning,
                eventId,
                correlationId,
                L"Injection",
                L"Sensitive system-process handle rights stripped.");

            if (decision.ResultCode == XDOWS_DECISION_RESULT_KILL_ACTOR) {
                NTSTATUS killStatus = XdowsInjectionKillActor(sourcePid);
                XdowsLogWriteStatus(
                    XdowsSecurityLogWarning,
                    eventId,
                    correlationId,
                    L"Injection",
                    L"Sensitive-process handle actor counter-kill",
                    killStatus);
            }
        }
        return OB_PREOP_SUCCESS;
    }

    //
    // Initiator exclusion list (capability 0x2000), HANDLE scope: a configured
    // heavy application (game, downloader, IME, build tool) stops reaching the
    // user-decision window for ordinary handle requests. This check sits
    // *after* the sensitive-process gate above, so an exclusion can never
    // suppress the rights-stripping applied to a critical system target -- it
    // only removes the generic consultation noise.
    //
    if (XdowsBehaviorIsInitiatorExcluded(
            XDOWS_SECURITY_EXCLUSION_SCOPE_HANDLE,
            NULL,
            PsGetProcessImageFileName(PsGetCurrentProcess()))) {
        return OB_PREOP_SUCCESS;
    }

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
            XdowsSecurityBehaviorNone,
            NULL,
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

    // CI is an optional false-positive reduction layer. Its initializer
    // intentionally returns success when private exports are unavailable so
    // process/thread injection protection remains active on unsupported OS
    // builds and falls back to the established user-mode policy.
    (VOID)XdowsCodeIntegrityInitialize();

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
        XdowsCodeIntegrityShutdown();
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
    XdowsCodeIntegrityShutdown();

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Injection",
        L"Injection protection callbacks unregistered.");
}
