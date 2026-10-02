/*++

Module Name:

    RegistryProtect.c

Abstract:

    This module implements kernel-mode R0 registry protection via
    CmRegisterCallbackEx. It monitors create, set value, delete value,
    delete key, rename, restore, replace and unload operations against
    configured protected registry paths and routes mutation decisions
    through the shared driver bridge with fail-closed semantics.

Environment:

    Kernel mode.

--*/

#include "driver.h"
#include "BehaviorRules.h"
#include "codeintegrity.h"
#include "registryprotect.h"
#include "selfprotect.h"
#include "InjectionProtect.h"
#include <ntstrsafe.h>

#define XDOWS_REGISTRY_ALTITUDE L"370031.12"

typedef struct _XDOWS_REGISTRY_CONTEXT {
    EX_PUSH_LOCK Lock;
    LARGE_INTEGER Cookie;
    BOOLEAN CallbackRegistered;
    BOOLEAN Enabled;
    ULONG RuleCount;
    WCHAR RulePaths[XDOWS_SECURITY_MAX_REGISTRY_RULES]
                   [XDOWS_SECURITY_MAX_REGISTRY_PATH_CHARS];
} XDOWS_REGISTRY_CONTEXT;

static XDOWS_REGISTRY_CONTEXT g_RegistryGuard;

NTKERNELAPI
NTSTATUS
SeLocateProcessImageName(
    _In_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING* ImageFileName
    );

//
// PsGetProcessImageFileName is declared in ntifs.h only; forward-declared
// here. Exported by ntoskrnl.lib. Returns the cached 15-char EPROCESS image
// name, which is not guaranteed to be null-terminated.
//
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

static
VOID
RegistryCopyUnicodeString(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ SIZE_T DestinationChars,
    _In_opt_ PCUNICODE_STRING Source
    )
{
    SIZE_T sourceChars;
    SIZE_T copyChars;

    if (Destination == NULL || DestinationChars == 0) {
        return;
    }

    Destination[0] = UNICODE_NULL;
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    sourceChars = Source->Length / sizeof(WCHAR);
    copyChars = min(sourceChars, DestinationChars - 1);
    if (copyChars > 0) {
        RtlCopyMemory(Destination, Source->Buffer, copyChars * sizeof(WCHAR));
    }
    Destination[copyChars] = UNICODE_NULL;
}

static
BOOLEAN
RegistryPrefixHasBoundary(
    _In_ PCUNICODE_STRING Prefix,
    _In_ PCUNICODE_STRING Value
    )
{
    ULONG prefixChars;

    if (!RtlPrefixUnicodeString((PUNICODE_STRING)Prefix, (PUNICODE_STRING)Value, TRUE)) {
        return FALSE;
    }
    if (Prefix->Length == Value->Length) {
        return TRUE;
    }

    prefixChars = Prefix->Length / sizeof(WCHAR);
    return Value->Buffer[prefixChars] == L'\\';
}

static
BOOLEAN
RegistryPathMatchesRules(
    _In_ PCUNICODE_STRING Path,
    _In_ BOOLEAN IncludeAncestor
    )
{
    ULONG index;
    BOOLEAN matches = FALSE;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_RegistryGuard.Lock);
    if (g_RegistryGuard.Enabled) {
        for (index = 0; index < g_RegistryGuard.RuleCount; index++) {
            UNICODE_STRING rule;

            RtlInitUnicodeString(&rule, g_RegistryGuard.RulePaths[index]);
            if (RegistryPrefixHasBoundary(&rule, Path) ||
                (IncludeAncestor && RegistryPrefixHasBoundary(Path, &rule))) {
                matches = TRUE;
                break;
            }
        }
    }
    ExReleasePushLockShared(&g_RegistryGuard.Lock);
    KeLeaveCriticalRegion();
    return matches;
}

static
NTSTATUS
RegistryGetObjectPath(
    _In_ PVOID Object,
    _Outptr_result_maybenull_ PUNICODE_STRING* Path
    )
{
    if (Object == NULL || Path == NULL || !g_RegistryGuard.CallbackRegistered) {
        return STATUS_INVALID_PARAMETER;
    }

    *Path = NULL;
    return CmCallbackGetKeyObjectIDEx(
        &g_RegistryGuard.Cookie,
        Object,
        NULL,
        Path,
        0);
}

static
NTSTATUS
RegistryBuildCreatePath(
    _In_ PREG_CREATE_KEY_INFORMATION Information,
    _Out_writes_(PathChars) PWCHAR PathBuffer,
    _In_ SIZE_T PathChars,
    _Out_ PUNICODE_STRING Path
    )
{
    PUNICODE_STRING rootPath = NULL;
    SIZE_T rootChars = 0;
    SIZE_T completeChars;
    SIZE_T cursor = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (Information == NULL || Information->CompleteName == NULL ||
        Information->CompleteName->Buffer == NULL || PathBuffer == NULL ||
        PathChars == 0 || Path == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    completeChars = Information->CompleteName->Length / sizeof(WCHAR);
    if (Information->CompleteName->Length >= sizeof(WCHAR) &&
        Information->CompleteName->Buffer[0] == L'\\') {
        if (completeChars >= PathChars) {
            return STATUS_NAME_TOO_LONG;
        }
        RtlCopyMemory(
            PathBuffer,
            Information->CompleteName->Buffer,
            Information->CompleteName->Length);
        PathBuffer[completeChars] = UNICODE_NULL;
        RtlInitUnicodeString(Path, PathBuffer);
        return STATUS_SUCCESS;
    }

    if (Information->RootObject == NULL) {
        return STATUS_OBJECT_PATH_INVALID;
    }

    status = RegistryGetObjectPath(Information->RootObject, &rootPath);
    if (!NT_SUCCESS(status) || rootPath == NULL || rootPath->Buffer == NULL) {
        return NT_SUCCESS(status) ? STATUS_OBJECT_PATH_INVALID : status;
    }

    rootChars = rootPath->Length / sizeof(WCHAR);
    if (rootChars + 1 + completeChars >= PathChars) {
        status = STATUS_NAME_TOO_LONG;
        goto Exit;
    }

    RtlCopyMemory(PathBuffer, rootPath->Buffer, rootPath->Length);
    cursor = rootChars;
    if (cursor > 0 && PathBuffer[cursor - 1] != L'\\') {
        PathBuffer[cursor++] = L'\\';
    }
    RtlCopyMemory(
        PathBuffer + cursor,
        Information->CompleteName->Buffer,
        Information->CompleteName->Length);
    cursor += completeChars;
    PathBuffer[cursor] = UNICODE_NULL;
    RtlInitUnicodeString(Path, PathBuffer);

Exit:
    CmCallbackReleaseKeyObjectIDEx(rootPath);
    return status;
}

static
VOID
RegistryCopyCurrentProcessPath(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ SIZE_T DestinationChars
    )
{
    PUNICODE_STRING imagePath = NULL;

    if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &imagePath)) &&
        imagePath != NULL) {
        RegistryCopyUnicodeString(Destination, DestinationChars, imagePath);
        ExFreePool(imagePath);
    }
}

static
NTSTATUS
RegistryDecideMutation(
    _In_ PCUNICODE_STRING Path,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ XDOWS_SECURITY_REGISTRY_OPERATION Operation,
    _In_ BOOLEAN IncludeAncestor
    )
{
    XDOWS_SECURITY_EVENT event;
    XDOWS_SECURITY_DECISION decision;
    ULONG processId = HandleToULong(PsGetCurrentProcessId());
    BOOLEAN signatureKnown;
    BOOLEAN sourceTrusted = FALSE;
    NTSTATUS status;

    if (!RegistryPathMatchesRules(Path, IncludeAncestor)) {
        return STATUS_SUCCESS;
    }
    // Registry callbacks can originate from the kernel/System process. Kernel
    // code is outside this user-mode persistence threat model, and blocking
    // PID 4 breaks ordinary Windows servicing and policy application.
    if (processId <= 4 || IsRegisteredClientProcess(processId)) {
        return STATUS_SUCCESS;
    }

    // The injection module owns the asynchronous CI cache and starts before
    // RegistryProtect. Reuse its PID+creation-time verdict so catalog-signed
    // Windows components never enter the synchronous user-mode decision path.
    signatureKnown = CodeIntegrityQueryProcessTrust(
        PsGetCurrentProcess(),
        &sourceTrusted);
    if (signatureKnown && sourceTrusted) {
        return STATUS_SUCCESS;
    }

    //
    // Initiator exclusion list (capability 0x2000), REGISTRY scope. Matched
    // with the acting image leaf name: the registry gate deliberately resolves
    // no actor path on the hot path, so a path-suffix exclusion does not apply
    // here. Registry rules already fail open when the decision infrastructure
    // is unavailable, so an exclusion only removes consultation noise for
    // known-heavy applications (games, installers, IMEs, build tools).
    //
    if (BehaviorIsInitiatorExcluded(
            XDOWS_SECURITY_EXCLUSION_SCOPE_REGISTRY,
            NULL,
            PsGetProcessImageFileName(PsGetCurrentProcess()))) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&event, sizeof(event));
    RtlZeroMemory(&decision, sizeof(decision));
    event.Header.Size = sizeof(event);
    event.Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
    event.EventId = AllocateEventId();
    event.CorrelationId = event.EventId;
    event.EventType = XdowsSecurityEventRegistryWrite;
    event.Flags = XdowsSecurityEventFlagUserModeRequired;
    event.ProcessId = processId;
    event.CreatingProcessId = processId;
    event.CreatingThreadId = HandleToULong(PsGetCurrentThreadId());
    event.KernelWaitTimeoutMs = XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;
    event.RegistryOperation = Operation;
    RegistryCopyUnicodeString(
        event.ImagePath,
        RTL_NUMBER_OF(event.ImagePath),
        Path);
    RegistryCopyUnicodeString(
        event.RegistryValueName,
        RTL_NUMBER_OF(event.RegistryValueName),
        ValueName);
    RegistryCopyCurrentProcessPath(
        event.ActorImagePath,
        RTL_NUMBER_OF(event.ActorImagePath));

    status = KeGetCurrentIrql() == PASSIVE_LEVEL
        ? QueueEventAndWait(&event, &decision)
        : STATUS_INVALID_DEVICE_STATE;
    if (!NT_SUCCESS(status) ||
        decision.Decision == XdowsSecurityDecisionTimeout) {
        LogWriteStatus(
            XdowsSecurityLogWarning,
            event.EventId,
            event.CorrelationId,
            L"RegistryProtect",
            L"Registry decision infrastructure unavailable; mutation allowed",
            status);
        return STATUS_SUCCESS;
    }

    if (decision.Decision != XdowsSecurityDecisionBlock) {
        return STATUS_SUCCESS;
    }

    LogWriteStatus(
        XdowsSecurityLogWarning,
        event.EventId,
        event.CorrelationId,
        L"RegistryProtect",
        L"Protected registry mutation denied",
        status);

    //
    // Escalation: a confirmed Block on a critical persistence key (safe-mode
    // autostart, boot-execute configuration, or a critical policy value) is a
    // hostile act that survives reboot. User mode sets the kill sentinel on
    // the decision for exactly those keys; the shared kill helper refuses to
    // touch the client, critical system processes, self-protected processes,
    // and PID <= 4. The verdict itself is never downgraded: the mutation is
    // denied regardless of whether the kill succeeds.
    //
    if (decision.ResultCode == XDOWS_DECISION_RESULT_KILL_ACTOR) {
        NTSTATUS killStatus = InjectionKillActor(processId);
        LogWriteStatus(
            XdowsSecurityLogWarning,
            event.EventId,
            event.CorrelationId,
            L"RegistryProtect",
            L"Critical registry mutation actor counter-kill",
            killStatus);
    }

    return STATUS_ACCESS_DENIED;
}

static
NTSTATUS
RegistryDecideObjectMutation(
    _In_ PVOID Object,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ XDOWS_SECURITY_REGISTRY_OPERATION Operation,
    _In_ BOOLEAN IncludeAncestor
    )
{
    PUNICODE_STRING path = NULL;
    NTSTATUS status;

    status = RegistryGetObjectPath(Object, &path);
    if (!NT_SUCCESS(status) || path == NULL) {
        return STATUS_SUCCESS;
    }

    status = RegistryDecideMutation(
        path,
        ValueName,
        Operation,
        IncludeAncestor);
    CmCallbackReleaseKeyObjectIDEx(path);
    return status;
}

static
NTSTATUS
RegistryDecideRename(
    _In_ PREG_RENAME_KEY_INFORMATION Information
    )
{
    PUNICODE_STRING sourcePath = NULL;
    WCHAR destinationBuffer[XDOWS_SECURITY_MAX_PATH_CHARS];
    UNICODE_STRING destinationPath;
    SIZE_T sourceChars;
    SIZE_T destinationParentChars;
    SIZE_T newNameChars;
    SIZE_T index;
    NTSTATUS status;

    if (Information == NULL || Information->NewName == NULL ||
        Information->NewName->Buffer == NULL) {
        return STATUS_SUCCESS;
    }

    status = RegistryGetObjectPath(Information->Object, &sourcePath);
    if (!NT_SUCCESS(status) || sourcePath == NULL || sourcePath->Buffer == NULL) {
        return STATUS_SUCCESS;
    }

    if (RegistryPathMatchesRules(sourcePath, TRUE)) {
        status = RegistryDecideMutation(
            sourcePath,
            Information->NewName,
            XdowsSecurityRegistryOperationRenameKey,
            TRUE);
        CmCallbackReleaseKeyObjectIDEx(sourcePath);
        return status;
    }

    sourceChars = sourcePath->Length / sizeof(WCHAR);
    destinationParentChars = 0;
    for (index = sourceChars; index > 0; index--) {
        if (sourcePath->Buffer[index - 1] == L'\\') {
            destinationParentChars = index;
            break;
        }
    }
    newNameChars = Information->NewName->Length / sizeof(WCHAR);
    if (destinationParentChars == 0 ||
        destinationParentChars + newNameChars >= RTL_NUMBER_OF(destinationBuffer)) {
        CmCallbackReleaseKeyObjectIDEx(sourcePath);
        return STATUS_SUCCESS;
    }

    RtlCopyMemory(
        destinationBuffer,
        sourcePath->Buffer,
        destinationParentChars * sizeof(WCHAR));
    RtlCopyMemory(
        destinationBuffer + destinationParentChars,
        Information->NewName->Buffer,
        Information->NewName->Length);
    destinationBuffer[destinationParentChars + newNameChars] = UNICODE_NULL;
    RtlInitUnicodeString(&destinationPath, destinationBuffer);
    status = RegistryDecideMutation(
        &destinationPath,
        Information->NewName,
        XdowsSecurityRegistryOperationRenameKey,
        TRUE);
    CmCallbackReleaseKeyObjectIDEx(sourcePath);
    return status;
}

static
NTSTATUS
RegistryCallback(
    _In_opt_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (!RegistryProtectIsEnabled()) {
        return STATUS_SUCCESS;
    }

    switch (notifyClass) {
    case RegNtPreCreateKeyEx:
    {
        PREG_CREATE_KEY_INFORMATION info =
            (PREG_CREATE_KEY_INFORMATION)Argument2;
        WCHAR pathBuffer[XDOWS_SECURITY_MAX_PATH_CHARS];
        UNICODE_STRING path;
        NTSTATUS status = RegistryBuildCreatePath(
            info,
            pathBuffer,
            RTL_NUMBER_OF(pathBuffer),
            &path);
        return NT_SUCCESS(status)
            ? RegistryDecideMutation(
                &path,
                NULL,
                XdowsSecurityRegistryOperationCreateKey,
                FALSE)
            : STATUS_SUCCESS;
    }
    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION info =
            (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        return info != NULL
            ? RegistryDecideObjectMutation(
                info->Object,
                info->ValueName,
                XdowsSecurityRegistryOperationSetValue,
                FALSE)
            : STATUS_SUCCESS;
    }
    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info =
            (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        return info != NULL
            ? RegistryDecideObjectMutation(
                info->Object,
                info->ValueName,
                XdowsSecurityRegistryOperationDeleteValue,
                FALSE)
            : STATUS_SUCCESS;
    }
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION info =
            (PREG_DELETE_KEY_INFORMATION)Argument2;
        return info != NULL
            ? RegistryDecideObjectMutation(
                info->Object,
                NULL,
                XdowsSecurityRegistryOperationDeleteKey,
                TRUE)
            : STATUS_SUCCESS;
    }
    case RegNtPreRenameKey:
    {
        PREG_RENAME_KEY_INFORMATION info =
            (PREG_RENAME_KEY_INFORMATION)Argument2;
        return RegistryDecideRename(info);
    }
    case RegNtPreRestoreKey:
    {
        PREG_RESTORE_KEY_INFORMATION info =
            (PREG_RESTORE_KEY_INFORMATION)Argument2;
        return info != NULL
            ? RegistryDecideObjectMutation(
                info->Object,
                NULL,
                XdowsSecurityRegistryOperationRestoreKey,
                TRUE)
            : STATUS_SUCCESS;
    }
    case RegNtPreReplaceKey:
    {
        PREG_REPLACE_KEY_INFORMATION info =
            (PREG_REPLACE_KEY_INFORMATION)Argument2;
        return info != NULL
            ? RegistryDecideObjectMutation(
                info->Object,
                NULL,
                XdowsSecurityRegistryOperationReplaceKey,
                TRUE)
            : STATUS_SUCCESS;
    }
    case RegNtPreUnLoadKey:
    {
        PREG_UNLOAD_KEY_INFORMATION info =
            (PREG_UNLOAD_KEY_INFORMATION)Argument2;
        return info != NULL
            ? RegistryDecideObjectMutation(
                info->Object,
                NULL,
                XdowsSecurityRegistryOperationUnloadKey,
                TRUE)
            : STATUS_SUCCESS;
    }
    default:
        return STATUS_SUCCESS;
    }
}

NTSTATUS
RegistryProtectInitialize(
    VOID
    )
{
    PDRIVER_OBJECT driverObject;
    UNICODE_STRING altitude;
    NTSTATUS status;

    RtlZeroMemory(&g_RegistryGuard, sizeof(g_RegistryGuard));
    ExInitializePushLock(&g_RegistryGuard.Lock);
    if (g_DriverContext.Device == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    driverObject = WdfDriverWdmGetDriverObject(
        WdfDeviceGetDriver(g_DriverContext.Device));
    RtlInitUnicodeString(&altitude, XDOWS_REGISTRY_ALTITUDE);
    status = CmRegisterCallbackEx(
        RegistryCallback,
        &altitude,
        driverObject,
        NULL,
        &g_RegistryGuard.Cookie,
        NULL);
    if (!NT_SUCCESS(status)) {
        LogWriteStatus(
            XdowsSecurityLogError,
            0,
            0,
            L"RegistryProtect",
            L"Registry callback registration failed",
            status);
        return status;
    }

    g_RegistryGuard.CallbackRegistered = TRUE;
    LogWrite(
        XdowsSecurityLogInfo,
        0,
        0,
        L"RegistryProtect",
        L"Registry callback registered.");
    return STATUS_SUCCESS;
}

VOID
RegistryProtectShutdown(
    VOID
    )
{
    if (g_RegistryGuard.CallbackRegistered) {
        (VOID)CmUnRegisterCallback(g_RegistryGuard.Cookie);
        g_RegistryGuard.CallbackRegistered = FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryGuard.Lock);
    g_RegistryGuard.Enabled = FALSE;
    g_RegistryGuard.RuleCount = 0;
    RtlSecureZeroMemory(g_RegistryGuard.RulePaths, sizeof(g_RegistryGuard.RulePaths));
    ExReleasePushLockExclusive(&g_RegistryGuard.Lock);
    KeLeaveCriticalRegion();
}

NTSTATUS
RegistryProtectConfigure(
    _In_ PXDOWS_SECURITY_REGISTRY_PROTECTION_REQUEST Request
    )
{
    UNICODE_STRING nativePrefix = RTL_CONSTANT_STRING(L"\\REGISTRY\\");
    ULONG index;

    if (Request == NULL || Request->Enabled > 1 ||
        Request->RuleCount > XDOWS_SECURITY_MAX_REGISTRY_RULES ||
        (Request->Enabled != 0 && Request->RuleCount == 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Request->RuleCount; index++) {
        size_t length = 0;
        UNICODE_STRING path;
        NTSTATUS status = RtlStringCchLengthW(
            Request->RulePaths[index],
            XDOWS_SECURITY_MAX_REGISTRY_PATH_CHARS,
            &length);
        if (!NT_SUCCESS(status) || length == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        RtlInitUnicodeString(&path, Request->RulePaths[index]);
        if (!RtlPrefixUnicodeString(&nativePrefix, &path, TRUE)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryGuard.Lock);
    RtlSecureZeroMemory(g_RegistryGuard.RulePaths, sizeof(g_RegistryGuard.RulePaths));
    for (index = 0; index < Request->RuleCount; index++) {
        (VOID)RtlStringCchCopyW(
            g_RegistryGuard.RulePaths[index],
            XDOWS_SECURITY_MAX_REGISTRY_PATH_CHARS,
            Request->RulePaths[index]);
    }
    g_RegistryGuard.RuleCount = Request->RuleCount;
    g_RegistryGuard.Enabled = Request->Enabled != 0;
    ExReleasePushLockExclusive(&g_RegistryGuard.Lock);
    KeLeaveCriticalRegion();

    LogWrite(
        XdowsSecurityLogInfo,
        0,
        0,
        L"RegistryProtect",
        Request->Enabled != 0
            ? L"R0 registry protection configured."
            : L"R0 registry protection disabled.");
    return STATUS_SUCCESS;
}

BOOLEAN
RegistryProtectIsEnabled(
    VOID
    )
{
    BOOLEAN enabled;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_RegistryGuard.Lock);
    enabled = g_RegistryGuard.Enabled;
    ExReleasePushLockShared(&g_RegistryGuard.Lock);
    KeLeaveCriticalRegion();
    return enabled;
}
