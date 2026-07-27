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

#define XDOWS_STARTUP_KEY_PATH \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define XDOWS_STARTUP_VALUE_NAME L"Xdows-Security"
#define XDOWS_STARTUP_REGISTRY_ALTITUDE L"370031.11"
#define XDOWS_STARTUP_QUERY_BUFFER_BYTES \
    (FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + \
     (XDOWS_SECURITY_MAX_PATH_CHARS * sizeof(WCHAR)))

static const UNICODE_STRING g_XdowsStartupKeyPath =
    RTL_CONSTANT_STRING(XDOWS_STARTUP_KEY_PATH);
static const UNICODE_STRING g_XdowsStartupValueName =
    RTL_CONSTANT_STRING(XDOWS_STARTUP_VALUE_NAME);

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

NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID Object,
    _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength
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
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT 0x0008
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
     PROCESS_SET_INFORMATION  | PROCESS_SUSPEND_RESUME     |               \
     WRITE_DAC                | WRITE_OWNER                 | DELETE)

#define XDOWS_GUARD_THREAD_RESTRICTED_MASK                                \
    (THREAD_TERMINATE          | THREAD_GET_CONTEXT             |          \
     THREAD_SET_CONTEXT        | THREAD_SUSPEND_RESUME          |          \
     THREAD_SET_INFORMATION    | THREAD_SET_THREAD_TOKEN        |          \
     THREAD_IMPERSONATE        | THREAD_DIRECT_IMPERSONATION    |          \
     THREAD_SET_LIMITED_INFORMATION | WRITE_DAC                  |          \
     WRITE_OWNER               | DELETE)

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
    volatile BOOLEAN StartupProtectionEnabled;
    volatile BOOLEAN StartupProtectionInitializing;
    volatile HANDLE  GuardedProcessId;
    USHORT           ProtectedDirectoryLength;
    WCHAR            ProtectedDirectory[XDOWS_SECURITY_MAX_PATH_CHARS];
    USHORT           StartupImagePathLength;
    WCHAR            StartupImagePath[XDOWS_SECURITY_MAX_PATH_CHARS];
    PVOID            CallbackHandle;
    LARGE_INTEGER    RegistryCookie;
    BOOLEAN          RegistryCallbackRegistered;
} XDOWS_GUARD_CONTEXT, *PXDOWS_GUARD_CONTEXT;

static XDOWS_GUARD_CONTEXT g_SelfGuard;

static
NTSTATUS
XdowsSelfProtectCopyProcessImagePath(
    _In_ ULONG ProcessId,
    _Out_writes_(PathChars) PWCHAR Path,
    _In_ USHORT PathChars,
    _Out_ PUSHORT PathLength
    )
{
    PEPROCESS process = NULL;
    PUNICODE_STRING imagePath = NULL;
    NTSTATUS status;

    *PathLength = 0;
    if (Path == NULL || PathChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    Path[0] = UNICODE_NULL;

    status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SeLocateProcessImageName(process, &imagePath);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (imagePath == NULL || imagePath->Buffer == NULL ||
        imagePath->Length == 0 ||
        imagePath->Length >= PathChars * sizeof(WCHAR)) {
        status = STATUS_NAME_TOO_LONG;
        goto Exit;
    }

    RtlCopyMemory(Path, imagePath->Buffer, imagePath->Length);
    Path[imagePath->Length / sizeof(WCHAR)] = UNICODE_NULL;
    *PathLength = imagePath->Length;
    status = STATUS_SUCCESS;

Exit:
    if (imagePath != NULL) {
        ExFreePool(imagePath);
    }
    return status;
}

static
NTSTATUS
XdowsSelfProtectResolveStartupImagePath(
    _In_ PCUNICODE_STRING DosPath,
    _Out_writes_(PathChars) PWCHAR Path,
    _In_ USHORT PathChars,
    _Out_ PUSHORT PathLength
    )
{
    WCHAR objectPathBuffer[XDOWS_SECURITY_MAX_PATH_CHARS + 4];
    UNICODE_STRING objectPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    POBJECT_NAME_INFORMATION objectName = NULL;
    ULONG requiredLength = 0;
    USHORT prefixChars = 0;
    NTSTATUS status;

    *PathLength = 0;
    if (DosPath == NULL || DosPath->Buffer == NULL || DosPath->Length == 0 ||
        Path == NULL || PathChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (DosPath->Length >= 4 * sizeof(WCHAR) &&
        DosPath->Buffer[0] == L'\\' && DosPath->Buffer[1] == L'?' &&
        DosPath->Buffer[2] == L'?' && DosPath->Buffer[3] == L'\\') {
        prefixChars = 0;
    } else if (DosPath->Length >= 2 * sizeof(WCHAR) &&
               DosPath->Buffer[1] == L':') {
        objectPathBuffer[0] = L'\\';
        objectPathBuffer[1] = L'?';
        objectPathBuffer[2] = L'?';
        objectPathBuffer[3] = L'\\';
        prefixChars = 4;
    } else {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    if ((DosPath->Length / sizeof(WCHAR)) + prefixChars >=
        RTL_NUMBER_OF(objectPathBuffer)) {
        return STATUS_NAME_TOO_LONG;
    }

    RtlCopyMemory(
        objectPathBuffer + prefixChars,
        DosPath->Buffer,
        DosPath->Length);
    objectPath.Length = DosPath->Length + (prefixChars * sizeof(WCHAR));
    objectPath.MaximumLength = objectPath.Length + sizeof(WCHAR);
    objectPath.Buffer = objectPathBuffer;
    objectPathBuffer[objectPath.Length / sizeof(WCHAR)] = UNICODE_NULL;

    InitializeObjectAttributes(
        &objectAttributes,
        &objectPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    status = ZwCreateFile(
        &fileHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = ObReferenceObjectByHandle(
        fileHandle,
        0,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&fileObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = ObQueryNameString(fileObject, NULL, 0, &requiredLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH || requiredLength == 0) {
        goto Exit;
    }

    objectName = (POBJECT_NAME_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED,
        requiredLength,
        'psDX');
    if (objectName == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    status = ObQueryNameString(
        fileObject,
        objectName,
        requiredLength,
        &requiredLength);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (objectName->Name.Buffer == NULL || objectName->Name.Length == 0 ||
        objectName->Name.Length >= PathChars * sizeof(WCHAR)) {
        status = STATUS_NAME_TOO_LONG;
        goto Exit;
    }

    RtlCopyMemory(Path, objectName->Name.Buffer, objectName->Name.Length);
    Path[objectName->Name.Length / sizeof(WCHAR)] = UNICODE_NULL;
    *PathLength = objectName->Name.Length;
    status = STATUS_SUCCESS;

Exit:
    if (objectName != NULL) {
        ExFreePoolWithTag(objectName, 'psDX');
    }
    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }
    if (fileHandle != NULL) {
        ZwClose(fileHandle);
    }
    return status;
}

static
BOOLEAN
XdowsSelfProtectReadStartupValue(
    _Out_writes_(PathChars) PWCHAR ImagePath,
    _In_ USHORT PathChars,
    _Out_ PUSHORT ImagePathLength
    )
{
    UCHAR queryBuffer[XDOWS_STARTUP_QUERY_BUFFER_BYTES];
    PKEY_VALUE_PARTIAL_INFORMATION valueInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)queryBuffer;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE keyHandle = NULL;
    ULONG resultLength = 0;
    PWCHAR data;
    USHORT dataChars;
    USHORT pathStart;
    USHORT pathChars;
    UNICODE_STRING dosPath;
    NTSTATUS status;

    *ImagePathLength = 0;
    ImagePath[0] = UNICODE_NULL;
    InitializeObjectAttributes(
        &objectAttributes,
        (PUNICODE_STRING)&g_XdowsStartupKeyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE, &objectAttributes);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    RtlZeroMemory(queryBuffer, sizeof(queryBuffer));
    status = ZwQueryValueKey(
        keyHandle,
        (PUNICODE_STRING)&g_XdowsStartupValueName,
        KeyValuePartialInformation,
        queryBuffer,
        sizeof(queryBuffer),
        &resultLength);
    ZwClose(keyHandle);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    if ((valueInfo->Type != REG_SZ && valueInfo->Type != REG_EXPAND_SZ) ||
        valueInfo->DataLength < sizeof(WCHAR)) {
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            0,
            0,
            L"SelfProtect",
            L"Startup value is invalid; startup protection remains disabled.");
        return FALSE;
    }

    data = (PWCHAR)valueInfo->Data;
    dataChars = (USHORT)(valueInfo->DataLength / sizeof(WCHAR));
    while (dataChars > 0 && data[dataChars - 1] == UNICODE_NULL) {
        dataChars--;
    }
    if (dataChars == 0) {
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            0,
            0,
            L"SelfProtect",
            L"Startup value is empty; startup protection remains disabled.");
        return FALSE;
    }

    if (data[0] == L'\"') {
        pathStart = 1;
        for (pathChars = 0;
             pathStart + pathChars < dataChars &&
             data[pathStart + pathChars] != L'\"';
             pathChars++) {
        }
    } else {
        pathStart = 0;
        for (pathChars = 0;
             pathChars < dataChars && data[pathChars] != L' ' &&
             data[pathChars] != L'\t';
             pathChars++) {
        }
    }

    if (pathChars == 0) {
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            0,
            0,
            L"SelfProtect",
            L"Startup command has no executable path; startup protection remains disabled.");
        return FALSE;
    }

    dosPath.Buffer = data + pathStart;
    dosPath.Length = pathChars * sizeof(WCHAR);
    dosPath.MaximumLength = dosPath.Length;
    status = XdowsSelfProtectResolveStartupImagePath(
        &dosPath,
        ImagePath,
        PathChars,
        ImagePathLength);
    if (!NT_SUCCESS(status)) {
        *ImagePathLength = 0;
        ImagePath[0] = UNICODE_NULL;
        XdowsLogWriteStatus(
            XdowsSecurityLogWarning,
            0,
            0,
            L"SelfProtect",
            L"Startup path could not be resolved; startup protection remains disabled",
            status);
        return FALSE;
    }
    return TRUE;
}

static
BOOLEAN
XdowsSelfProtectIsKeyObjectProtected(
    _In_ PVOID Object,
    _In_ BOOLEAN IncludeAncestor
    )
{
    PCUNICODE_STRING objectName = NULL;
    BOOLEAN protectedKey = FALSE;
    USHORT objectChars;
    NTSTATUS status;

    if (Object == NULL || !g_SelfGuard.RegistryCallbackRegistered) {
        return FALSE;
    }

    status = CmCallbackGetKeyObjectIDEx(
        &g_SelfGuard.RegistryCookie,
        Object,
        NULL,
        &objectName,
        0);
    if (!NT_SUCCESS(status) || objectName == NULL) {
        return FALSE;
    }

    if (RtlEqualUnicodeString(
            (PUNICODE_STRING)objectName,
            (PUNICODE_STRING)&g_XdowsStartupKeyPath,
            TRUE)) {
        protectedKey = TRUE;
    } else if (IncludeAncestor &&
               RtlPrefixUnicodeString(
                   (PUNICODE_STRING)objectName,
                   (PUNICODE_STRING)&g_XdowsStartupKeyPath,
                   TRUE)) {
        objectChars = objectName->Length / sizeof(WCHAR);
        protectedKey = objectName->Length < g_XdowsStartupKeyPath.Length &&
            g_XdowsStartupKeyPath.Buffer[objectChars] == L'\\';
    }

    CmCallbackReleaseKeyObjectIDEx(objectName);
    return protectedKey;
}

static
NTSTATUS
XdowsSelfProtectRegistryCallback(
    _In_opt_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    HANDLE guardedProcessId;
    BOOLEAN startupProtectionEnabled;
    BOOLEAN block = FALSE;

    UNREFERENCED_PARAMETER(CallbackContext);

    ExAcquirePushLockShared(&g_SelfGuard.Lock);
    startupProtectionEnabled = g_SelfGuard.StartupProtectionInitializing ||
        g_SelfGuard.StartupProtectionEnabled;
    guardedProcessId = g_SelfGuard.GuardedProcessId;
    if (!startupProtectionEnabled ||
        (g_SelfGuard.Active &&
         guardedProcessId == PsGetCurrentProcessId())) {
        ExReleasePushLockShared(&g_SelfGuard.Lock);
        return STATUS_SUCCESS;
    }
    ExReleasePushLockShared(&g_SelfGuard.Lock);

    switch (notifyClass) {
    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION info =
            (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        block = info != NULL &&
            info->ValueName != NULL &&
            RtlEqualUnicodeString(
                info->ValueName,
                (PUNICODE_STRING)&g_XdowsStartupValueName,
                TRUE) &&
            XdowsSelfProtectIsKeyObjectProtected(info->Object, FALSE);
        break;
    }
    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info =
            (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        block = info != NULL &&
            info->ValueName != NULL &&
            RtlEqualUnicodeString(
                info->ValueName,
                (PUNICODE_STRING)&g_XdowsStartupValueName,
                TRUE) &&
            XdowsSelfProtectIsKeyObjectProtected(info->Object, FALSE);
        break;
    }
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION info =
            (PREG_DELETE_KEY_INFORMATION)Argument2;
        block = info != NULL &&
            XdowsSelfProtectIsKeyObjectProtected(info->Object, FALSE);
        break;
    }
    case RegNtPreRenameKey:
    {
        PREG_RENAME_KEY_INFORMATION info =
            (PREG_RENAME_KEY_INFORMATION)Argument2;
        block = info != NULL &&
            XdowsSelfProtectIsKeyObjectProtected(info->Object, TRUE);
        break;
    }
    case RegNtPreRestoreKey:
    {
        PREG_RESTORE_KEY_INFORMATION info =
            (PREG_RESTORE_KEY_INFORMATION)Argument2;
        block = info != NULL &&
            XdowsSelfProtectIsKeyObjectProtected(info->Object, TRUE);
        break;
    }
    case RegNtPreReplaceKey:
    {
        PREG_REPLACE_KEY_INFORMATION info =
            (PREG_REPLACE_KEY_INFORMATION)Argument2;
        block = info != NULL &&
            XdowsSelfProtectIsKeyObjectProtected(info->Object, TRUE);
        break;
    }
    case RegNtPreUnLoadKey:
    {
        PREG_UNLOAD_KEY_INFORMATION info =
            (PREG_UNLOAD_KEY_INFORMATION)Argument2;
        block = info != NULL &&
            XdowsSelfProtectIsKeyObjectProtected(info->Object, TRUE);
        break;
    }
    default:
        break;
    }

    if (!block) {
        return STATUS_SUCCESS;
    }

    XdowsLogWrite(
        XdowsSecurityLogWarning,
        0,
        0,
        L"SelfProtect",
        L"External startup registry mutation denied.");
    return STATUS_ACCESS_DENIED;
}

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
    UNICODE_STRING registryAltitude;
    PDRIVER_OBJECT driverObject;
    WCHAR startupImagePath[XDOWS_SECURITY_MAX_PATH_CHARS];
    USHORT startupImagePathLength = 0;
    BOOLEAN startupProtectionEnabled;
    NTSTATUS status;

    RtlZeroMemory(&g_SelfGuard, sizeof(g_SelfGuard));
    ExInitializePushLock(&g_SelfGuard.Lock);
    g_SelfGuard.Active = FALSE;
    g_SelfGuard.ExitPermitted = FALSE;
    g_SelfGuard.StartupProtectionEnabled = FALSE;
    g_SelfGuard.StartupProtectionInitializing = TRUE;
    g_SelfGuard.GuardedProcessId = NULL;
    g_SelfGuard.CallbackHandle = NULL;
    g_SelfGuard.RegistryCallbackRegistered = FALSE;

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

    if (g_XdowsDriverContext.Device == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto RegistryRegistrationFailed;
    }

    driverObject = WdfDriverWdmGetDriverObject(
        WdfDeviceGetDriver(g_XdowsDriverContext.Device));
    RtlInitUnicodeString(&registryAltitude, XDOWS_STARTUP_REGISTRY_ALTITUDE);
    status = CmRegisterCallbackEx(
        XdowsSelfProtectRegistryCallback,
        &registryAltitude,
        driverObject,
        NULL,
        &g_SelfGuard.RegistryCookie,
        NULL);
    if (!NT_SUCCESS(status)) {
        goto RegistryRegistrationFailed;
    }
    g_SelfGuard.RegistryCallbackRegistered = TRUE;

    startupProtectionEnabled = XdowsSelfProtectReadStartupValue(
        startupImagePath,
        RTL_NUMBER_OF(startupImagePath),
        &startupImagePathLength);
    ExAcquirePushLockExclusive(&g_SelfGuard.Lock);
    g_SelfGuard.StartupProtectionEnabled = startupProtectionEnabled;
    g_SelfGuard.StartupImagePathLength = startupImagePathLength;
    if (startupImagePathLength > 0) {
        RtlCopyMemory(
            g_SelfGuard.StartupImagePath,
            startupImagePath,
            startupImagePathLength + sizeof(WCHAR));
    }
    g_SelfGuard.StartupProtectionInitializing = FALSE;
    ExReleasePushLockExclusive(&g_SelfGuard.Lock);

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect",
        L"Self-protection callbacks registered.");
    return STATUS_SUCCESS;

RegistryRegistrationFailed:
    g_SelfGuard.StartupProtectionInitializing = FALSE;
    if (g_SelfGuard.CallbackHandle != NULL) {
        ObUnRegisterCallbacks(g_SelfGuard.CallbackHandle);
        g_SelfGuard.CallbackHandle = NULL;
    }
    XdowsLogWriteStatus(
        XdowsSecurityLogError,
        0,
        0,
        L"SelfProtect",
        L"Startup registry callback registration failed",
        status);
    return status;
}

VOID
XdowsSelfProtectShutdown(
    VOID
    )
{
    PVOID handle;

    if (g_SelfGuard.RegistryCallbackRegistered) {
        (VOID)CmUnRegisterCallback(g_SelfGuard.RegistryCookie);
        g_SelfGuard.RegistryCallbackRegistered = FALSE;
        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"SelfProtect",
            L"Startup registry callback unregistered.");
    }

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
XdowsSelfProtectIsClientImageAllowed(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    UNICODE_STRING expectedPath;
    BOOLEAN allowed;

    if (ImagePath == NULL || ImagePath->Buffer == NULL ||
        ImagePath->Length == 0) {
        return FALSE;
    }

    ExAcquirePushLockShared(&g_SelfGuard.Lock);
    if (!g_SelfGuard.StartupProtectionInitializing &&
        !g_SelfGuard.StartupProtectionEnabled) {
        allowed = TRUE;
    } else if (g_SelfGuard.StartupImagePathLength == 0) {
        allowed = FALSE;
    } else {
        expectedPath.Buffer = g_SelfGuard.StartupImagePath;
        expectedPath.Length = g_SelfGuard.StartupImagePathLength;
        expectedPath.MaximumLength = g_SelfGuard.StartupImagePathLength;
        allowed = RtlEqualUnicodeString(
            &expectedPath,
            (PUNICODE_STRING)ImagePath,
            TRUE);
    }
    ExReleasePushLockShared(&g_SelfGuard.Lock);
    return allowed;
}

NTSTATUS
XdowsSelfProtectSetStartupProtection(
    _In_ ULONG ProcessId,
    _In_ BOOLEAN Enabled
    )
{
    WCHAR imagePath[XDOWS_SECURITY_MAX_PATH_CHARS];
    USHORT imagePathLength = 0;
    NTSTATUS status;

    if (!XdowsSelfProtectIsProcessProtected(ULongToHandle(ProcessId))) {
        return STATUS_ACCESS_DENIED;
    }

    if (Enabled) {
        status = XdowsSelfProtectCopyProcessImagePath(
            ProcessId,
            imagePath,
            RTL_NUMBER_OF(imagePath),
            &imagePathLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    ExAcquirePushLockExclusive(&g_SelfGuard.Lock);
    g_SelfGuard.StartupProtectionEnabled = Enabled;
    g_SelfGuard.StartupImagePathLength = imagePathLength;
    RtlSecureZeroMemory(
        g_SelfGuard.StartupImagePath,
        sizeof(g_SelfGuard.StartupImagePath));
    if (imagePathLength > 0) {
        RtlCopyMemory(
            g_SelfGuard.StartupImagePath,
            imagePath,
            imagePathLength + sizeof(WCHAR));
    }
    ExReleasePushLockExclusive(&g_SelfGuard.Lock);

    XdowsLogWrite(
        XdowsSecurityLogInfo,
        0,
        0,
        L"SelfProtect",
        Enabled ? L"Startup registry protection enabled."
                : L"Startup registry protection disabled.");
    return STATUS_SUCCESS;
}

BOOLEAN
XdowsSelfProtectIsStartupProtectionEnabled(
    VOID
    )
{
    BOOLEAN enabled;

    ExAcquirePushLockShared(&g_SelfGuard.Lock);
    enabled = g_SelfGuard.StartupProtectionEnabled;
    ExReleasePushLockShared(&g_SelfGuard.Lock);
    return enabled;
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
