/*++

Module Name:

    fileprotect.c

Abstract:

    Filesystem minifilter that gates file create, rename, and post-write
    operations with user-mode scanning verdicts.

    Three IRP operation callbacks are registered:
      * IRP_MJ_CREATE        (pre)  -- gates file open with the scannable path
      * IRP_MJ_SET_INFORMATION (pre) -- gates FileRenameInformation / Ex
      * IRP_MJ_CLEANUP       (post) -- reports a post-write scan event for
                                       files that pass a size gate; this path
                                       only logs, it cannot fail the original
                                       operation which has already completed.

    A block or timeout verdict fails the originating operation with
    STATUS_VIRUS_INFECTED, which surfaces to the caller as the Windows shell
    message "Operation did not complete successfully because the file contains
    a virus or potentially unwanted software."

    This module is self-contained: it depends only on the minifilter API,
    the bridge queue, and the shared log facility. A failure here never
    affects other protection modules.

Environment:

    Kernel-mode Driver Framework

--*/

#include <fltKernel.h>
#include "driver.h"
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
// Files larger than this are not submitted for post-cleanup write scanning:
// scanning a huge archive would saturate the user-mode scan limiter and is
// of marginal threat value compared to the cost.
//
#define XDOWS_FILE_SCAN_SIZE_CEILING_BYTES    (512ULL * 1024ULL * 1024ULL)

//
// Single source of truth for the minifilter state. The operation table and
// registration descriptor live alongside the filter handle so teardown is
// self-contained.
//
typedef struct _XDOWS_FILE_CONTEXT {
    PFLT_FILTER            FilterHandle;
    volatile LONG          UnloadPermitted;
    EX_PUSH_LOCK           BootConfigurationLock;
    BOOLEAN                BootProtectionEnabled;
    ULONG                  BootDiskNumber;
    ULONG                  BootVolumeRootCount;
    WCHAR                  BootVolumeRoots[XDOWS_SECURITY_MAX_BOOT_VOLUME_ROOTS]
                                          [XDOWS_SECURITY_MAX_BOOT_VOLUME_ROOT_CHARS];
    FLT_OPERATION_REGISTRATION Operations[5];
    FLT_CONTEXT_REGISTRATION Contexts[2];
    FLT_REGISTRATION       Registration;
} XDOWS_FILE_CONTEXT, *PXDOWS_FILE_CONTEXT;

typedef struct _XDOWS_DIRTY_HANDLE_CONTEXT {
    ULONG OriginatorPid;
    BOOLEAN BootProtected;
    WCHAR Path[XDOWS_SECURITY_MAX_PATH_CHARS];
} XDOWS_DIRTY_HANDLE_CONTEXT, *PXDOWS_DIRTY_HANDLE_CONTEXT;

typedef struct _XDOWS_BOOT_CREATE_CONTEXT {
    ULONG OriginatorPid;
    WCHAR Path[XDOWS_SECURITY_MAX_PATH_CHARS];
} XDOWS_BOOT_CREATE_CONTEXT, *PXDOWS_BOOT_CREATE_CONTEXT;

typedef struct _XDOWS_CLEANUP_SCAN_CONTEXT {
    ULONG OriginatorPid;
    WCHAR Path[XDOWS_SECURITY_MAX_PATH_CHARS];
} XDOWS_CLEANUP_SCAN_CONTEXT, *PXDOWS_CLEANUP_SCAN_CONTEXT;

static XDOWS_FILE_CONTEXT g_FileGuard;

static
VOID
XdowsFileCopyNameInto(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ SIZE_T DestinationChars,
    _In_opt_ PCUNICODE_STRING Source
    );

static
NTSTATUS
XdowsFileAcquireName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Outptr_result_maybenull_ PFLT_FILE_NAME_INFORMATION* NameInfo
    );

static
BOOLEAN
XdowsFileIsProtectedBootPath(
    _In_opt_ PCUNICODE_STRING Path
    )
{
    BOOLEAN protectedPath = FALSE;
    ULONG index;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_FileGuard.BootConfigurationLock);
    if (g_FileGuard.BootProtectionEnabled) {
        for (index = 0; index < g_FileGuard.BootVolumeRootCount; index++) {
            UNICODE_STRING root;
            UNICODE_STRING relative;
            UNICODE_STRING efiPrefix = RTL_CONSTANT_STRING(L"EFI\\Microsoft\\Boot\\");
            UNICODE_STRING efiDirectory = RTL_CONSTANT_STRING(L"EFI\\Microsoft\\Boot");
            UNICODE_STRING bcdPath = RTL_CONSTANT_STRING(L"Boot\\BCD");

            RtlInitUnicodeString(&root, g_FileGuard.BootVolumeRoots[index]);
            if (root.Length == 0 ||
                Path->Length < root.Length ||
                !RtlPrefixUnicodeString(&root, (PUNICODE_STRING)Path, TRUE)) {
                continue;
            }

            relative.Buffer = Path->Buffer + (root.Length / sizeof(WCHAR));
            relative.Length = Path->Length - root.Length;
            relative.MaximumLength = relative.Length;
            while (relative.Length >= sizeof(WCHAR) &&
                   relative.Buffer[0] == L'\\') {
                relative.Buffer++;
                relative.Length -= sizeof(WCHAR);
                relative.MaximumLength = relative.Length;
            }

            protectedPath = RtlPrefixUnicodeString(&efiPrefix, &relative, TRUE) ||
                RtlEqualUnicodeString(&efiDirectory, &relative, TRUE) ||
                RtlEqualUnicodeString(&bcdPath, &relative, TRUE);
            if (protectedPath) {
                break;
            }
        }
    }
    ExReleasePushLockShared(&g_FileGuard.BootConfigurationLock);
    KeLeaveCriticalRegion();
    return protectedPath;
}

static
NTSTATUS
XdowsFileConsultBootPolicy(
    _In_ PCUNICODE_STRING Path,
    _In_ ULONG OriginatorPid,
    _Out_ PXDOWS_SECURITY_DECISION Decision
    )
{
    XDOWS_SECURITY_EVENT event;

    RtlZeroMemory(&event, sizeof(event));
    event.Header.Size = sizeof(event);
    event.Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
    event.EventId = XdowsAllocateEventId();
    event.CorrelationId = event.EventId;
    event.EventType = XdowsSecurityEventBootWrite;
    event.Flags = XdowsSecurityEventFlagUserModeRequired |
        XdowsSecurityEventFlagThreatConfirmed |
        XdowsSecurityEventFlagFileOpenNameAvailable;
    event.ProcessId = OriginatorPid;
    event.CreatingProcessId = HandleToULong(PsGetCurrentProcessId());
    event.KernelWaitTimeoutMs = XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;
    XdowsFileCopyNameInto(
        event.ImagePath,
        XDOWS_SECURITY_MAX_PATH_CHARS,
        Path);
    return XdowsQueueEventAndWait(&event, Decision);
}

static
BOOLEAN
XdowsFileBootMutationMustBeBlocked(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING Path
    )
{
    XDOWS_SECURITY_DECISION decision;
    NTSTATUS status;

    if (!XdowsFileIsProtectedBootPath(Path)) {
        return FALSE;
    }

    RtlZeroMemory(&decision, sizeof(decision));
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        status = XdowsFileConsultBootPolicy(
            Path,
            HandleToULong(FltGetRequestorProcessIdEx(Data)),
            &decision);
    }

    if (NT_SUCCESS(status) &&
        decision.Decision == XdowsSecurityDecisionAllow) {
        return FALSE;
    }

    XdowsLogWriteStatus(
        XdowsSecurityLogWarning,
        decision.EventId,
        decision.EventId,
        L"BootProtect",
        L"EFI or BCD mutation blocked",
        status);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return TRUE;
}

static
FLT_PREOP_CALLBACK_STATUS
XdowsFilePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    )
{
    PXDOWS_DIRTY_HANDLE_CONTEXT context = NULL;
    PXDOWS_DIRTY_HANDLE_CONTEXT existingContext = NULL;
    PFLT_FILE_NAME_INFORMATION bootName = NULL;
    NTSTATUS status;

    *CompletionContext = NULL;

    if (Data->Iopb->Parameters.Write.Length == 0 ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&existingContext);
    if (NT_SUCCESS(status) && existingContext != NULL) {
        if (existingContext->BootProtected) {
            UNICODE_STRING protectedPath;
            RtlInitUnicodeString(&protectedPath, existingContext->Path);
            if (XdowsFileBootMutationMustBeBlocked(Data, &protectedPath)) {
                FltReleaseContext(existingContext);
                return FLT_PREOP_COMPLETE;
            }
        }
        FltReleaseContext(existingContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() <= APC_LEVEL &&
        NT_SUCCESS(XdowsFileAcquireName(Data, &bootName))) {
        if (XdowsFileBootMutationMustBeBlocked(Data, &bootName->Name)) {
            FltReleaseFileNameInformation(bootName);
            return FLT_PREOP_COMPLETE;
        }
        FltReleaseFileNameInformation(bootName);
    }

    status = FltAllocateContext(
        FltObjects->Filter,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(*context),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&context);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    context->OriginatorPid = HandleToULong(FltGetRequestorProcessIdEx(Data));
    context->BootProtected = FALSE;
    context->Path[0] = UNICODE_NULL;
    status = FltSetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        context,
        NULL);
    FltReleaseContext(context);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// Extension allowlist. Each entry is a fully-formed UNICODE_STRING whose
// Length/MaximumLength/Buffer are baked in at compile time via
// RTL_CONSTANT_STRING, so the table needs no runtime initialization and is
// safe to read concurrently from multiple minifilter callbacks.
//
static
BOOLEAN
XdowsFileIsScannablePath(
    _In_opt_ PCUNICODE_STRING Path
    )
{
    static const UNICODE_STRING Entries[] = {
        RTL_CONSTANT_STRING(L".exe"  ), RTL_CONSTANT_STRING(L".dll"  ),
        RTL_CONSTANT_STRING(L".sys"  ), RTL_CONSTANT_STRING(L".scr"  ),
        RTL_CONSTANT_STRING(L".bat"  ), RTL_CONSTANT_STRING(L".cmd"  ),
        RTL_CONSTANT_STRING(L".ps1"  ), RTL_CONSTANT_STRING(L".vbs"  ),
        RTL_CONSTANT_STRING(L".js"   ), RTL_CONSTANT_STRING(L".jse"  ),
        RTL_CONSTANT_STRING(L".wsf"  ), RTL_CONSTANT_STRING(L".msi"  ),
        RTL_CONSTANT_STRING(L".msp"  ), RTL_CONSTANT_STRING(L".cab"  ),
        RTL_CONSTANT_STRING(L".zip"  ), RTL_CONSTANT_STRING(L".rar"  ),
        RTL_CONSTANT_STRING(L".7z"   ), RTL_CONSTANT_STRING(L".iso"  ),
        RTL_CONSTANT_STRING(L".doc"  ), RTL_CONSTANT_STRING(L".docx" ),
        RTL_CONSTANT_STRING(L".xls"  ), RTL_CONSTANT_STRING(L".xlsx" ),
        RTL_CONSTANT_STRING(L".ppt"  ), RTL_CONSTANT_STRING(L".pptx" ),
        RTL_CONSTANT_STRING(L".pdf"  )
    };
    ULONG i;

    if (Path == NULL || Path->Buffer == NULL ||
        Path->Length < sizeof(WCHAR) * 5) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(Entries); i++) {
        if (Path->Length >= Entries[i].Length &&
            RtlSuffixUnicodeString((PUNICODE_STRING)&Entries[i],
                                   (PUNICODE_STRING)Path, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Fetch and parse the normalized name for the current operation. The caller
// must release *NameInfo with FltReleaseFileNameInformation on success.
//
static
NTSTATUS
XdowsFileAcquireName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Outptr_result_maybenull_ PFLT_FILE_NAME_INFORMATION* NameInfo
    )
{
    NTSTATUS status;

    *NameInfo = NULL;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        NameInfo);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(*NameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(*NameInfo);
        *NameInfo = NULL;
    }
    return status;
}

static
BOOLEAN
XdowsFileDenyProtectedMutation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING Path
    )
{
    HANDLE requestorProcessId;

    requestorProcessId = FltGetRequestorProcessIdEx(Data);
    if (!XdowsSelfProtectShouldBlockFileMutation(Path, requestorProcessId)) {
        return FALSE;
    }

    XdowsLogWrite(
        XdowsSecurityLogWarning,
        0,
        0,
        L"SelfProtect",
        L"External mutation of the guarded application directory was blocked.");
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return TRUE;
}

//
// Copy a UNICODE_STRING into a fixed wide buffer with NUL termination.
// Implemented byte-wise so the user-mode scanner always receives a fully
// owned, NUL-terminated copy of exactly the bytes the source reported.
//
static
VOID
XdowsFileCopyNameInto(
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
// Submit a file event to user-mode policy and return the verdict.
//
static
NTSTATUS
XdowsFileConsultPolicy(
    _In_ ULONG EventType,
    _In_ PCUNICODE_STRING Path,
    _In_ ULONG OriginatorPid,
    _Out_ PXDOWS_SECURITY_DECISION Decision
    )
{
    XDOWS_SECURITY_EVENT event;

    RtlZeroMemory(&event, sizeof(event));
    event.Header.Size = sizeof(event);
    event.Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;
    event.EventId = XdowsAllocateEventId();
    event.CorrelationId = event.EventId;
    event.EventType = EventType;
    event.Flags = XdowsSecurityEventFlagUserModeRequired |
                 XdowsSecurityEventFlagFileOpenNameAvailable;
    event.ProcessId = OriginatorPid;
    event.CreatingProcessId = HandleToULong(PsGetCurrentProcessId());
    event.KernelWaitTimeoutMs = (EventType == XdowsSecurityEventFileCreate)
        ? XDOWS_FILE_CREATE_KERNEL_WAIT_TIMEOUT_MS
        : XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;

    XdowsFileCopyNameInto(event.ImagePath, XDOWS_SECURITY_MAX_PATH_CHARS, Path);

    return XdowsQueueEventAndWait(&event, Decision);
}

//
// TRUE if the user-mode verdict should fail the originating operation.
//
// IMPORTANT: Only an explicit Block verdict fails the operation.
// STATUS_TIMEOUT (0x00000102) is NT_SUCCESS, so the QueueStatus short-circuit
// below does NOT fire for kernel wait timeouts. Instead we exclude
// XdowsSecurityDecisionTimeout explicitly: a timeout means the user-mode
// scanner was too busy to answer, which is NOT a confirmed virus verdict.
// Failing every file open on scanner congestion would make the entire system
// unusable (no .exe/.dll can be loaded). The spec's R02 "bridge failed -> Allow"
// intent covers this case.
//
static
BOOLEAN
XdowsFileVerdictBlocks(
    _In_ NTSTATUS QueueStatus,
    _In_ PXDOWS_SECURITY_DECISION Decision
    )
{
    if (!NT_SUCCESS(QueueStatus)) {
        return FALSE;
    }
    return Decision->Decision == XdowsSecurityDecisionBlock;
}

//
// Complete the operation as a virus hit. The caller returns FLT_PREOP_COMPLETE.
//
static
VOID
XdowsFileFailWithVirus(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PXDOWS_SECURITY_DECISION Decision
    )
{
    XdowsLogWrite(
        XdowsSecurityLogWarning,
        Decision->EventId,
        Decision->EventId,
        L"File",
        Decision->Decision == XdowsSecurityDecisionTimeout
            ? L"Operation blocked after verdict timeout."
            : L"Operation blocked by user-mode verdict.");

    Data->IoStatus.Status = STATUS_VIRUS_INFECTED;
    Data->IoStatus.Information = 0;
}

//
// TRUE if SetInformation can expose existing content under a new name.
//
static
BOOLEAN
XdowsFileIsNameChangeClass(
    _In_ FILE_INFORMATION_CLASS InfoClass
    )
{
    return InfoClass == FileRenameInformation ||
           InfoClass == FileRenameInformationEx ||
           InfoClass == FileLinkInformation ||
           InfoClass == FileLinkInformationEx;
}

static
BOOLEAN
XdowsFileIsDeleteDispositionClass(
    _In_ FILE_INFORMATION_CLASS InfoClass
    )
{
    return InfoClass == FileDispositionInformation ||
           InfoClass == FileDispositionInformationEx;
}

//
// TRUE if the PreCreate operation requests write access to the file. This
// distinguishes opens that will modify the file from read-only opens, which
// the ransomware rate monitor must not count -- a file manager thumbnailing
// a folder can open dozens of document files read-only in a burst, and
// counting those as writes would cause false positives.
//
// Both the create disposition (FILE_OVERWRITE / FILE_SUPERSEDE / etc.) and
// the DesiredAccess mask (FILE_WRITE_DATA / FILE_APPEND_DATA) are checked:
// some callers pass FILE_OPEN_IF with write access, others pass FILE_OVERWRITE
// with no explicit access bits.
//
static
BOOLEAN
XdowsFileIsWriteOpen(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    ULONG disposition;
    ACCESS_MASK desiredAccess;

    disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

    if (disposition == FILE_OVERWRITE ||
        disposition == FILE_OVERWRITE_IF ||
        disposition == FILE_SUPERSEDE ||
        disposition == FILE_CREATE) {
        return TRUE;
    }

    if (FlagOn(desiredAccess, FILE_WRITE_DATA) ||
        FlagOn(desiredAccess, FILE_APPEND_DATA) ||
        FlagOn(desiredAccess, DELETE) ||
        FlagOn(desiredAccess, FILE_WRITE_EA) ||
        FlagOn(desiredAccess, FILE_WRITE_ATTRIBUTES) ||
        FlagOn(desiredAccess, WRITE_DAC) ||
        FlagOn(desiredAccess, WRITE_OWNER)) {
        return TRUE;
    }

    return FALSE;
}

//
// Post-cleanup size gate: only report writes on regular files whose size is
// within the scan ceiling.
//
static
BOOLEAN
XdowsFilePassesSizeGate(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    FILE_STANDARD_INFORMATION info;
    NTSTATUS status;

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &info,
        sizeof(info),
        FileStandardInformation,
        NULL);
    if (!NT_SUCCESS(status) ||
        info.Directory ||
        info.EndOfFile.QuadPart <= 0 ||
        (ULONGLONG)info.EndOfFile.QuadPart > XDOWS_FILE_SCAN_SIZE_CEILING_BYTES) {
        return FALSE;
    }
    return TRUE;
}

static
FLT_PREOP_CALLBACK_STATUS
XdowsFilePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    )
{
    PXDOWS_BOOT_CREATE_CONTEXT bootContext = NULL;
    PFLT_FILE_NAME_INFORMATION name = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (KeGetCurrentIrql() > APC_LEVEL ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileAcquireName(Data, &name);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (XdowsFileIsWriteOpen(Data) &&
        XdowsFileDenyProtectedMutation(Data, &name->Name)) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_COMPLETE;
    }

    if (XdowsFileIsWriteOpen(Data) &&
        XdowsFileIsProtectedBootPath(&name->Name)) {
        if (XdowsFileBootMutationMustBeBlocked(Data, &name->Name)) {
            FltReleaseFileNameInformation(name);
            return FLT_PREOP_COMPLETE;
        }

        bootContext = (PXDOWS_BOOT_CREATE_CONTEXT)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(*bootContext),
            'oBsX');
        if (bootContext == NULL) {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            FltReleaseFileNameInformation(name);
            return FLT_PREOP_COMPLETE;
        }
        RtlZeroMemory(bootContext, sizeof(*bootContext));
        bootContext->OriginatorPid =
            HandleToULong(FltGetRequestorProcessIdEx(Data));
        XdowsFileCopyNameInto(
            bootContext->Path,
            RTL_NUMBER_OF(bootContext->Path),
            &name->Name);
        *CompletionContext = bootContext;
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    if (!XdowsFileIsScannablePath(&name->Name)) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Ransomware rate detection (sliding window).
    //
    // For write-opens: record the document-file write. RecordWrite returns
    // TRUE when the per-process threshold is crossed within the window, or
    // when the process is already flagged. This catches the encryption
    // burst at open time -- before the file is actually encrypted -- so
    // only the first handful of files in the burst are affected.
    //
    // For read-opens: do not increment the counter (a file manager
    // thumbnailing a folder can open dozens of documents read-only), but
    // still check IsFlagged so an already-flagged ransomware process is
    // blocked from reading further files to encrypt.
    //
    {
        ULONG originatorPid = HandleToULong(FltGetRequestorProcessIdEx(Data));
        BOOLEAN ransomBlock = FALSE;

        if (XdowsFileIsWriteOpen(Data)) {
            ransomBlock = XdowsRansomwareMonitorRecordWrite(
                originatorPid, &name->Name);
        }
        if (!ransomBlock) {
            ransomBlock = XdowsRansomwareMonitorIsFlagged(originatorPid);
        }

        if (ransomBlock) {
            ULONGLONG ransomEventId = XdowsAllocateEventId();
            XdowsLogWrite(
                XdowsSecurityLogWarning,
                ransomEventId,
                ransomEventId,
                L"File",
                L"Ransomware rate threshold exceeded; operation blocked.");
            //
            // Complete the IRP directly with STATUS_VIRUS_INFECTED rather
            // than calling XdowsFileFailWithVirus, which would log a
            // misleading "blocked by user-mode verdict" message -- this
            // block originates from the in-kernel monitor.
            //
            Data->IoStatus.Status = STATUS_VIRUS_INFECTED;
            Data->IoStatus.Information = 0;
            FltReleaseFileNameInformation(name);
            return FLT_PREOP_COMPLETE;
        }
    }

    // Opens are never sent to user mode. IRP_MJ_WRITE marks the stream-handle
    // dirty only when a real write reaches the minifilter.
    FltReleaseFileNameInformation(name);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
FLT_POSTOP_CALLBACK_STATUS
XdowsFilePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PXDOWS_BOOT_CREATE_CONTEXT bootContext =
        (PXDOWS_BOOT_CREATE_CONTEXT)CompletionContext;
    PXDOWS_DIRTY_HANDLE_CONTEXT handleContext = NULL;
    NTSTATUS status;

    if (bootContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(Data->IoStatus.Status) ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        ExFreePoolWithTag(bootContext, 'oBsX');
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltAllocateContext(
        FltObjects->Filter,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(*handleContext),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&handleContext);
    if (!NT_SUCCESS(status) || handleContext == NULL) {
        goto FailClosed;
    }

    RtlZeroMemory(handleContext, sizeof(*handleContext));
    handleContext->OriginatorPid = bootContext->OriginatorPid;
    handleContext->BootProtected = TRUE;
    status = RtlStringCchCopyW(
        handleContext->Path,
        RTL_NUMBER_OF(handleContext->Path),
        bootContext->Path);
    if (NT_SUCCESS(status)) {
        status = FltSetStreamHandleContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            handleContext,
            NULL);
    }
    FltReleaseContext(handleContext);
    if (!NT_SUCCESS(status)) {
        goto FailClosed;
    }

    ExFreePoolWithTag(bootContext, 'oBsX');
    return FLT_POSTOP_FINISHED_PROCESSING;

FailClosed:
    FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    XdowsLogWriteStatus(
        XdowsSecurityLogError,
        0,
        0,
        L"BootProtect",
        L"Protected boot handle context could not be retained; open denied",
        status);
    ExFreePoolWithTag(bootContext, 'oBsX');
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static
FLT_PREOP_CALLBACK_STATUS
XdowsFilePreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    )
{
    PXDOWS_DIRTY_HANDLE_CONTEXT dirtyContext = NULL;
    PXDOWS_CLEANUP_SCAN_CONTEXT scanContext = NULL;
    PFLT_FILE_NAME_INFORMATION name = NULL;
    NTSTATUS status;

    *CompletionContext = NULL;

    if (KeGetCurrentIrql() > APC_LEVEL ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&dirtyContext);
    if (!NT_SUCCESS(status) || dirtyContext == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileAcquireName(Data, &name);
    if (!NT_SUCCESS(status)) {
        FltReleaseContext(dirtyContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!XdowsFileIsScannablePath(&name->Name) ||
        !XdowsFilePassesSizeGate(FltObjects)) {
        FltReleaseFileNameInformation(name);
        FltReleaseContext(dirtyContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    scanContext = (PXDOWS_CLEANUP_SCAN_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*scanContext),
        'cDsX');
    if (scanContext == NULL) {
        FltReleaseFileNameInformation(name);
        FltReleaseContext(dirtyContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(scanContext, sizeof(*scanContext));
    scanContext->OriginatorPid = dirtyContext->OriginatorPid;
    XdowsFileCopyNameInto(
        scanContext->Path,
        RTL_NUMBER_OF(scanContext->Path),
        &name->Name);

    (VOID)FltDeleteStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        NULL);
    FltReleaseFileNameInformation(name);
    FltReleaseContext(dirtyContext);
    *CompletionContext = scanContext;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static
FLT_POSTOP_CALLBACK_STATUS
XdowsFilePostCleanupWhenSafe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PXDOWS_CLEANUP_SCAN_CONTEXT scanContext;
    XDOWS_SECURITY_DECISION verdict;
    UNICODE_STRING path;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    scanContext = (PXDOWS_CLEANUP_SCAN_CONTEXT)CompletionContext;
    if (scanContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        ExFreePoolWithTag(scanContext, 'cDsX');
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RtlInitUnicodeString(&path, scanContext->Path);

    //
    // Post-cleanup cannot fail the original operation; report the write
    // event so user-mode policy can act on it (e.g. mark the file).
    //
    status = XdowsFileConsultPolicy(
        XdowsSecurityEventFileWrite,
        &path,
        scanContext->OriginatorPid,
        &verdict);

    if (XdowsFileVerdictBlocks(status, &verdict)) {
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            verdict.EventId,
            verdict.EventId,
            L"File",
            L"Post-cleanup write reported as blocked.");
    }

    ExFreePoolWithTag(scanContext, 'cDsX');
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static
FLT_POSTOP_CALLBACK_STATUS
XdowsFilePostCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    FLT_POSTOP_CALLBACK_STATUS returnStatus;

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        if (CompletionContext != NULL) {
            ExFreePoolWithTag(CompletionContext, 'cDsX');
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FltDoCompletionProcessingWhenSafe(
            Data,
            FltObjects,
            CompletionContext,
            Flags,
            XdowsFilePostCleanupWhenSafe,
            &returnStatus)) {
        return returnStatus;
    }

    XdowsLogWrite(
        XdowsSecurityLogWarning,
        0,
        0,
        L"File",
        L"Cleanup scan could not be scheduled safely; operation allowed.");
    if (CompletionContext != NULL) {
        ExFreePoolWithTag(CompletionContext, 'cDsX');
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static
FLT_PREOP_CALLBACK_STATUS
XdowsFilePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PFLT_FILE_NAME_INFORMATION destinationName = NULL;
    PFILE_RENAME_INFORMATION nameChangeInformation;
    XDOWS_SECURITY_DECISION verdict;
    FILE_INFORMATION_CLASS informationClass;
    ULONG nameChangeHeaderLength;
    NTSTATUS status;

    *CompletionContext = NULL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    informationClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (!XdowsFileIsNameChangeClass(informationClass) &&
        !XdowsFileIsDeleteDispositionClass(informationClass)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileAcquireName(Data, &name);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (XdowsFileDenyProtectedMutation(Data, &name->Name)) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_COMPLETE;
    }

    if (XdowsFileIsProtectedBootPath(&name->Name)) {
        if (XdowsFileBootMutationMustBeBlocked(Data, &name->Name)) {
            FltReleaseFileNameInformation(name);
            return FLT_PREOP_COMPLETE;
        }
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (XdowsFileIsDeleteDispositionClass(informationClass)) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // FILE_RENAME_INFORMATION and FILE_LINK_INFORMATION intentionally share
    // the Flags/RootDirectory/FileNameLength/FileName layout.
    nameChangeHeaderLength = (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    if (Data->Iopb->Parameters.SetFileInformation.InfoBuffer == NULL ||
        Data->Iopb->Parameters.SetFileInformation.Length < nameChangeHeaderLength) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    nameChangeInformation =
        (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    if (nameChangeInformation->FileNameLength == 0 ||
        nameChangeInformation->FileNameLength >
            Data->Iopb->Parameters.SetFileInformation.Length -
                nameChangeHeaderLength) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance,
        FltObjects->FileObject,
        nameChangeInformation->RootDirectory,
        nameChangeInformation->FileName,
        nameChangeInformation->FileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &destinationName);
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(destinationName);
    }
    if (!NT_SUCCESS(status)) {
        if (destinationName != NULL) {
            FltReleaseFileNameInformation(destinationName);
        }
        FltReleaseFileNameInformation(name);
        XdowsLogWriteStatus(
            XdowsSecurityLogWarning,
            0,
            0,
            L"File",
            L"Name-change destination path query failed; operation allowed",
            status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (XdowsFileDenyProtectedMutation(Data, &destinationName->Name)) {
        FltReleaseFileNameInformation(destinationName);
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_COMPLETE;
    }

    if (XdowsFileIsProtectedBootPath(&destinationName->Name)) {
        if (XdowsFileBootMutationMustBeBlocked(Data, &destinationName->Name)) {
            FltReleaseFileNameInformation(destinationName);
            FltReleaseFileNameInformation(name);
            return FLT_PREOP_COMPLETE;
        }
        FltReleaseFileNameInformation(destinationName);
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!XdowsFileIsScannablePath(&name->Name) &&
        !XdowsFileIsScannablePath(&destinationName->Name)) {
        FltReleaseFileNameInformation(destinationName);
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileConsultPolicy(
        XdowsSecurityEventFileRename,
        &name->Name,
        HandleToULong(FltGetRequestorProcessIdEx(Data)),
        &verdict);
    FltReleaseFileNameInformation(destinationName);
    FltReleaseFileNameInformation(name);

    if (XdowsFileVerdictBlocks(status, &verdict)) {
        XdowsFileFailWithVirus(Data, &verdict);
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
NTSTATUS
XdowsFileFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    if (InterlockedCompareExchange(&g_FileGuard.UnloadPermitted, 0, 0) == 0) {
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            0,
            0,
            L"SelfProtect",
            L"Unauthorized minifilter unload request denied.");
        return STATUS_FLT_DO_NOT_DETACH;
    }

    if (g_FileGuard.FilterHandle != NULL) {
        PFLT_FILTER filter = g_FileGuard.FilterHandle;
        g_FileGuard.FilterHandle = NULL;
        g_XdowsDriverContext.FileProtectionEnabled = FALSE;
        FltUnregisterFilter(filter);
    }
    return STATUS_SUCCESS;
}

NTSTATUS
XdowsFileProtectInitialize(
    VOID
    )
{
    PDEVICE_OBJECT deviceObject;
    PDRIVER_OBJECT driverObject;
    NTSTATUS status;

    g_XdowsDriverContext.FileProtectionEnabled = FALSE;
    if (g_FileGuard.FilterHandle != NULL) {
        g_XdowsDriverContext.FileProtectionEnabled = TRUE;
        return STATUS_SUCCESS;
    }

    if (g_XdowsDriverContext.Device == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Initialize the ransomware rate monitor before the minifilter goes
    // active. The monitor is zero-initialized statically but the spinlock
    // must be set up explicitly.
    //
    XdowsRansomwareMonitorInitialize();

    deviceObject = WdfDeviceWdmGetDeviceObject(g_XdowsDriverContext.Device);
    if (deviceObject == NULL || deviceObject->DriverObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    driverObject = deviceObject->DriverObject;

    RtlZeroMemory(&g_FileGuard, sizeof(g_FileGuard));
    (VOID)InterlockedExchange(&g_FileGuard.UnloadPermitted, 0);
    ExInitializePushLock(&g_FileGuard.BootConfigurationLock);

    g_FileGuard.Operations[0].MajorFunction = IRP_MJ_CREATE;
    g_FileGuard.Operations[0].PreOperation  = XdowsFilePreCreate;
    g_FileGuard.Operations[0].PostOperation = XdowsFilePostCreate;
    g_FileGuard.Operations[1].MajorFunction = IRP_MJ_WRITE;
    g_FileGuard.Operations[1].PreOperation = XdowsFilePreWrite;
    g_FileGuard.Operations[2].MajorFunction = IRP_MJ_CLEANUP;
    g_FileGuard.Operations[2].PreOperation = XdowsFilePreCleanup;
    g_FileGuard.Operations[2].PostOperation = XdowsFilePostCleanup;
    g_FileGuard.Operations[3].MajorFunction = IRP_MJ_SET_INFORMATION;
    g_FileGuard.Operations[3].PreOperation  = XdowsFilePreSetInformation;
    g_FileGuard.Operations[4].MajorFunction = IRP_MJ_OPERATION_END;

    g_FileGuard.Contexts[0].ContextType = FLT_STREAMHANDLE_CONTEXT;
    g_FileGuard.Contexts[0].Flags = 0;
    g_FileGuard.Contexts[0].Size = sizeof(XDOWS_DIRTY_HANDLE_CONTEXT);
    g_FileGuard.Contexts[0].PoolTag = 'hDsX';
    g_FileGuard.Contexts[1].ContextType = FLT_CONTEXT_END;

    g_FileGuard.Registration.Size = sizeof(FLT_REGISTRATION);
    g_FileGuard.Registration.Version = FLT_REGISTRATION_VERSION;
    g_FileGuard.Registration.ContextRegistration = g_FileGuard.Contexts;
    g_FileGuard.Registration.OperationRegistration = g_FileGuard.Operations;
    g_FileGuard.Registration.FilterUnloadCallback = XdowsFileFilterUnload;

    status = FltRegisterFilter(driverObject,
                              &g_FileGuard.Registration,
                              &g_FileGuard.FilterHandle);
    if (!NT_SUCCESS(status)) {
        g_FileGuard.FilterHandle = NULL;
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"File",
            L"Minifilter registration failed", status);
        return status;
    }

    status = FltStartFiltering(g_FileGuard.FilterHandle);
    if (!NT_SUCCESS(status)) {
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"File",
            L"Filtering start failed", status);
        FltUnregisterFilter(g_FileGuard.FilterHandle);
        g_FileGuard.FilterHandle = NULL;
        return status;
    }

    g_XdowsDriverContext.FileProtectionEnabled = TRUE;
    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"File",
        L"File minifilter active.");
    return STATUS_SUCCESS;
}

VOID
XdowsFileProtectShutdown(
    VOID
    )
{
    PFLT_FILTER filter;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FileGuard.BootConfigurationLock);
    g_FileGuard.BootProtectionEnabled = FALSE;
    g_FileGuard.BootVolumeRootCount = 0;
    RtlZeroMemory(g_FileGuard.BootVolumeRoots, sizeof(g_FileGuard.BootVolumeRoots));
    ExReleasePushLockExclusive(&g_FileGuard.BootConfigurationLock);
    KeLeaveCriticalRegion();

    (VOID)InterlockedExchange(&g_FileGuard.UnloadPermitted, 0);
    filter = g_FileGuard.FilterHandle;
    g_FileGuard.FilterHandle = NULL;
    g_XdowsDriverContext.FileProtectionEnabled = FALSE;

    if (filter != NULL) {
        //
        // FltUnregisterFilter drains in-flight callbacks, so it is safe to
        // leave the operation table inside g_FileGuard untouched here.
        //
        FltUnregisterFilter(filter);
        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"File",
            L"File minifilter stopped.");
    }
}

VOID
XdowsFileProtectAuthorizeUnload(
    VOID
    )
{
    (VOID)InterlockedExchange(&g_FileGuard.UnloadPermitted, 1);
    XdowsLogWrite(
        XdowsSecurityLogInfo,
        0,
        0,
        L"SelfProtect",
        L"Authorized minifilter unload enabled.");
}

VOID
XdowsFileProtectRevokeUnload(
    VOID
    )
{
    (VOID)InterlockedExchange(&g_FileGuard.UnloadPermitted, 0);
}

//
// Public helper retained for callers that need to know whether a path would
// be considered for scanning (e.g. a fast-path trust check elsewhere).
//
BOOLEAN
XdowsFileProtectIsPathScannable(
    _In_opt_ PCUNICODE_STRING Path
    )
{
    return XdowsFileIsScannablePath(Path);
}

NTSTATUS
XdowsFileProtectConfigureBootProtection(
    _In_ PXDOWS_SECURITY_BOOT_PROTECTION_REQUEST Request
    )
{
    ULONG index;

    if (Request == NULL ||
        Request->Enabled > 1 ||
        Request->VolumeRootCount > XDOWS_SECURITY_MAX_BOOT_VOLUME_ROOTS ||
        (Request->Enabled != 0 && Request->VolumeRootCount == 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Request->VolumeRootCount; index++) {
        size_t length = 0;
        UNICODE_STRING root;
        UNICODE_STRING devicePrefix = RTL_CONSTANT_STRING(L"\\Device\\");
        NTSTATUS status = RtlStringCchLengthW(
            Request->VolumeRoots[index],
            XDOWS_SECURITY_MAX_BOOT_VOLUME_ROOT_CHARS,
            &length);
        RtlInitUnicodeString(&root, Request->VolumeRoots[index]);
        if (!NT_SUCCESS(status) ||
            length < devicePrefix.Length / sizeof(WCHAR) ||
            !RtlPrefixUnicodeString(&devicePrefix, &root, TRUE)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FileGuard.BootConfigurationLock);
    RtlZeroMemory(g_FileGuard.BootVolumeRoots, sizeof(g_FileGuard.BootVolumeRoots));
    for (index = 0; index < Request->VolumeRootCount; index++) {
        (VOID)RtlStringCchCopyW(
            g_FileGuard.BootVolumeRoots[index],
            XDOWS_SECURITY_MAX_BOOT_VOLUME_ROOT_CHARS,
            Request->VolumeRoots[index]);
    }
    g_FileGuard.BootDiskNumber = Request->DiskNumber;
    g_FileGuard.BootVolumeRootCount = Request->VolumeRootCount;
    g_FileGuard.BootProtectionEnabled = Request->Enabled != 0;
    ExReleasePushLockExclusive(&g_FileGuard.BootConfigurationLock);
    KeLeaveCriticalRegion();

    XdowsLogWrite(
        XdowsSecurityLogInfo,
        0,
        0,
        L"BootProtect",
        Request->Enabled != 0
            ? L"EFI and BCD write protection enabled."
            : L"EFI and BCD write protection disabled.");
    return STATUS_SUCCESS;
}

BOOLEAN
XdowsFileProtectIsBootProtectionEnabled(
    VOID
    )
{
    BOOLEAN enabled;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_FileGuard.BootConfigurationLock);
    enabled = g_FileGuard.BootProtectionEnabled;
    ExReleasePushLockShared(&g_FileGuard.BootConfigurationLock);
    KeLeaveCriticalRegion();
    return enabled;
}
