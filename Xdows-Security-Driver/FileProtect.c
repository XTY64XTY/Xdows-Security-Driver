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
    FLT_OPERATION_REGISTRATION Operations[4];
    FLT_REGISTRATION       Registration;
} XDOWS_FILE_CONTEXT, *PXDOWS_FILE_CONTEXT;

static XDOWS_FILE_CONTEXT g_FileGuard;

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
// Fast-path trust check: files under \Windows\System32\ and \Windows\SysWOW64\
// are trusted OS binaries that are re-opened constantly (system DLLs, drivers).
// Scanning them on every FileCreate saturates user-mode scan capacity and
// indirectly stalls InjectionProtect's user-mode consultation, which surfaces
// as handle-strip timeouts and UI pop-up floods. The normalized name includes
// a volume device prefix, so we search for the directory segment anywhere in
// the path rather than matching a prefix.
//
static
BOOLEAN
XdowsFileIsSystemDirectory(
    _In_ PCUNICODE_STRING Path
    )
{
    static const UNICODE_STRING Segments[] = {
        RTL_CONSTANT_STRING(L"\\Windows\\System32\\"),
        RTL_CONSTANT_STRING(L"\\Windows\\SysWOW64\\")
    };
    ULONG i;
    ULONG s;

    if (Path == NULL || Path->Buffer == NULL) {
        return FALSE;
    }

    for (s = 0; s < RTL_NUMBER_OF(Segments); s++) {
        if (Path->Length < Segments[s].Length) {
            continue;
        }
        for (i = 0; i + Segments[s].Length <= Path->Length; i += sizeof(WCHAR)) {
            UNICODE_STRING sub;
            sub.Buffer = (PWCH)((PUCHAR)Path->Buffer + i);
            sub.Length = Segments[s].Length;
            sub.MaximumLength = Segments[s].Length;
            if (RtlEqualUnicodeString(&sub, (PUNICODE_STRING)&Segments[s], TRUE)) {
                return TRUE;
            }
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
    event.KernelWaitTimeoutMs = XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;

    XdowsFileCopyNameInto(event.ImagePath, XDOWS_SECURITY_MAX_PATH_CHARS, Path);

    return XdowsQueueEventAndWait(&event, Decision);
}

//
// TRUE if the user-mode verdict should fail the originating operation.
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
    return Decision->Decision == XdowsSecurityDecisionBlock ||
           Decision->Decision == XdowsSecurityDecisionTimeout;
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
// TRUE if the SetInformation class is a rename we care about.
//
static
BOOLEAN
XdowsFileIsRenameClass(
    _In_ FILE_INFORMATION_CLASS InfoClass
    )
{
    return InfoClass == FileRenameInformation ||
           InfoClass == FileRenameInformationEx;
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
    PFLT_FILE_NAME_INFORMATION name = NULL;
    XDOWS_SECURITY_DECISION verdict;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileAcquireName(Data, &name);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!XdowsFileIsScannablePath(&name->Name)) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Fast-path trust: skip scanning for files under trusted system
    // directories. These are constantly re-opened OS binaries; scanning
    // them floods user mode and indirectly stalls injection consultation.
    // Only the FileCreate path is skipped -- writes and renames are still
    // scanned because modifying system binaries is itself suspicious.
    //
    if (XdowsFileIsSystemDirectory(&name->Name)) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileConsultPolicy(
        XdowsSecurityEventFileCreate,
        &name->Name,
        HandleToULong(FltGetRequestorProcessIdEx(Data)),
        &verdict);
    FltReleaseFileNameInformation(name);

    if (XdowsFileVerdictBlocks(status, &verdict)) {
        XdowsFileFailWithVirus(Data, &verdict);
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
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
    PFLT_FILE_NAME_INFORMATION name = NULL;
    XDOWS_SECURITY_DECISION verdict;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        !NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!XdowsFilePassesSizeGate(FltObjects)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = XdowsFileAcquireName(Data, &name);
    if (!NT_SUCCESS(status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!XdowsFileIsScannablePath(&name->Name)) {
        FltReleaseFileNameInformation(name);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Post-cleanup cannot fail the original operation; report the write
    // event so user-mode policy can act on it (e.g. mark the file).
    //
    status = XdowsFileConsultPolicy(
        XdowsSecurityEventFileWrite,
        &name->Name,
        HandleToULong(FltGetRequestorProcessIdEx(Data)),
        &verdict);

    if (XdowsFileVerdictBlocks(status, &verdict)) {
        XdowsLogWrite(
            XdowsSecurityLogWarning,
            verdict.EventId,
            verdict.EventId,
            L"File",
            L"Post-cleanup write reported as blocked.");
    }

    FltReleaseFileNameInformation(name);
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
    XDOWS_SECURITY_DECISION verdict;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!XdowsFileIsRenameClass(
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileAcquireName(Data, &name);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!XdowsFileIsScannablePath(&name->Name)) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileConsultPolicy(
        XdowsSecurityEventFileRename,
        &name->Name,
        HandleToULong(FltGetRequestorProcessIdEx(Data)),
        &verdict);
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

    if (g_FileGuard.FilterHandle != NULL) {
        PFLT_FILTER filter = g_FileGuard.FilterHandle;
        g_FileGuard.FilterHandle = NULL;
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

    if (g_FileGuard.FilterHandle != NULL) {
        return STATUS_SUCCESS;
    }

    if (g_XdowsDriverContext.Device == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    deviceObject = WdfDeviceWdmGetDeviceObject(g_XdowsDriverContext.Device);
    if (deviceObject == NULL || deviceObject->DriverObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    driverObject = deviceObject->DriverObject;

    RtlZeroMemory(&g_FileGuard, sizeof(g_FileGuard));

    g_FileGuard.Operations[0].MajorFunction = IRP_MJ_CREATE;
    g_FileGuard.Operations[0].PreOperation  = XdowsFilePreCreate;
    g_FileGuard.Operations[1].MajorFunction = IRP_MJ_CLEANUP;
    g_FileGuard.Operations[1].PostOperation = XdowsFilePostCleanup;
    g_FileGuard.Operations[2].MajorFunction = IRP_MJ_SET_INFORMATION;
    g_FileGuard.Operations[2].PreOperation  = XdowsFilePreSetInformation;
    g_FileGuard.Operations[3].MajorFunction = IRP_MJ_OPERATION_END;

    g_FileGuard.Registration.Size = sizeof(FLT_REGISTRATION);
    g_FileGuard.Registration.Version = FLT_REGISTRATION_VERSION;
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

    filter = g_FileGuard.FilterHandle;
    g_FileGuard.FilterHandle = NULL;

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
