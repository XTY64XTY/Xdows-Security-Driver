#include "driver.h"
#include <fltKernel.h>
#include <ntstrsafe.h>

#define XDOWS_FILEPROTECT_MAX_FILE_BYTES (512ULL * 1024ULL * 1024ULL)

static PFLT_FILTER g_XdowsFilter;

static
VOID
XdowsCopyUnicodeToFixedBuffer(
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

BOOLEAN
XdowsFileProtectIsPathScannable(
    _In_opt_ PCUNICODE_STRING Path
    )
{
    static const WCHAR* Extensions[] = {
        L".exe", L".dll", L".sys", L".scr", L".bat", L".cmd", L".ps1",
        L".vbs", L".js", L".jse", L".wsf", L".msi", L".msp", L".cab",
        L".zip", L".rar", L".7z", L".iso", L".doc", L".docx", L".xls",
        L".xlsx", L".ppt", L".pptx", L".pdf"
    };
    UNICODE_STRING extension;

    if (Path == NULL || Path->Buffer == NULL || Path->Length < sizeof(WCHAR) * 5) {
        return FALSE;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(Extensions); i++) {
        RtlInitUnicodeString(&extension, Extensions[i]);
        if (Path->Length >= extension.Length &&
            RtlSuffixUnicodeString(&extension, Path, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

static
NTSTATUS
XdowsFileProtectGetNormalizedName(
    _Inout_ PFLT_CALLBACK_DATA Data,
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
NTSTATUS
XdowsFileProtectQueueDecision(
    _In_ ULONG EventType,
    _In_ PCUNICODE_STRING Path,
    _In_ ULONG ProcessId,
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
    event.Flags = XdowsSecurityEventFlagUserModeRequired | XdowsSecurityEventFlagFileOpenNameAvailable;
    event.ProcessId = ProcessId;
    event.CreatingProcessId = HandleToULong(PsGetCurrentProcessId());
    event.KernelWaitTimeoutMs = XDOWS_SECURITY_DEFAULT_KERNEL_WAIT_TIMEOUT_MS;

    XdowsCopyUnicodeToFixedBuffer(event.ImagePath, XDOWS_SECURITY_MAX_PATH_CHARS, Path);

    return XdowsQueueEventAndWait(&event, Decision);
}

static
BOOLEAN
XdowsFileProtectShouldBlock(
    _In_ NTSTATUS Status,
    _In_ PXDOWS_SECURITY_DECISION Decision
    )
{
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    return Decision->Decision == XdowsSecurityDecisionBlock ||
        Decision->Decision == XdowsSecurityDecisionTimeout;
}

static
FLT_PREOP_CALLBACK_STATUS
XdowsFileProtectPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    XDOWS_SECURITY_DECISION decision;
    NTSTATUS status;
    ULONG requestorPid;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileProtectGetNormalizedName(Data, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!XdowsFileProtectIsPathScannable(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    requestorPid = HandleToULong(FltGetRequestorProcessIdEx(Data));
    status = XdowsFileProtectQueueDecision(
        XdowsSecurityEventFileCreate,
        &nameInfo->Name,
        requestorPid,
        &decision);
    FltReleaseFileNameInformation(nameInfo);

    if (XdowsFileProtectShouldBlock(status, &decision)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
FLT_POSTOP_CALLBACK_STATUS
XdowsFileProtectPostCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FILE_STANDARD_INFORMATION standardInformation;
    XDOWS_SECURITY_DECISION decision;
    NTSTATUS status;
    ULONG requestorPid;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &standardInformation,
        sizeof(standardInformation),
        FileStandardInformation,
        NULL);
    if (!NT_SUCCESS(status) ||
        standardInformation.Directory ||
        standardInformation.EndOfFile.QuadPart <= 0 ||
        (ULONGLONG)standardInformation.EndOfFile.QuadPart > XDOWS_FILEPROTECT_MAX_FILE_BYTES) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = XdowsFileProtectGetNormalizedName(Data, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!XdowsFileProtectIsPathScannable(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    requestorPid = HandleToULong(FltGetRequestorProcessIdEx(Data));
    (VOID)XdowsFileProtectQueueDecision(
        XdowsSecurityEventFileWrite,
        &nameInfo->Name,
        requestorPid,
        &decision);

    FltReleaseFileNameInformation(nameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static
FLT_PREOP_CALLBACK_STATUS
XdowsFileProtectPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FILE_INFORMATION_CLASS fileInformationClass;
    XDOWS_SECURITY_DECISION decision;
    NTSTATUS status;
    ULONG requestorPid;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    fileInformationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (fileInformationClass != FileRenameInformation &&
        fileInformationClass != FileRenameInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = XdowsFileProtectGetNormalizedName(Data, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!XdowsFileProtectIsPathScannable(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    requestorPid = HandleToULong(FltGetRequestorProcessIdEx(Data));
    status = XdowsFileProtectQueueDecision(
        XdowsSecurityEventFileRename,
        &nameInfo->Name,
        requestorPid,
        &decision);
    FltReleaseFileNameInformation(nameInfo);

    if (XdowsFileProtectShouldBlock(status, &decision)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
NTSTATUS
XdowsFileProtectUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);
    g_XdowsFilter = NULL;
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION g_XdowsFileOperations[] = {
    {
        IRP_MJ_CREATE,
        0,
        XdowsFileProtectPreCreate,
        NULL
    },
    {
        IRP_MJ_CLEANUP,
        0,
        NULL,
        XdowsFileProtectPostCleanup
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        XdowsFileProtectPreSetInformation,
        NULL
    },
    {
        IRP_MJ_OPERATION_END
    }
};

CONST FLT_REGISTRATION g_XdowsFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_XdowsFileOperations,
    XdowsFileProtectUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS
XdowsFileProtectInitialize(
    VOID
    )
{
    PDEVICE_OBJECT deviceObject;
    PDRIVER_OBJECT driverObject;
    NTSTATUS status;

    if (g_XdowsFilter != NULL) {
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

    status = FltRegisterFilter(driverObject, &g_XdowsFilterRegistration, &g_XdowsFilter);
    if (!NT_SUCCESS(status)) {
        g_XdowsFilter = NULL;
        return status;
    }

    status = FltStartFiltering(g_XdowsFilter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_XdowsFilter);
        g_XdowsFilter = NULL;
    }

    return status;
}

VOID
XdowsFileProtectShutdown(
    VOID
    )
{
    PFLT_FILTER filter = g_XdowsFilter;
    g_XdowsFilter = NULL;

    if (filter != NULL) {
        FltUnregisterFilter(filter);
    }
}
