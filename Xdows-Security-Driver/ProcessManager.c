#include "driver.h"
#include "processmanager.h"
#include "selfprotect.h"
#include <ntstrsafe.h>

#define XDOWS_PROCESS_SNAPSHOT_TAG 'pSdX'
#define XDOWS_SYSTEM_PROCESS_INFORMATION_CLASS 5
#define XDOWS_PROCESS_BREAK_ON_TERMINATION_CLASS 29
#define XDOWS_PROCESS_SNAPSHOT_SLACK (64u * 1024u)
#define XDOWS_PROCESS_SNAPSHOT_ATTEMPTS 3u

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

NTSYSAPI
NTSTATUS
NTAPI
ZwSuspendProcess(
    _In_ HANDLE ProcessHandle);

NTSYSAPI
NTSTATUS
NTAPI
ZwResumeProcess(
    _In_ HANDLE ProcessHandle);

typedef struct _XDOWS_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
} XDOWS_SYSTEM_PROCESS_INFORMATION, *PXDOWS_SYSTEM_PROCESS_INFORMATION;

static
NTSTATUS
XdowsProcessManagerCaptureSnapshot(
    _Outptr_result_bytebuffer_(*SnapshotLength) PVOID* Snapshot,
    _Out_ PULONG SnapshotLength)
{
    PVOID buffer = NULL;
    ULONG bufferLength;
    ULONG requiredLength = 0;
    ULONG attempt;
    NTSTATUS status;

    if (Snapshot == NULL || SnapshotLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Snapshot = NULL;
    *SnapshotLength = 0;

    status = ZwQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)XDOWS_SYSTEM_PROCESS_INFORMATION_CLASS,
        NULL,
        0,
        &requiredLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status)) {
        return status;
    }

    for (attempt = 0; attempt < XDOWS_PROCESS_SNAPSHOT_ATTEMPTS; attempt++) {
        if (requiredLength > MAXULONG - XDOWS_PROCESS_SNAPSHOT_SLACK) {
            return STATUS_INTEGER_OVERFLOW;
        }

        bufferLength = requiredLength + XDOWS_PROCESS_SNAPSHOT_SLACK;
        buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferLength, XDOWS_PROCESS_SNAPSHOT_TAG);
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)XDOWS_SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer,
            bufferLength,
            &requiredLength);
        if (NT_SUCCESS(status)) {
            *Snapshot = buffer;
            *SnapshotLength = bufferLength;
            return STATUS_SUCCESS;
        }

        ExFreePoolWithTag(buffer, XDOWS_PROCESS_SNAPSHOT_TAG);
        buffer = NULL;
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            return status;
        }
    }

    return STATUS_BUFFER_TOO_SMALL;
}

static
VOID
XdowsProcessManagerCopyName(
    _In_ PXDOWS_SYSTEM_PROCESS_INFORMATION Process,
    _Out_writes_(XDOWS_SECURITY_MAX_PROCESS_NAME_CHARS) PWCHAR Destination)
{
    USHORT charsToCopy;

    Destination[0] = UNICODE_NULL;
    if (Process->ImageName.Buffer == NULL || Process->ImageName.Length == 0) {
        if (HandleToULong(Process->UniqueProcessId) == 0) {
            (VOID)RtlStringCchCopyW(
                Destination,
                XDOWS_SECURITY_MAX_PROCESS_NAME_CHARS,
                L"System Idle Process");
        } else if (HandleToULong(Process->UniqueProcessId) == 4) {
            (VOID)RtlStringCchCopyW(
                Destination,
                XDOWS_SECURITY_MAX_PROCESS_NAME_CHARS,
                L"System");
        }
        return;
    }

    charsToCopy = Process->ImageName.Length / sizeof(WCHAR);
    if (charsToCopy >= XDOWS_SECURITY_MAX_PROCESS_NAME_CHARS) {
        charsToCopy = XDOWS_SECURITY_MAX_PROCESS_NAME_CHARS - 1;
    }

    RtlCopyMemory(Destination, Process->ImageName.Buffer, charsToCopy * sizeof(WCHAR));
    Destination[charsToCopy] = UNICODE_NULL;
}

NTSTATUS
XdowsProcessManagerQuery(
    _In_ PXDOWS_SECURITY_PROCESS_QUERY_REQUEST Request,
    _Out_ PXDOWS_SECURITY_PROCESS_QUERY_RESPONSE Response)
{
    PVOID snapshot = NULL;
    ULONG snapshotLength = 0;
    PXDOWS_SYSTEM_PROCESS_INFORMATION current;
    ULONG index = 0;
    ULONG count = 0;
    BOOLEAN hasMore = FALSE;
    NTSTATUS status;

    PAGED_CODE();

    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Response, sizeof(*Response));
    Response->Header.Size = sizeof(*Response);
    Response->Header.Version = XDOWS_SECURITY_PROTOCOL_VERSION;

    status = XdowsProcessManagerCaptureSnapshot(&snapshot, &snapshotLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    current = (PXDOWS_SYSTEM_PROCESS_INFORMATION)snapshot;
    for (;;) {
        if (index >= Request->Cursor) {
            if (count >= XDOWS_SECURITY_PROCESS_BATCH_SIZE) {
                hasMore = TRUE;
                break;
            }

            Response->Entries[count].ProcessId = HandleToULong(current->UniqueProcessId);
            Response->Entries[count].ParentProcessId = HandleToULong(current->InheritedFromUniqueProcessId);
            Response->Entries[count].SessionId = current->SessionId;
            Response->Entries[count].ThreadCount = current->NumberOfThreads;
            Response->Entries[count].HandleCount = current->HandleCount;
            Response->Entries[count].BasePriority = (ULONG)current->BasePriority;
            Response->Entries[count].WorkingSetBytes = (ULONGLONG)current->WorkingSetSize;
            Response->Entries[count].PrivateBytes = (ULONGLONG)current->PrivatePageCount;
            XdowsProcessManagerCopyName(current, Response->Entries[count].ImageName);
            count++;
        }

        index++;
        if (current->NextEntryOffset == 0) {
            break;
        }
        if (current->NextEntryOffset > snapshotLength ||
            (PUCHAR)current + current->NextEntryOffset >= (PUCHAR)snapshot + snapshotLength) {
            status = STATUS_DATA_ERROR;
            goto Exit;
        }
        current = (PXDOWS_SYSTEM_PROCESS_INFORMATION)((PUCHAR)current + current->NextEntryOffset);
    }

    Response->Count = count;
    Response->NextCursor = Request->Cursor + count;
    Response->HasMore = hasMore ? 1u : 0u;
    status = STATUS_SUCCESS;

Exit:
    ExFreePoolWithTag(snapshot, XDOWS_PROCESS_SNAPSHOT_TAG);
    return status;
}

static
NTSTATUS
XdowsProcessManagerOpenTarget(
    _In_ ULONG ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle)
{
    OBJECT_ATTRIBUTES attributes;
    CLIENT_ID clientId;

    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ULongToHandle(ProcessId);
    clientId.UniqueThread = NULL;
    return ZwOpenProcess(ProcessHandle, DesiredAccess, &attributes, &clientId);
}

static
NTSTATUS
XdowsProcessManagerQueryCriticalState(
    _In_ HANDLE ProcessHandle,
    _Out_ PBOOLEAN IsCritical)
{
    ULONG breakOnTermination = 0;
    NTSTATUS status;

    if (IsCritical == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsCritical = TRUE;
    status = ZwQueryInformationProcess(
        ProcessHandle,
        (PROCESSINFOCLASS)XDOWS_PROCESS_BREAK_ON_TERMINATION_CLASS,
        &breakOnTermination,
        sizeof(breakOnTermination),
        NULL);
    if (NT_SUCCESS(status)) {
        *IsCritical = breakOnTermination != 0;
    }
    return status;
}

NTSTATUS
XdowsProcessManagerOperate(
    _In_ ULONG RequestorProcessId,
    _In_ PXDOWS_SECURITY_PROCESS_OPERATION_REQUEST Request)
{
    ACCESS_MASK desiredAccess;
    HANDLE processHandle = NULL;
    BOOLEAN isCritical;
    NTSTATUS status;

    PAGED_CODE();

    if (Request == NULL ||
        Request->ProcessId == 0 ||
        Request->ProcessId == 4 ||
        Request->ProcessId == RequestorProcessId ||
        XdowsSelfProtectIsProcessProtected(ULongToHandle(Request->ProcessId))) {
        return STATUS_ACCESS_DENIED;
    }

    switch ((XDOWS_SECURITY_PROCESS_OPERATION)Request->Operation) {
    case XdowsSecurityProcessOperationSuspend:
    case XdowsSecurityProcessOperationResume:
        desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME;
        break;
    case XdowsSecurityProcessOperationTerminate:
        desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    status = XdowsProcessManagerOpenTarget(Request->ProcessId, desiredAccess, &processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = XdowsProcessManagerQueryCriticalState(processHandle, &isCritical);
    if (!NT_SUCCESS(status) || isCritical) {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    switch ((XDOWS_SECURITY_PROCESS_OPERATION)Request->Operation) {
    case XdowsSecurityProcessOperationSuspend:
        status = ZwSuspendProcess(processHandle);
        break;
    case XdowsSecurityProcessOperationResume:
        status = ZwResumeProcess(processHandle);
        break;
    case XdowsSecurityProcessOperationTerminate:
        status = ZwTerminateProcess(processHandle, STATUS_SUCCESS);
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

Exit:
    ZwClose(processHandle);
    return status;
}
