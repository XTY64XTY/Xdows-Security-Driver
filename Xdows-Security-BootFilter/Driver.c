#include <ntddk.h>
#include <wdmsec.h>
#include <ntstrsafe.h>
#include <initguid.h>
#include "Public.h"

DEFINE_GUID(GUID_DEVCLASS_XDOWS_BOOT_FILTER,
    0x82f67d19, 0x6cd5, 0x4b79, 0x9d, 0x62, 0xa6, 0x35, 0xd5, 0x44, 0x9e, 0x31);

NTKERNELAPI
NTSTATUS
SeLocateProcessImageName(
    _In_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING* ImageFileName
    );

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

#define XDOWS_BOOT_RANGE_MAX_BYTES (16ULL * 1024ULL * 1024ULL)
#define XDOWS_BOOT_POOL_TAG 'bBsX'

typedef struct _XDOWS_BOOT_PENDING_WRITE {
    LIST_ENTRY Link;
    PIRP Irp;
    PIO_WORKITEM WorkItem;
    XDOWS_BOOT_WRITE_EVENT Event;
    KEVENT DecisionEvent;
    ULONG Decision;
    BOOLEAN Delivered;
    BOOLEAN Linked;
    ULONG ReservedBytes;
} XDOWS_BOOT_PENDING_WRITE, *PXDOWS_BOOT_PENDING_WRITE;

typedef struct _XDOWS_BOOT_CONTEXT {
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT ControlDevice;
    PDEVICE_OBJECT FilterDevice;
    PDEVICE_OBJECT LowerDevice;
    PFILE_OBJECT TargetFileObject;
    KSPIN_LOCK Lock;
    KEVENT EventAvailable;
    KEVENT PendingZeroEvent;
    LIST_ENTRY PendingWrites;
    XDOWS_BOOT_RAW_RANGE Ranges[XDOWS_BOOT_MAX_RANGES];
    ULONG RangeCount;
    ULONG DiskNumber;
    ULONG ClientProcessId;
    ULONG PendingRequestCount;
    ULONG PendingBytes;
    ULONG BlockedNoClientCount;
    ULONG BlockedResourceCount;
    ULONG TimedOutCount;
    ULONGLONG NextEventId;
    BOOLEAN ClientConnected;
    BOOLEAN Configured;
    BOOLEAN Unloading;
} XDOWS_BOOT_CONTEXT;

static XDOWS_BOOT_CONTEXT g_BootContext;

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS XdowsBootDispatchUnsupported(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS XdowsBootDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS XdowsBootDispatchCleanup(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS XdowsBootDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS XdowsBootDispatchWrite(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS XdowsBootDispatchPassThrough(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS XdowsBootDispatchPower(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static VOID XdowsBootUnload(_In_ PDRIVER_OBJECT DriverObject);

static
ULONG
XdowsBootGetRequestorProcessId(
    _In_ PIRP Irp
    )
{
    HANDLE processId = Irp->Tail.Overlay.Thread != NULL
        ? PsGetThreadProcessId(Irp->Tail.Overlay.Thread)
        : PsGetCurrentProcessId();

    return HandleToULong(processId);
}

static
VOID
XdowsBootInitializeHeader(
    _Out_ PXDOWS_BOOT_PROTOCOL_HEADER Header,
    _In_ ULONG Size
    )
{
    Header->Size = Size;
    Header->Version = XDOWS_BOOT_PROTOCOL_VERSION;
}

static
BOOLEAN
XdowsBootHeaderIsValid(
    _In_ PXDOWS_BOOT_PROTOCOL_HEADER Header,
    _In_ ULONG ExpectedSize
    )
{
    return Header != NULL &&
        Header->Size == ExpectedSize &&
        Header->Version == XDOWS_BOOT_PROTOCOL_VERSION;
}

static
NTSTATUS
XdowsBootComplete(
    _Inout_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
    )
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static
VOID
XdowsBootLogBlockedWrite(
    _In_ ULONG Reason,
    _In_ NTSTATUS Status,
    _In_ LONGLONG Offset,
    _In_ ULONG Length
    )
{
    PIO_ERROR_LOG_PACKET packet;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_WARNING_LEVEL,
        "XdowsBootFilter: blocked write reason=%lu status=0x%08X offset=%I64d length=%lu\n",
        Reason,
        Status,
        Offset,
        Length);

    if (g_BootContext.DriverObject == NULL) {
        return;
    }

    packet = IoAllocateErrorLogEntry(
        g_BootContext.DriverObject,
        (UCHAR)(sizeof(IO_ERROR_LOG_PACKET) + sizeof(ULONG) * 4));
    if (packet == NULL) {
        return;
    }

    packet->ErrorCode = Status;
    packet->UniqueErrorValue = Reason;
    packet->FinalStatus = Status;
    packet->DumpDataSize = sizeof(ULONG) * 4;
    packet->DumpData[0] = g_BootContext.DiskNumber;
    packet->DumpData[1] = (ULONG)Offset;
    packet->DumpData[2] = (ULONG)((ULONGLONG)Offset >> 32);
    packet->DumpData[3] = Length;
    IoWriteErrorLogEntry(packet);
}

static
NTSTATUS
XdowsBootValidateClientProcess(
    _In_ ULONG ProcessId
    )
{
    static const UNICODE_STRING expectedName =
        RTL_CONSTANT_STRING(L"Xdows-Security.exe");
    PEPROCESS process = NULL;
    PUNICODE_STRING imagePath = NULL;
    UNICODE_STRING imageName;
    USHORT characterCount;
    USHORT nameStart = 0;
    USHORT index;
    NTSTATUS status;

    status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &process);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    status = SeLocateProcessImageName(process, &imagePath);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status) || imagePath == NULL || imagePath->Buffer == NULL) {
        if (imagePath != NULL) {
            ExFreePool(imagePath);
        }
        return STATUS_ACCESS_DENIED;
    }

    characterCount = imagePath->Length / sizeof(WCHAR);
    for (index = characterCount; index > 0; index--) {
        if (imagePath->Buffer[index - 1] == L'\\') {
            nameStart = index;
            break;
        }
    }

    imageName.Buffer = imagePath->Buffer + nameStart;
    imageName.Length = imagePath->Length - (nameStart * sizeof(WCHAR));
    imageName.MaximumLength = imageName.Length;
    status = RtlEqualUnicodeString(&imageName, &expectedName, TRUE)
        ? STATUS_SUCCESS
        : STATUS_ACCESS_DENIED;
    ExFreePool(imagePath);
    return status;
}

static
BOOLEAN
XdowsBootCallerIsClient(
    _In_ PIRP Irp
    )
{
    KIRQL oldIrql;
    ULONG requestorProcessId = XdowsBootGetRequestorProcessId(Irp);
    BOOLEAN authorized;

    KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
    authorized = g_BootContext.ClientConnected &&
        g_BootContext.ClientProcessId == requestorProcessId;
    KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
    return authorized;
}

static
VOID
XdowsBootDisconnectClient(
    _In_ ULONG ProcessId
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
    if (!g_BootContext.ClientConnected ||
        (ProcessId != 0 && g_BootContext.ClientProcessId != ProcessId)) {
        KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
        return;
    }

    g_BootContext.ClientConnected = FALSE;
    g_BootContext.ClientProcessId = 0;
    for (entry = g_BootContext.PendingWrites.Flink;
         entry != &g_BootContext.PendingWrites;
         entry = entry->Flink) {
        PXDOWS_BOOT_PENDING_WRITE pending =
            CONTAINING_RECORD(entry, XDOWS_BOOT_PENDING_WRITE, Link);
        pending->Decision = XdowsBootDecisionBlock;
        KeSetEvent(&pending->DecisionEvent, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
    KeSetEvent(&g_BootContext.EventAvailable, IO_NO_INCREMENT, FALSE);
}

static
BOOLEAN
XdowsBootRangesAreValid(
    _In_ PXDOWS_BOOT_CONFIGURE_REQUEST Request
    )
{
    ULONG index;

    if (Request->RangeCount == 0 || Request->RangeCount > XDOWS_BOOT_MAX_RANGES) {
        return FALSE;
    }

    for (index = 0; index < Request->RangeCount; index++) {
        ULONGLONG offset;
        ULONGLONG length = Request->Ranges[index].Length;
        ULONGLONG end;

        if (Request->Ranges[index].Offset < 0 ||
            length == 0 ||
            length > XDOWS_BOOT_RANGE_MAX_BYTES) {
            return FALSE;
        }
        offset = (ULONGLONG)Request->Ranges[index].Offset;
        end = offset + length;
        if (end < offset) {
            return FALSE;
        }
    }
    return TRUE;
}

static
NTSTATUS
XdowsBootAttachDisk(
    _In_ ULONG DiskNumber
    )
{
    WCHAR devicePathBuffer[64];
    UNICODE_STRING devicePath;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT targetDevice = NULL;
    PDEVICE_OBJECT filterDevice = NULL;
    PDEVICE_OBJECT lowerDevice = NULL;
    NTSTATUS status;

    if (g_BootContext.FilterDevice != NULL) {
        return g_BootContext.DiskNumber == DiskNumber
            ? STATUS_SUCCESS
            : STATUS_DEVICE_BUSY;
    }

    status = RtlStringCchPrintfW(
        devicePathBuffer,
        RTL_NUMBER_OF(devicePathBuffer),
        L"\\Device\\Harddisk%lu\\Partition0",
        DiskNumber);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlInitUnicodeString(&devicePath, devicePathBuffer);

    status = IoGetDeviceObjectPointer(
        &devicePath,
        FILE_READ_ATTRIBUTES,
        &fileObject,
        &targetDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateDevice(
        g_BootContext.DriverObject,
        0,
        NULL,
        targetDevice->DeviceType,
        targetDevice->Characteristics,
        FALSE,
        &filterDevice);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(fileObject);
        return status;
    }

    status = IoAttachDeviceToDeviceStackSafe(
        filterDevice,
        targetDevice,
        &lowerDevice);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(filterDevice);
        ObDereferenceObject(fileObject);
        return status;
    }

    filterDevice->Flags |= targetDevice->Flags &
        (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    filterDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    g_BootContext.FilterDevice = filterDevice;
    g_BootContext.LowerDevice = lowerDevice;
    g_BootContext.TargetFileObject = fileObject;
    g_BootContext.DiskNumber = DiskNumber;
    return STATUS_SUCCESS;
}

static
BOOLEAN
XdowsBootWriteIntersectsProtectedRange(
    _In_ LONGLONG WriteOffset,
    _In_ ULONG WriteLength
    )
{
    KIRQL oldIrql;
    ULONGLONG start;
    ULONGLONG end;
    ULONG index;
    BOOLEAN intersects = FALSE;

    if (WriteOffset < 0 || WriteLength == 0) {
        return WriteOffset < 0;
    }

    start = (ULONGLONG)WriteOffset;
    end = start + WriteLength;
    if (end < start) {
        return TRUE;
    }

    KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
    if (g_BootContext.Configured) {
        for (index = 0; index < g_BootContext.RangeCount; index++) {
            ULONGLONG rangeStart =
                (ULONGLONG)g_BootContext.Ranges[index].Offset;
            ULONGLONG rangeEnd = rangeStart +
                g_BootContext.Ranges[index].Length;
            if (start < rangeEnd && rangeStart < end) {
                intersects = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
    return intersects;
}

static
VOID
XdowsBootReleasePendingReservation(
    _In_ ULONG Bytes
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
    if (g_BootContext.PendingRequestCount > 0) {
        g_BootContext.PendingRequestCount--;
    }
    if (g_BootContext.PendingBytes >= Bytes) {
        g_BootContext.PendingBytes -= Bytes;
    } else {
        g_BootContext.PendingBytes = 0;
    }
    if (g_BootContext.PendingRequestCount == 0) {
        KeSetEvent(&g_BootContext.PendingZeroEvent, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
}

static
VOID
XdowsBootProcessProtectedWrite(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PXDOWS_BOOT_PENDING_WRITE pending =
        (PXDOWS_BOOT_PENDING_WRITE)Context;
    LARGE_INTEGER timeout;
    KIRQL oldIrql;
    NTSTATUS waitStatus = STATUS_DEVICE_NOT_CONNECTED;
    BOOLEAN queued = FALSE;
    ULONG decision = XdowsBootDecisionBlock;

    UNREFERENCED_PARAMETER(DeviceObject);

    KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
    if (g_BootContext.ClientConnected && !g_BootContext.Unloading) {
        pending->Event.EventId = g_BootContext.NextEventId++;
        if (g_BootContext.NextEventId == 0) {
            g_BootContext.NextEventId = 1;
        }
        InsertTailList(&g_BootContext.PendingWrites, &pending->Link);
        pending->Linked = TRUE;
        queued = TRUE;
        KeSetEvent(&g_BootContext.EventAvailable, IO_NO_INCREMENT, FALSE);
    } else {
        g_BootContext.BlockedNoClientCount++;
    }
    KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);

    if (queued) {
        timeout.QuadPart = -(LONGLONG)XDOWS_BOOT_DECISION_TIMEOUT_MS * 10000LL;
        waitStatus = KeWaitForSingleObject(
            &pending->DecisionEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout);

        KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
        decision = waitStatus == STATUS_SUCCESS
            ? pending->Decision
            : XdowsBootDecisionBlock;
        if (pending->Linked) {
            RemoveEntryList(&pending->Link);
            pending->Linked = FALSE;
        }
        if (waitStatus != STATUS_SUCCESS) {
            g_BootContext.TimedOutCount++;
        }
        KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
    }

    if (decision == XdowsBootDecisionAllow &&
        !g_BootContext.Unloading &&
        g_BootContext.LowerDevice != NULL) {
        PIRP irp = pending->Irp;
        PIO_WORKITEM workItem = pending->WorkItem;
        ULONG reservedBytes = pending->ReservedBytes;
        ExFreePoolWithTag(pending, XDOWS_BOOT_POOL_TAG);
        IoFreeWorkItem(workItem);
        IoSkipCurrentIrpStackLocation(irp);
        (VOID)IoCallDriver(g_BootContext.LowerDevice, irp);
        XdowsBootReleasePendingReservation(reservedBytes);
        return;
    }

    XdowsBootLogBlockedWrite(
        queued && waitStatus != STATUS_SUCCESS ? 3u : (queued ? 4u : 1u),
        STATUS_ACCESS_DENIED,
        pending->Event.Offset,
        pending->Event.Length);
    XdowsBootComplete(pending->Irp, STATUS_ACCESS_DENIED, 0);
    IoFreeWorkItem(pending->WorkItem);
    {
        ULONG reservedBytes = pending->ReservedBytes;
        ExFreePoolWithTag(pending, XDOWS_BOOT_POOL_TAG);
        XdowsBootReleasePendingReservation(reservedBytes);
    }
}

static
NTSTATUS
XdowsBootGetNextEvent(
    _Out_ PXDOWS_BOOT_WRITE_EVENT Event
    )
{
    LARGE_INTEGER timeout;
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    NTSTATUS waitStatus;

    for (;;) {
        KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
        for (entry = g_BootContext.PendingWrites.Flink;
             entry != &g_BootContext.PendingWrites;
             entry = entry->Flink) {
            PXDOWS_BOOT_PENDING_WRITE pending =
                CONTAINING_RECORD(entry, XDOWS_BOOT_PENDING_WRITE, Link);
            if (!pending->Delivered) {
                pending->Delivered = TRUE;
                RtlCopyMemory(Event, &pending->Event, sizeof(*Event));
                KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
                return STATUS_SUCCESS;
            }
        }
        if (!g_BootContext.ClientConnected || g_BootContext.Unloading) {
            KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
            return STATUS_DEVICE_NOT_CONNECTED;
        }
        KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);

        timeout.QuadPart = -(LONGLONG)1000 * 10000LL;
        waitStatus = KeWaitForSingleObject(
            &g_BootContext.EventAvailable,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
        if (waitStatus != STATUS_SUCCESS) {
            return STATUS_NO_MORE_ENTRIES;
        }
    }
}

static
NTSTATUS
XdowsBootSubmitDecision(
    _In_ PXDOWS_BOOT_DECISION Decision
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    if (!XdowsBootHeaderIsValid(&Decision->Header, sizeof(*Decision)) ||
        (Decision->Decision != XdowsBootDecisionAllow &&
         Decision->Decision != XdowsBootDecisionBlock)) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
    for (entry = g_BootContext.PendingWrites.Flink;
         entry != &g_BootContext.PendingWrites;
         entry = entry->Flink) {
        PXDOWS_BOOT_PENDING_WRITE pending =
            CONTAINING_RECORD(entry, XDOWS_BOOT_PENDING_WRITE, Link);
        if (pending->Event.EventId == Decision->EventId) {
            pending->Decision = Decision->Decision;
            KeSetEvent(&pending->DecisionEvent, IO_NO_INCREMENT, FALSE);
            KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
    return STATUS_NOT_FOUND;
}

static
VOID
XdowsBootGetState(
    _Out_ PXDOWS_BOOT_STATE State
    )
{
    KIRQL oldIrql;

    RtlZeroMemory(State, sizeof(*State));
    XdowsBootInitializeHeader(&State->Header, sizeof(*State));
    KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
    State->ClientConnected = g_BootContext.ClientConnected ? 1u : 0u;
    State->Configured = g_BootContext.Configured ? 1u : 0u;
    State->Attached = g_BootContext.FilterDevice != NULL ? 1u : 0u;
    State->DiskNumber = g_BootContext.DiskNumber;
    State->PendingRequestCount = g_BootContext.PendingRequestCount;
    State->PendingBytes = g_BootContext.PendingBytes;
    State->BlockedNoClientCount = g_BootContext.BlockedNoClientCount;
    State->BlockedResourceCount = g_BootContext.BlockedResourceCount;
    State->TimedOutCount = g_BootContext.TimedOutCount;
    State->DriverBuildId = XDOWS_BOOT_DRIVER_BUILD_ID;
    KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
}

static
NTSTATUS
XdowsBootDispatchUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    if (DeviceObject == g_BootContext.FilterDevice &&
        g_BootContext.LowerDevice != NULL) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(g_BootContext.LowerDevice, Irp);
    }
    return XdowsBootComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static
NTSTATUS
XdowsBootDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    if (DeviceObject == g_BootContext.ControlDevice) {
        return XdowsBootComplete(Irp, STATUS_SUCCESS, 0);
    }
    return XdowsBootDispatchPassThrough(DeviceObject, Irp);
}

static
NTSTATUS
XdowsBootDispatchCleanup(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    if (DeviceObject == g_BootContext.ControlDevice) {
        XdowsBootDisconnectClient(XdowsBootGetRequestorProcessId(Irp));
        return XdowsBootComplete(Irp, STATUS_SUCCESS, 0);
    }
    return XdowsBootDispatchPassThrough(DeviceObject, Irp);
}

static
NTSTATUS
XdowsBootDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    PVOID buffer;
    ULONG inputLength;
    ULONG outputLength;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    if (DeviceObject != g_BootContext.ControlDevice) {
        return XdowsBootDispatchPassThrough(DeviceObject, Irp);
    }

    stack = IoGetCurrentIrpStackLocation(Irp);
    buffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_XDOWS_BOOT_REGISTER_CLIENT:
        if (inputLength >= sizeof(XDOWS_BOOT_REGISTER_REQUEST) &&
            outputLength >= sizeof(XDOWS_BOOT_REGISTER_RESPONSE) &&
            buffer != NULL) {
            PXDOWS_BOOT_REGISTER_REQUEST request =
                (PXDOWS_BOOT_REGISTER_REQUEST)buffer;
            ULONG requestorProcessId =
                XdowsBootGetRequestorProcessId(Irp);
            KIRQL oldIrql;

            if (!XdowsBootHeaderIsValid(&request->Header, sizeof(*request))) {
                status = STATUS_REVISION_MISMATCH;
                break;
            }
            if (request->ClientProcessId != requestorProcessId ||
                !NT_SUCCESS(XdowsBootValidateClientProcess(requestorProcessId))) {
                status = STATUS_ACCESS_DENIED;
                break;
            }

            KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
            if (g_BootContext.ClientConnected &&
                g_BootContext.ClientProcessId != requestorProcessId) {
                status = STATUS_DEVICE_BUSY;
            } else {
                PXDOWS_BOOT_REGISTER_RESPONSE response =
                    (PXDOWS_BOOT_REGISTER_RESPONSE)buffer;
                RtlZeroMemory(response, sizeof(*response));
                XdowsBootInitializeHeader(&response->Header, sizeof(*response));
                response->ProtocolVersion = XDOWS_BOOT_PROTOCOL_VERSION;
                response->MaxRequestBytes = XDOWS_BOOT_MAX_REQUEST_BYTES;
                response->MaxPendingBytes = XDOWS_BOOT_MAX_PENDING_BYTES;
                response->DecisionTimeoutMs = XDOWS_BOOT_DECISION_TIMEOUT_MS;
                response->DriverBuildId = XDOWS_BOOT_DRIVER_BUILD_ID;
                g_BootContext.ClientConnected = TRUE;
                g_BootContext.ClientProcessId = requestorProcessId;
                status = STATUS_SUCCESS;
                information = sizeof(*response);
            }
            KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_XDOWS_BOOT_CONFIGURE:
        if (!XdowsBootCallerIsClient(Irp)) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        if (inputLength < sizeof(XDOWS_BOOT_CONFIGURE_REQUEST) || buffer == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            PXDOWS_BOOT_CONFIGURE_REQUEST request =
                (PXDOWS_BOOT_CONFIGURE_REQUEST)buffer;
            KIRQL oldIrql;
            if (!XdowsBootHeaderIsValid(&request->Header, sizeof(*request)) ||
                !XdowsBootRangesAreValid(request)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            status = XdowsBootAttachDisk(request->DiskNumber);
            if (!NT_SUCCESS(status)) {
                break;
            }

            KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
            RtlCopyMemory(
                g_BootContext.Ranges,
                request->Ranges,
                sizeof(XDOWS_BOOT_RAW_RANGE) * request->RangeCount);
            g_BootContext.RangeCount = request->RangeCount;
            g_BootContext.DiskNumber = request->DiskNumber;
            g_BootContext.Configured = TRUE;
            KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
        }
        break;

    case IOCTL_XDOWS_BOOT_GET_NEXT_EVENT:
        if (!XdowsBootCallerIsClient(Irp)) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        if (outputLength < sizeof(XDOWS_BOOT_WRITE_EVENT) || buffer == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = XdowsBootGetNextEvent((PXDOWS_BOOT_WRITE_EVENT)buffer);
        if (NT_SUCCESS(status)) {
            information = sizeof(XDOWS_BOOT_WRITE_EVENT);
        }
        break;

    case IOCTL_XDOWS_BOOT_SUBMIT_DECISION:
        if (!XdowsBootCallerIsClient(Irp)) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        if (inputLength < sizeof(XDOWS_BOOT_DECISION) || buffer == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = XdowsBootSubmitDecision((PXDOWS_BOOT_DECISION)buffer);
        break;

    case IOCTL_XDOWS_BOOT_GET_STATE:
        if (!XdowsBootCallerIsClient(Irp)) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        if (outputLength < sizeof(XDOWS_BOOT_STATE) || buffer == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        XdowsBootGetState((PXDOWS_BOOT_STATE)buffer);
        status = STATUS_SUCCESS;
        information = sizeof(XDOWS_BOOT_STATE);
        break;
    }

    return XdowsBootComplete(Irp, status, information);
}

static
NTSTATUS
XdowsBootDispatchWrite(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    LONGLONG offset;
    ULONG length;
    KIRQL oldIrql;
    PXDOWS_BOOT_PENDING_WRITE pending;
    BOOLEAN reserve = FALSE;
    BOOLEAN clientConnected;

    if (DeviceObject != g_BootContext.FilterDevice ||
        g_BootContext.LowerDevice == NULL) {
        return XdowsBootDispatchUnsupported(DeviceObject, Irp);
    }

    stack = IoGetCurrentIrpStackLocation(Irp);
    offset = stack->Parameters.Write.ByteOffset.QuadPart;
    length = stack->Parameters.Write.Length;
    if (!XdowsBootWriteIntersectsProtectedRange(offset, length)) {
        return XdowsBootDispatchPassThrough(DeviceObject, Irp);
    }

    if (length == 0 || length > XDOWS_BOOT_MAX_REQUEST_BYTES) {
        KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
        g_BootContext.BlockedResourceCount++;
        KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
        XdowsBootLogBlockedWrite(2u, STATUS_INVALID_BUFFER_SIZE, offset, length);
        return XdowsBootComplete(Irp, STATUS_ACCESS_DENIED, 0);
    }

    KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
    clientConnected = g_BootContext.ClientConnected && !g_BootContext.Unloading;
    if (clientConnected &&
        g_BootContext.PendingRequestCount < XDOWS_BOOT_MAX_PENDING_REQUESTS &&
        g_BootContext.PendingBytes <= XDOWS_BOOT_MAX_PENDING_BYTES - length) {
        g_BootContext.PendingRequestCount++;
        g_BootContext.PendingBytes += length;
        if (g_BootContext.PendingRequestCount == 1) {
            KeClearEvent(&g_BootContext.PendingZeroEvent);
        }
        reserve = TRUE;
    } else if (!clientConnected) {
        g_BootContext.BlockedNoClientCount++;
    } else {
        g_BootContext.BlockedResourceCount++;
    }
    KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);

    if (!reserve) {
        XdowsBootLogBlockedWrite(
            clientConnected ? 2u : 1u,
            STATUS_ACCESS_DENIED,
            offset,
            length);
        return XdowsBootComplete(Irp, STATUS_ACCESS_DENIED, 0);
    }

    pending = (PXDOWS_BOOT_PENDING_WRITE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*pending),
        XDOWS_BOOT_POOL_TAG);
    if (pending == NULL) {
        XdowsBootReleasePendingReservation(length);
        XdowsBootLogBlockedWrite(2u, STATUS_INSUFFICIENT_RESOURCES, offset, length);
        return XdowsBootComplete(Irp, STATUS_ACCESS_DENIED, 0);
    }

    RtlZeroMemory(pending, sizeof(*pending));
    pending->Irp = Irp;
    pending->ReservedBytes = length;
    pending->Decision = XdowsBootDecisionBlock;
    XdowsBootInitializeHeader(&pending->Event.Header, sizeof(pending->Event));
    pending->Event.DiskNumber = g_BootContext.DiskNumber;
    pending->Event.ProcessId = XdowsBootGetRequestorProcessId(Irp);
    pending->Event.Offset = offset;
    pending->Event.Length = length;
    KeInitializeEvent(&pending->DecisionEvent, NotificationEvent, FALSE);
    pending->WorkItem = IoAllocateWorkItem(DeviceObject);
    if (pending->WorkItem == NULL) {
        ExFreePoolWithTag(pending, XDOWS_BOOT_POOL_TAG);
        XdowsBootReleasePendingReservation(length);
        XdowsBootLogBlockedWrite(2u, STATUS_INSUFFICIENT_RESOURCES, offset, length);
        return XdowsBootComplete(Irp, STATUS_ACCESS_DENIED, 0);
    }

    IoMarkIrpPending(Irp);
    IoQueueWorkItem(
        pending->WorkItem,
        XdowsBootProcessProtectedWrite,
        DelayedWorkQueue,
        pending);
    return STATUS_PENDING;
}

static
NTSTATUS
XdowsBootDispatchPassThrough(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    if (DeviceObject == g_BootContext.FilterDevice &&
        g_BootContext.LowerDevice != NULL) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(g_BootContext.LowerDevice, Irp);
    }
    return XdowsBootComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static
NTSTATUS
XdowsBootDispatchPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    if (DeviceObject == g_BootContext.FilterDevice &&
        g_BootContext.LowerDevice != NULL) {
        PoStartNextPowerIrp(Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        return PoCallDriver(g_BootContext.LowerDevice, Irp);
    }
    return XdowsBootComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static
VOID
XdowsBootUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symbolicName;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(DriverObject);

    KeAcquireSpinLock(&g_BootContext.Lock, &oldIrql);
    g_BootContext.Unloading = TRUE;
    KeReleaseSpinLock(&g_BootContext.Lock, oldIrql);
    XdowsBootDisconnectClient(0);

    (VOID)KeWaitForSingleObject(
        &g_BootContext.PendingZeroEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL);

    if (g_BootContext.FilterDevice != NULL) {
        if (g_BootContext.LowerDevice != NULL) {
            IoDetachDevice(g_BootContext.LowerDevice);
        }
        IoDeleteDevice(g_BootContext.FilterDevice);
        g_BootContext.FilterDevice = NULL;
        g_BootContext.LowerDevice = NULL;
    }
    if (g_BootContext.TargetFileObject != NULL) {
        ObDereferenceObject(g_BootContext.TargetFileObject);
        g_BootContext.TargetFileObject = NULL;
    }

    RtlInitUnicodeString(&symbolicName, XDOWS_BOOT_SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&symbolicName);
    if (g_BootContext.ControlDevice != NULL) {
        IoDeleteDevice(g_BootContext.ControlDevice);
        g_BootContext.ControlDevice = NULL;
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicName;
    UNICODE_STRING sddl;
    ULONG index;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_BootContext, sizeof(g_BootContext));
    g_BootContext.DriverObject = DriverObject;
    g_BootContext.NextEventId = 1;
    g_BootContext.DiskNumber = MAXULONG;
    KeInitializeSpinLock(&g_BootContext.Lock);
    KeInitializeEvent(&g_BootContext.EventAvailable, SynchronizationEvent, FALSE);
    KeInitializeEvent(&g_BootContext.PendingZeroEvent, NotificationEvent, TRUE);
    InitializeListHead(&g_BootContext.PendingWrites);

    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; index++) {
        DriverObject->MajorFunction[index] = XdowsBootDispatchUnsupported;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = XdowsBootDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = XdowsBootDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = XdowsBootDispatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = XdowsBootDispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = XdowsBootDispatchWrite;
    DriverObject->MajorFunction[IRP_MJ_READ] = XdowsBootDispatchPassThrough;
    DriverObject->MajorFunction[IRP_MJ_PNP] = XdowsBootDispatchPassThrough;
    DriverObject->MajorFunction[IRP_MJ_POWER] = XdowsBootDispatchPower;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = XdowsBootDispatchPassThrough;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = XdowsBootDispatchPassThrough;
    DriverObject->MajorFunction[IRP_MJ_SCSI] = XdowsBootDispatchPassThrough;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = XdowsBootDispatchPassThrough;
    DriverObject->DriverUnload = XdowsBootUnload;

    RtlInitUnicodeString(&deviceName, XDOWS_BOOT_DEVICE_NAME);
    RtlInitUnicodeString(
        &sddl,
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &GUID_DEVCLASS_XDOWS_BOOT_FILTER,
        &g_BootContext.ControlDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_BootContext.ControlDevice->Flags |= DO_BUFFERED_IO;
    RtlInitUnicodeString(&symbolicName, XDOWS_BOOT_SYMBOLIC_NAME);
    status = IoCreateSymbolicLink(&symbolicName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_BootContext.ControlDevice);
        g_BootContext.ControlDevice = NULL;
        return status;
    }

    g_BootContext.ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
