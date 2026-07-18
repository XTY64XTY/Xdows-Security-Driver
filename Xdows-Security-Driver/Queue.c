/*++

Module Name:

    queue.c

Abstract:

    This file contains the queue entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "fileprotect.h"
#include "processmanager.h"
#include "selfprotect.h"
#include "tokenauth.h"
#include "queue.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, XdowsSecurityDriverQueueInitialize)
#endif

NTSTATUS
XdowsSecurityDriverQueueInitialize(
    _In_ WDFDEVICE Device
    )
/*++

Routine Description:

     The I/O dispatch callbacks for the frameworks device object
     are configured in this function.

     A single default I/O Queue is configured for parallel request
     processing, and a driver context memory allocation is created
     to hold our structure QUEUE_CONTEXT.

Arguments:

    Device - Handle to a framework device object.

Return Value:

    VOID

--*/
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttributes;

    PAGED_CODE();

    //
    // Configure a default queue so that requests that are not
    // configure-fowarded using WdfDeviceConfigureRequestDispatching to goto
    // other queues get dispatched here.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
         &queueConfig,
        WdfIoQueueDispatchParallel
        );

    queueConfig.PowerManaged = WdfFalse;
    queueConfig.EvtIoDeviceControl = XdowsSecurityDriverEvtIoDeviceControl;
    queueConfig.EvtIoStop = XdowsSecurityDriverEvtIoStop;

    WDF_OBJECT_ATTRIBUTES_INIT(&queueAttributes);
    queueAttributes.ExecutionLevel = WdfExecutionLevelPassive;

    status = WdfIoQueueCreate(
                 Device,
                 &queueConfig,
                 &queueAttributes,
                 &queue
                 );

    if(!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfIoQueueCreate failed %!STATUS!", status);
        return status;
    }

    return status;
}

static
ULONG
XdowsGetRequestorProcessId(
    _In_ WDFREQUEST Request
    )
{
    PIRP irp;
    PETHREAD requestorThread;

    irp = WdfRequestWdmGetIrp(Request);
    if (irp == NULL) {
        return 0;
    }

    requestorThread = irp->Tail.Overlay.Thread;
    return requestorThread != NULL
        ? HandleToULong(PsGetThreadProcessId(requestorThread))
        : 0;
}

static
NTSTATUS
XdowsRequireRegisteredClient(
    _In_ WDFREQUEST Request,
    _Out_opt_ PULONG RequestorProcessId
    )
{
    ULONG processId;

    processId = XdowsGetRequestorProcessId(Request);
    if (RequestorProcessId != NULL) {
        *RequestorProcessId = processId;
    }

    return XdowsIsRegisteredClientProcess(processId)
        ? STATUS_SUCCESS
        : STATUS_ACCESS_DENIED;
}

static
NTSTATUS
XdowsRequireProtectedClient(
    _In_ WDFREQUEST Request,
    _Out_opt_ PULONG RequestorProcessId
    )
{
    ULONG processId;
    NTSTATUS status;

    status = XdowsRequireRegisteredClient(Request, &processId);
    if (RequestorProcessId != NULL) {
        *RequestorProcessId = processId;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return XdowsSelfProtectIsProcessProtected(ULongToHandle(processId))
        ? STATUS_SUCCESS
        : STATUS_ACCESS_DENIED;
}

VOID
XdowsSecurityDriverEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
/*++

Routine Description:

    This event is invoked when the framework receives IRP_MJ_DEVICE_CONTROL request.

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    OutputBufferLength - Size of the output buffer in bytes

    InputBufferLength - Size of the input buffer in bytes

    IoControlCode - I/O control code.

Return Value:

    VOID

--*/
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t information = 0;

    UNREFERENCED_PARAMETER(Queue);

    TraceEvents(TRACE_LEVEL_INFORMATION,
                TRACE_QUEUE,
                "%!FUNC! Request 0x%p OutputBufferLength %d InputBufferLength %d IoControlCode %d",
                Request, (int) OutputBufferLength, (int) InputBufferLength, IoControlCode);

    switch (IoControlCode) {
    case IOCTL_XDOWS_SECURITY_REGISTER_CLIENT:
    {
        PXDOWS_SECURITY_REGISTER_REQUEST input;
        PXDOWS_SECURITY_REGISTER_RESPONSE output;
        ULONG requestorProcessId;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*input), (PVOID*)&input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*output), (PVOID*)&output, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        requestorProcessId = XdowsGetRequestorProcessId(Request);
        if (requestorProcessId == 0 ||
            input->ClientProcessId != requestorProcessId) {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        status = XdowsRegisterClient(input, requestorProcessId, output);
        if (NT_SUCCESS(status)) {
            XdowsSecurityDriverRevokeUnload();
            XdowsFileProtectRevokeUnload();
            information = sizeof(*output);
        }
        break;
    }
    case IOCTL_XDOWS_SECURITY_HEARTBEAT:
    {
        PXDOWS_SECURITY_HEARTBEAT_REQUEST input;

        status = XdowsRequireRegisteredClient(Request, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*input), (PVOID*)&input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = XdowsHeartbeat(input);
        break;
    }
    case IOCTL_XDOWS_SECURITY_GET_NEXT_EVENT:
    {
        PXDOWS_SECURITY_EVENT output;

        UNREFERENCED_PARAMETER(InputBufferLength);

        status = XdowsRequireRegisteredClient(Request, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*output), (PVOID*)&output, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = XdowsGetNextPendingEvent(output);
        if (NT_SUCCESS(status)) {
            information = sizeof(*output);
        }
        break;
    }
    case IOCTL_XDOWS_SECURITY_SUBMIT_DECISION:
    {
        PXDOWS_SECURITY_DECISION input;

        status = XdowsRequireRegisteredClient(Request, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*input), (PVOID*)&input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = XdowsSubmitDecision(input);
        break;
    }
    case IOCTL_XDOWS_SECURITY_GET_STATE:
    {
        PXDOWS_SECURITY_STATE output;

        UNREFERENCED_PARAMETER(OutputBufferLength);

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*output), (PVOID*)&output, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        XdowsGetState(output);
        status = STATUS_SUCCESS;
        information = sizeof(*output);
        break;
    }
    case IOCTL_XDOWS_SECURITY_GET_NEXT_LOG:
    {
        PXDOWS_SECURITY_LOG_ENTRY output;

        status = XdowsRequireRegisteredClient(Request, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*output), (PVOID*)&output, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = XdowsLogGetNext(output);
        if (NT_SUCCESS(status)) {
            information = sizeof(*output);
        }
        break;
    }
    case IOCTL_XDOWS_SECURITY_DISCONNECT_CLIENT:
        status = XdowsRequireRegisteredClient(Request, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Bridge", L"Client disconnected.");
        XdowsDisconnectClient();
        status = STATUS_SUCCESS;
        break;
    case IOCTL_XDOWS_SECURITY_REGISTER_PROTECTED_PROCESS:
    {
        PXDOWS_SECURITY_PROTECTED_PROCESS_REQUEST input;
        ULONG requestorProcessId;

        status = XdowsRequireRegisteredClient(Request, &requestorProcessId);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*input), (PVOID*)&input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (input->Header.Size != sizeof(*input) ||
            input->Header.Version != XDOWS_SECURITY_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
            break;
        }
        if (input->ProcessId != requestorProcessId) {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        status = XdowsSelfProtectRegisterProcess(input->ProcessId, input->MainThreadId, input->Flags);
        break;
    }
    case IOCTL_XDOWS_SECURITY_SET_VOLUNTARY_EXIT:
    {
        PXDOWS_SECURITY_VOLUNTARY_EXIT_REQUEST input;
        ULONG requestorProcessId;

        status = XdowsRequireRegisteredClient(Request, &requestorProcessId);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*input), (PVOID*)&input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (input->Header.Size != sizeof(*input) ||
            input->Header.Version != XDOWS_SECURITY_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
            break;
        }
        if (input->ProcessId != requestorProcessId) {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        status = XdowsSelfProtectSetVoluntaryExit(input->ProcessId, input->IsVoluntaryExit != 0);
        break;
    }
    case IOCTL_XDOWS_SECURITY_AUTHORIZED_SHUTDOWN:
    {
        PXDOWS_SECURITY_SHUTDOWN_REQUEST input;

        status = XdowsRequireProtectedClient(Request, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*input), (PVOID*)&input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (input->Header.Size != sizeof(*input) ||
            input->Header.Version != XDOWS_SECURITY_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
            break;
        }

        if (!XdowsTokenAuthValidate(input->ShutdownToken)) {
            XdowsLogWrite(XdowsSecurityLogWarning, 0, 0, L"TokenAuth", L"Authorized shutdown denied.");
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (!XdowsSecurityDriverAuthorizeUnload()) {
            XdowsLogWrite(
                XdowsSecurityLogError,
                0,
                0,
                L"TokenAuth",
                L"Authorized shutdown could not enable the SCM unload entry.");
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"TokenAuth", L"Authorized shutdown accepted.");
        XdowsFileProtectAuthorizeUnload();
        XdowsSelfProtectClearRegistration();
        XdowsTokenAuthInvalidate();
        XdowsDisconnectClient();
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_XDOWS_SECURITY_SET_STARTUP_PROTECTION:
    {
        PXDOWS_SECURITY_STARTUP_PROTECTION_REQUEST input;
        ULONG requestorProcessId;

        status = XdowsRequireProtectedClient(Request, &requestorProcessId);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveInputBuffer(
            Request,
            sizeof(*input),
            (PVOID*)&input,
            NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (input->Header.Size != sizeof(*input) ||
            input->Header.Version != XDOWS_SECURITY_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
            break;
        }
        if (input->ProcessId != requestorProcessId || input->Enabled > 1) {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        status = XdowsSelfProtectSetStartupProtection(
            input->ProcessId,
            input->Enabled != 0);
        break;
    }
    case IOCTL_XDOWS_SECURITY_QUERY_PROCESSES:
    {
        PXDOWS_SECURITY_PROCESS_QUERY_REQUEST input;
        XDOWS_SECURITY_PROCESS_QUERY_REQUEST requestCopy;
        PXDOWS_SECURITY_PROCESS_QUERY_RESPONSE output;

        status = XdowsRequireProtectedClient(Request, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*input), (PVOID*)&input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        if (input->Header.Size != sizeof(*input) ||
            input->Header.Version != XDOWS_SECURITY_PROTOCOL_VERSION ||
            !XdowsTokenAuthValidate(input->AuthorizationToken)) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        RtlCopyMemory(&requestCopy, input, sizeof(requestCopy));

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*output), (PVOID*)&output, NULL);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(requestCopy.AuthorizationToken, sizeof(requestCopy.AuthorizationToken));
            break;
        }

        status = XdowsProcessManagerQuery(&requestCopy, output);
        RtlSecureZeroMemory(requestCopy.AuthorizationToken, sizeof(requestCopy.AuthorizationToken));
        if (NT_SUCCESS(status)) {
            information = sizeof(*output);
        }
        break;
    }
    case IOCTL_XDOWS_SECURITY_OPERATE_PROCESS:
    {
        PXDOWS_SECURITY_PROCESS_OPERATION_REQUEST input;
        ULONG requestorProcessId;

        status = XdowsRequireProtectedClient(Request, &requestorProcessId);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*input), (PVOID*)&input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        if (input->Header.Size != sizeof(*input) ||
            input->Header.Version != XDOWS_SECURITY_PROTOCOL_VERSION ||
            !XdowsTokenAuthValidate(input->AuthorizationToken)) {
            XdowsLogWrite(XdowsSecurityLogWarning, 0, 0, L"ProcessManager",
                L"Process operation authorization denied.");
            status = STATUS_ACCESS_DENIED;
            break;
        }

        status = XdowsProcessManagerOperate(requestorProcessId, input);
        RtlSecureZeroMemory(input->AuthorizationToken, sizeof(input->AuthorizationToken));
        if (NT_SUCCESS(status)) {
            XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"ProcessManager",
                L"Authorized process operation completed.");
        } else {
            XdowsLogWriteStatus(XdowsSecurityLogWarning, 0, 0, L"ProcessManager",
                L"Authorized process operation failed", status);
        }
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, information);
}

VOID
XdowsSecurityDriverEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
/*++

Routine Description:

    This event is invoked for a power-managed queue before the device leaves the working state (D0).

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    ActionFlags - A bitwise OR of one or more WDF_REQUEST_STOP_ACTION_FLAGS-typed flags
                  that identify the reason that the callback function is being called
                  and whether the request is cancelable.

Return Value:

    VOID

--*/
{
    TraceEvents(TRACE_LEVEL_INFORMATION, 
                TRACE_QUEUE, 
                "%!FUNC! Queue 0x%p, Request 0x%p ActionFlags %d", 
                Queue, Request, ActionFlags);

    //
    // In most cases, the EvtIoStop callback function completes, cancels, or postpones
    // further processing of the I/O request.
    //
    // Typically, the driver uses the following rules:
    //
    // - If the driver owns the I/O request, it calls WdfRequestUnmarkCancelable
    //   (if the request is cancelable) and either calls WdfRequestStopAcknowledge
    //   with a Requeue value of TRUE, or it calls WdfRequestComplete with a
    //   completion status value of STATUS_SUCCESS or STATUS_CANCELLED.
    //
    //   Before it can call these methods safely, the driver must make sure that
    //   its implementation of EvtIoStop has exclusive access to the request.
    //
    //   In order to do that, the driver must synchronize access to the request
    //   to prevent other threads from manipulating the request concurrently.
    //   The synchronization method you choose will depend on your driver's design.
    //
    //   For example, if the request is held in a shared context, the EvtIoStop callback
    //   might acquire an internal driver lock, take the request from the shared context,
    //   and then release the lock. At this point, the EvtIoStop callback owns the request
    //   and can safely complete or requeue the request.
    //
    // - If the driver has forwarded the I/O request to an I/O target, it either calls
    //   WdfRequestCancelSentRequest to attempt to cancel the request, or it postpones
    //   further processing of the request and calls WdfRequestStopAcknowledge with
    //   a Requeue value of FALSE.
    //
    // A driver might choose to take no action in EvtIoStop for requests that are
    // guaranteed to complete in a small amount of time.
    //
    // In this case, the framework waits until the specified request is complete
    // before moving the device (or system) to a lower power state or removing the device.
    // Potentially, this inaction can prevent a system from entering its hibernation state
    // or another low system power state. In extreme cases, it can cause the system
    // to crash with bugcheck code 9F.
    //

    return;
}
