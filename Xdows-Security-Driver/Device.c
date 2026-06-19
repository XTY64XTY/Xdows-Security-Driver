/*++

Module Name:

    device.c - Device handling events for example driver.

Abstract:

   This file contains the device entry points and callbacks.
    
Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "device.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, XdowsSecurityDriverCreateControlDevice)
#pragma alloc_text (PAGE, XdowsSecurityDriverEvtDeviceContextCleanup)
#endif

static
NTSTATUS
XdowsSecurityDriverInitializeDevice(
    _In_ WDFDEVICE Device,
    _In_ BOOLEAN CreateDeviceInterface
    )
{
    NTSTATUS status;
    UNICODE_STRING symbolicName;

    PAGED_CODE();

    RtlInitUnicodeString(&symbolicName, XDOWS_SECURITY_SYMBOLIC_NAME);
    status = WdfDeviceCreateSymbolicLink(Device, &symbolicName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (CreateDeviceInterface) {
        status = WdfDeviceCreateDeviceInterface(
            Device,
            &GUID_DEVINTERFACE_XdowsSecurityDriver,
            NULL);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    status = XdowsSecurityDriverQueueInitialize(Device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = XdowsInitializeGlobalContext(Device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = XdowsModulesInitialize();
    if (!NT_SUCCESS(status)) {
        XdowsShutdownGlobalContext();
    }

    return status;
}

NTSTATUS
XdowsSecurityDriverCreateControlDevice(
    _In_ WDFDRIVER Driver
    )
{
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    PWDFDEVICE_INIT deviceInit;
    WDFDEVICE device;
    PDEVICE_CONTEXT deviceContext;
    NTSTATUS status;
    UNICODE_STRING deviceName;

    PAGED_CODE();

    deviceInit = WdfControlDeviceInitAllocate(
        Driver,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&deviceName, XDOWS_SECURITY_DEVICE_NAME);
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);
    deviceAttributes.EvtCleanupCallback = XdowsSecurityDriverEvtDeviceContextCleanup;

    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    deviceContext = DeviceGetContext(device);
    deviceContext->PrivateDeviceData = 0;

    status = XdowsSecurityDriverInitializeDevice(device, FALSE);
    if (!NT_SUCCESS(status)) {
        WdfObjectDelete(device);
        return status;
    }

    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

VOID
XdowsSecurityDriverEvtDeviceContextCleanup(
    _In_ WDFOBJECT DeviceObject
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    XdowsModulesShutdown();
    XdowsShutdownGlobalContext();
}
