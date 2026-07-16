/*++

Module Name:

    driver.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "driver.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XdowsSecurityDriverEvtDriverUnload)
#pragma alloc_text (PAGE, XdowsSecurityDriverEvtDriverContextCleanup)
#endif

typedef struct _XDOWS_DRIVER_UNLOAD_GUARD {
    PDRIVER_OBJECT DriverObject;
    PDRIVER_UNLOAD FrameworkUnload;
    volatile LONG Initialized;
} XDOWS_DRIVER_UNLOAD_GUARD, *PXDOWS_DRIVER_UNLOAD_GUARD;

static XDOWS_DRIVER_UNLOAD_GUARD g_DriverUnloadGuard;

//
// KMDF's EvtDriverUnload returns VOID, so it is too late to reject an SCM
// NtUnloadDriver request once that callback starts. Preserve the framework
// thunk but hide it from the I/O manager until the registered client proves
// possession of the one-time shutdown token.
//
NTSTATUS
XdowsSecurityDriverLockUnload(
    _Inout_ PDRIVER_OBJECT DriverObject
    )
{
    PDRIVER_UNLOAD frameworkUnload;

    if (DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&g_DriverUnloadGuard.Initialized, 0, 0) != 0) {
        return g_DriverUnloadGuard.DriverObject == DriverObject
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
    }

    frameworkUnload = DriverObject->DriverUnload;
    if (frameworkUnload == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    g_DriverUnloadGuard.DriverObject = DriverObject;
    g_DriverUnloadGuard.FrameworkUnload = frameworkUnload;
    (VOID)InterlockedExchangePointer(
        (PVOID volatile*)&DriverObject->DriverUnload,
        NULL);
    (VOID)InterlockedExchange(&g_DriverUnloadGuard.Initialized, 1);

    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_DRIVER,
        "SCM driver unload locked until token authorization");
    return STATUS_SUCCESS;
}

BOOLEAN
XdowsSecurityDriverAuthorizeUnload(
    VOID
    )
{
    PVOID previous;

    if (InterlockedCompareExchange(&g_DriverUnloadGuard.Initialized, 0, 0) == 0 ||
        g_DriverUnloadGuard.DriverObject == NULL ||
        g_DriverUnloadGuard.FrameworkUnload == NULL) {
        return FALSE;
    }

    previous = InterlockedCompareExchangePointer(
        (PVOID volatile*)&g_DriverUnloadGuard.DriverObject->DriverUnload,
        (PVOID)g_DriverUnloadGuard.FrameworkUnload,
        NULL);
    if (previous != NULL &&
        previous != (PVOID)g_DriverUnloadGuard.FrameworkUnload) {
        return FALSE;
    }

    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_DRIVER,
        "SCM driver unload enabled by authorized shutdown token");
    return TRUE;
}

VOID
XdowsSecurityDriverRevokeUnload(
    VOID
    )
{
    if (InterlockedCompareExchange(&g_DriverUnloadGuard.Initialized, 0, 0) == 0 ||
        g_DriverUnloadGuard.DriverObject == NULL) {
        return;
    }

    (VOID)InterlockedExchangePointer(
        (PVOID volatile*)&g_DriverUnloadGuard.DriverObject->DriverUnload,
        NULL);
    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_DRIVER,
        "SCM driver unload authorization revoked");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:
    DriverEntry initializes the driver and is the first routine called by the
    system after the driver is loaded. DriverEntry specifies the other entry
    points in the function driver, such as EvtDevice and DriverUnload.

Parameters Description:

    DriverObject - represents the instance of the function driver that is loaded
    into memory. DriverEntry must initialize members of DriverObject before it
    returns to the caller. DriverObject is allocated by the system before the
    driver is loaded, and it is released by the system after the system unloads
    the function driver from memory.

    RegistryPath - represents the driver specific path in the Registry.
    The function driver can use the path to store driver related data between
    reboots. The path does not store hardware instance specific data.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;

    //
    // Initialize WPP Tracing
    //
    WPP_INIT_TRACING(DriverObject, RegistryPath);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Register a cleanup callback so that we can call WPP_CLEANUP when
    // the framework driver object is deleted during driver unload.
    //
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = XdowsSecurityDriverEvtDriverContextCleanup;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = XdowsSecurityDriverEvtDriverUnload;

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             &attributes,
                             &config,
                             &driver
                             );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    status = XdowsSecurityDriverCreateControlDevice(driver);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Create control device failed %!STATUS!", status);
        WdfObjectDelete(driver);
        return status;
    }

    status = XdowsSecurityDriverLockUnload(DriverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Lock driver unload failed %!STATUS!", status);
        WdfObjectDelete(driver);
        return status;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");

    return status;
}

VOID
XdowsSecurityDriverEvtDriverUnload(
    _In_ WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");
    (VOID)InterlockedExchange(&g_DriverUnloadGuard.Initialized, 0);
    g_DriverUnloadGuard.DriverObject = NULL;
    g_DriverUnloadGuard.FrameworkUnload = NULL;
    XdowsModulesShutdown();
    XdowsShutdownGlobalContext();
}

VOID
XdowsSecurityDriverEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
/*++
Routine Description:

    Free all the resources allocated in DriverEntry.

Arguments:

    DriverObject - handle to a WDF Driver object.

Return Value:

    VOID.

--*/
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Stop WPP Tracing
    //
    WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)DriverObject));
}
