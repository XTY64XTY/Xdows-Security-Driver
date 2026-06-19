/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>
#include <initguid.h>

#include "device.h"
#include "drivercontext.h"
#include "log.h"
#include "moduleregistry.h"
#include "processprotect.h"
#include "queue.h"
#include "trace.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD XdowsSecurityDriverEvtDriverUnload;
EVT_WDF_OBJECT_CONTEXT_CLEANUP XdowsSecurityDriverEvtDriverContextCleanup;

EXTERN_C_END
