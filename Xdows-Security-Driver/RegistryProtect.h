/*++

Module Name:

    RegistryProtect.h

Abstract:

    Public interface for the R0 registry protection module.

Environment:

    Kernel mode.

--*/

#pragma once

#include "public.h"

EXTERN_C_START

NTSTATUS
XdowsRegistryProtectInitialize(
    VOID
    );

VOID
XdowsRegistryProtectShutdown(
    VOID
    );

NTSTATUS
XdowsRegistryProtectConfigure(
    _In_ PXDOWS_SECURITY_REGISTRY_PROTECTION_REQUEST Request
    );

BOOLEAN
XdowsRegistryProtectIsEnabled(
    VOID
    );

EXTERN_C_END
