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
RegistryProtectInitialize(
    VOID
    );

VOID
RegistryProtectShutdown(
    VOID
    );

NTSTATUS
RegistryProtectConfigure(
    _In_ PXDOWS_SECURITY_REGISTRY_PROTECTION_REQUEST Request
    );

BOOLEAN
RegistryProtectIsEnabled(
    VOID
    );

EXTERN_C_END
