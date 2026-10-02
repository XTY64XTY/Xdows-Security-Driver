/*++

Module Name:

    moduleregistry.h

Abstract:

    Ordered protection module initialization and shutdown.

--*/

#pragma once

EXTERN_C_START

NTSTATUS
ModulesInitialize(
    VOID
    );

VOID
ModulesShutdown(
    VOID
    );

ULONG
ModulesGetActiveMask(
    VOID
    );

EXTERN_C_END
