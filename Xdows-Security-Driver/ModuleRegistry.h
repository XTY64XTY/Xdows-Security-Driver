/*++

Module Name:

    moduleregistry.h

Abstract:

    Ordered protection module initialization and shutdown.

--*/

#pragma once

EXTERN_C_START

NTSTATUS
XdowsModulesInitialize(
    VOID
    );

VOID
XdowsModulesShutdown(
    VOID
    );

EXTERN_C_END
