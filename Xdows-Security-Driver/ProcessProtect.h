/*++

Module Name:

    processprotect.h

Abstract:

    Process creation interception module.

--*/

#pragma once

EXTERN_C_START

NTSTATUS
XdowsProcessProtectInitialize(
    VOID
    );

VOID
XdowsProcessProtectShutdown(
    VOID
    );

EXTERN_C_END
