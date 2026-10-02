/*++

Module Name:

    processprotect.h

Abstract:

    Process creation interception module.

--*/

#pragma once

EXTERN_C_START

NTSTATUS
ProcessProtectInitialize(
    VOID
    );

VOID
ProcessProtectShutdown(
    VOID
    );

EXTERN_C_END
