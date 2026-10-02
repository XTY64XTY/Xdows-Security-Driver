/*++

Module Name:

    codeintegrity.h

Abstract:

    Kernel-mode Authenticode verification through the Code Integrity module
    (ci.dll). Used by the injection module to recognize signed source
    processes so legitimate cross-process access does not reach the user
    decision path.

Environment:

    Kernel-mode Driver Framework

--*/

#pragma once

EXTERN_C_START

//
// Resolve the ci.dll exports. Never fails the caller: when CI cannot be
// used, CodeIntegrityIsAvailable() returns FALSE and callers must fall
// back to their own policy.
//
NTSTATUS
CodeIntegrityInitialize(
    VOID
    );

VOID
CodeIntegrityShutdown(
    VOID
    );

BOOLEAN
CodeIntegrityIsAvailable(
    VOID
    );

//
// Query the cached Authenticode verdict for the image backing Process.
// Validation is performed asynchronously when processes are created; this
// function never performs file I/O and is safe in an Ob pre-operation
// callback. FALSE means that no verdict is available, not that the image is
// unsigned.
//
BOOLEAN
CodeIntegrityQueryProcessTrust(
    _In_ PEPROCESS Process,
    _Out_ PBOOLEAN Trusted
    );

EXTERN_C_END
