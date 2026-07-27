/*++

Module Name:

    behaviorrules.h

Abstract:

    In-kernel command-line behavior inspection for process-launch events.

    Provides a fast-path rule engine that scans the command line of a newly
    launched process for high-confidence malicious patterns (VSS deletion,
    hidden/encoded PowerShell, execution-policy bypass, download-and-execute,
    suspicious LOLBin usage). Hits are published as confirmed behavior events
    so user mode can hold the originating operation for an explicit decision.

    Rules that could match legitimate use (-enc, -ExecutionPolicy Bypass)
    are scoped to command lines that contain "powershell" or "pwsh" so
    unrelated tools accepting similar arguments are not affected.

Environment:

    Kernel-mode Driver Framework

--*/

#pragma once

EXTERN_C_START

//
// The shared behavior categories are declared in Public.h so user mode sees
// the same stable numeric values as the kernel rule engine.

NTSTATUS
XdowsBehaviorProtectInitialize(
    VOID
    );

VOID
XdowsBehaviorProtectShutdown(
    VOID
    );

BOOLEAN
XdowsBehaviorProtectIsEnabled(
    VOID
    );

//
// Inspect a command line for malicious patterns.
//
// Returns XdowsSecurityBehaviorNone when no rule matches, or a specific behavior
// type. The comparison is case-insensitive. The caller must NOT free the
// command line buffer before this function returns.
//
XDOWS_SECURITY_BEHAVIOR_TYPE
XdowsBehaviorInspectCommandLine(
    _In_opt_ PCUNICODE_STRING CommandLine
    );

//
// Convert a behavior type to a human-readable wide string for logging.
//
PCWSTR
XdowsBehaviorTypeName(
    _In_ XDOWS_SECURITY_BEHAVIOR_TYPE Type
    );

EXTERN_C_END
