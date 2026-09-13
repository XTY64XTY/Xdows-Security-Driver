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
// Inspect a process-launch parent/child chain for the classic document or
// browser exploit pattern: a document viewer / browser / email client parent
// spawning a script host child (cmd, powershell, wscript, mshta, rundll32).
//
// ParentProcessId must be the PID of the acting parent. The child image name
// is matched case-insensitively against the script-host allowlist. Returns
// XdowsSecurityBehaviorParentProcessChain on a match, else None. Safe at
// PASSIVE_LEVEL; performs a bounded PID->image lookup.
//
XDOWS_SECURITY_BEHAVIOR_TYPE
XdowsBehaviorInspectParentChain(
    _In_ ULONG ParentProcessId,
    _In_ PCUNICODE_STRING ChildImageName
    );

//
// TRUE if the EPROCESS 15-char image name (PsGetProcessImageFileName, NOT
// guaranteed null-terminated) belongs to a Windows script host
// (cmd/powershell/pwsh/wscript/cscript/mshta/rundll32/regsvr32). Used by
// the file minifilter to scope the system-directory ransomware monitor.
// Comparison is bounded to 15 chars and case-insensitive.
//
BOOLEAN
XdowsBehaviorImageNameIsScriptHost(
    _In_ PCSTR ImageName
    );

//
// Convert a behavior type to a human-readable wide string for logging.
//
PCWSTR
XdowsBehaviorTypeName(
    _In_ XDOWS_SECURITY_BEHAVIOR_TYPE Type
    );

EXTERN_C_END
