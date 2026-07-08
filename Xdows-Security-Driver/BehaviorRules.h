/*++

Module Name:

    behaviorrules.h

Abstract:

    In-kernel command-line behavior inspection for process-launch events.

    Provides a fast-path rule engine that scans the command line of a newly
    launched process for high-confidence malicious patterns (VSS deletion,
    hidden/encoded PowerShell, execution-policy bypass, download-and-execute,
    suspicious LOLBin usage). A hit allows the caller to block the launch
    immediately without waiting for the user-mode model verdict, which is
    critical for time-sensitive attacks such as ransomware shadow-copy
    deletion.

    Rules that could match legitimate use (-enc, -ExecutionPolicy Bypass)
    are scoped to command lines that contain "powershell" or "pwsh" so
    unrelated tools accepting similar arguments are not affected.

Environment:

    Kernel-mode Driver Framework

--*/

#pragma once

EXTERN_C_START

//
// Behavior categories matched by the rule engine. The numeric values are
// stable across kernel/user releases: user mode can log them directly.
//
typedef enum _XDOWS_BEHAVIOR_TYPE {
    XdowsBehaviorNone = 0,
    XdowsBehaviorVssDeletion = 1,          // vssadmin delete shadows / wmic shadowcopy delete
    XdowsBehaviorHiddenPowerShell = 2,     // -windowstyle hidden / -w hidden
    XdowsBehaviorEncodedCommand = 3,       // -enc / -encodedcommand
    XdowsBehaviorPolicyBypass = 4,         // -executionpolicy bypass / -ep bypass
    XdowsBehaviorDownloadExecute = 5,      // DownloadString / Invoke-WebRequest / certutil -urlcache
    XdowsBehaviorLolbinAbuse = 6           // mshta with remote payload / rundll32 with URL
} XDOWS_BEHAVIOR_TYPE, *PXDOWS_BEHAVIOR_TYPE;

//
// Inspect a command line for malicious patterns.
//
// Returns XdowsBehaviorNone when no rule matches, or a specific behavior
// type. The comparison is case-insensitive. The caller must NOT free the
// command line buffer before this function returns.
//
XDOWS_BEHAVIOR_TYPE
XdowsBehaviorInspectCommandLine(
    _In_opt_ PCUNICODE_STRING CommandLine
    );

//
// Convert a behavior type to a human-readable wide string for logging.
//
PCWSTR
XdowsBehaviorTypeName(
    _In_ XDOWS_BEHAVIOR_TYPE Type
    );

EXTERN_C_END
