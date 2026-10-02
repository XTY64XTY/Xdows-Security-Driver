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
BehaviorProtectInitialize(
    VOID
    );

VOID
BehaviorProtectShutdown(
    VOID
    );

BOOLEAN
BehaviorProtectIsEnabled(
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
BehaviorInspectCommandLine(
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
BehaviorInspectParentChain(
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
BehaviorImageNameIsScriptHost(
    _In_ PCSTR ImageName
    );

//
// ---------------------------------------------------------------------------
// Declarative rule interpreter (capability 0x1000) and initiator exclusion
// list (capability 0x2000).
// ---------------------------------------------------------------------------
//

//
// Replace the declarative rule set. The whole request is validated first and
// rejected as a unit on any malformed rule, so a partially applied set can
// never be evaluated. Enabled == 0 or RuleCount == 0 clears the set.
//
NTSTATUS
BehaviorConfigureRules(
    _In_ PXDOWS_SECURITY_BEHAVIOR_RULE_REQUEST Request
    );

//
// Replace the initiator exclusion list. Count == 0 clears it.
//
NTSTATUS
BehaviorConfigureInitiatorExclusions(
    _In_ PXDOWS_SECURITY_INITIATOR_EXCLUSION_REQUEST Request
    );

//
// TRUE when the acting process matches an exclusion entry carrying Scope
// (XDOWS_SECURITY_EXCLUSION_SCOPE_*). Callers use this to skip the user-mode
// consultation for that gate. The critical in-kernel denials and the fixed
// command-line threat rules are never bypassed by an exclusion.
//
BOOLEAN
BehaviorIsInitiatorExcluded(
    _In_ ULONG Scope,
    _In_opt_ PCUNICODE_STRING ActorPath,
    _In_opt_ PCSTR ActorImageName
    );

//
// Evaluate the declarative rule set for one operation.
//
// ActorPath/ActorImageName describe the acting process, CommandLine and
// TargetPath are optional (NULL when the operation has no such dimension),
// Operation is one XDOWS_SECURITY_RULE_OPERATION_* value, and ActorProcessId
// keys the per-process rate window for rules that declare a Threshold.
//
// Returns TRUE when a rule matched (after the optional rate gate) and fills
// the out parameters with the rule id, its flags, and the behavior type the
// match must be reported as. Safe at PASSIVE_LEVEL.
//
BOOLEAN
BehaviorEvaluateCustomRules(
    _In_opt_ PCUNICODE_STRING ActorPath,
    _In_opt_ PCSTR ActorImageName,
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_opt_ PCUNICODE_STRING TargetPath,
    _In_ ULONG Operation,
    _In_ ULONG ActorProcessId,
    _Out_opt_ PULONG MatchedRuleId,
    _Out_opt_ PULONG MatchedRuleFlags,
    _Out_opt_ PULONG MatchedBehaviorType
    );

//
// Convert a behavior type to a human-readable wide string for logging.
//
PCWSTR
BehaviorTypeName(
    _In_ XDOWS_SECURITY_BEHAVIOR_TYPE Type
    );

EXTERN_C_END
