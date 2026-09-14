/*++

Module Name:

    public.h

Abstract:

    Shared protocol declarations for the Xdows Security driver bridge.

Environment:

    User and kernel mode.

--*/

#pragma once

#define XDOWS_SECURITY_PROTOCOL_VERSION 9u
#define XDOWS_SECURITY_DRIVER_BUILD_ID 2026081603ULL
#define XDOWS_SECURITY_EVENT_TYPE_COUNT 12u
#define XDOWS_SECURITY_CAP_PRIORITY_QUEUE 0x00000001u
#define XDOWS_SECURITY_CAP_DIRTY_WRITE_COALESCING 0x00000002u
#define XDOWS_SECURITY_CAP_BUILD_ID 0x00000004u
#define XDOWS_SECURITY_CAP_STARTUP_SELF_PROTECT 0x00000008u
#define XDOWS_SECURITY_CAP_USER_DECISION_HOLD 0x00000010u
#define XDOWS_SECURITY_CAP_PROCESS_MANAGEMENT 0x00000020u
#define XDOWS_SECURITY_CAP_ENHANCED_SELF_PROTECT 0x00000040u
#define XDOWS_SECURITY_CAP_R0_BEHAVIOR_PROTECTION 0x00000080u
#define XDOWS_SECURITY_CAP_R0_BOOT_PROTECTION 0x00000100u
#define XDOWS_SECURITY_CAP_R0_REGISTRY_PROTECTION 0x00000200u
#define XDOWS_SECURITY_CAP_ASYNC_REVIEW 0x00000400u
#define XDOWS_SECURITY_CAP_EVENT_BATCH 0x00000800u
#define XDOWS_SECURITY_CAP_RULE_INTERPRETER 0x00001000u
#define XDOWS_SECURITY_CAP_INITIATOR_EXCLUSION 0x00002000u
#define XDOWS_SECURITY_CAPABILITIES ( \
    XDOWS_SECURITY_CAP_PRIORITY_QUEUE | \
    XDOWS_SECURITY_CAP_DIRTY_WRITE_COALESCING | \
    XDOWS_SECURITY_CAP_BUILD_ID | \
    XDOWS_SECURITY_CAP_STARTUP_SELF_PROTECT | \
    XDOWS_SECURITY_CAP_USER_DECISION_HOLD | \
    XDOWS_SECURITY_CAP_PROCESS_MANAGEMENT | \
    XDOWS_SECURITY_CAP_ENHANCED_SELF_PROTECT | \
    XDOWS_SECURITY_CAP_R0_BEHAVIOR_PROTECTION | \
    XDOWS_SECURITY_CAP_R0_BOOT_PROTECTION | \
    XDOWS_SECURITY_CAP_R0_REGISTRY_PROTECTION | \
    XDOWS_SECURITY_CAP_ASYNC_REVIEW | \
    XDOWS_SECURITY_CAP_EVENT_BATCH | \
    XDOWS_SECURITY_CAP_RULE_INTERPRETER | \
    XDOWS_SECURITY_CAP_INITIATOR_EXCLUSION)

//
// Client registration flags. The driver ignores unknown bits for forward
// compatibility.
//
#define XDOWS_SECURITY_REGISTER_FLAG_ASYNC_REVIEW 0x00000001u
#define XDOWS_SECURITY_MODULE_TOKEN_AUTH 0x00000001u
#define XDOWS_SECURITY_MODULE_PROCESS 0x00000002u
#define XDOWS_SECURITY_MODULE_FILE 0x00000004u
#define XDOWS_SECURITY_MODULE_INJECTION 0x00000008u
#define XDOWS_SECURITY_MODULE_SELF_PROTECT 0x00000010u
#define XDOWS_SECURITY_MODULE_BEHAVIOR 0x00000020u
#define XDOWS_SECURITY_MODULE_REGISTRY 0x00000040u
#define XDOWS_SECURITY_REQUIRED_MODULES ( \
    XDOWS_SECURITY_MODULE_TOKEN_AUTH | \
    XDOWS_SECURITY_MODULE_PROCESS | \
    XDOWS_SECURITY_MODULE_FILE | \
    XDOWS_SECURITY_MODULE_INJECTION | \
    XDOWS_SECURITY_MODULE_SELF_PROTECT | \
    XDOWS_SECURITY_MODULE_BEHAVIOR | \
    XDOWS_SECURITY_MODULE_REGISTRY)
#define XDOWS_SECURITY_MAX_PATH_CHARS 520u
#define XDOWS_SECURITY_MAX_COMMAND_CHARS 1024u
#define XDOWS_SECURITY_MAX_REASON_CHARS 128u
#define XDOWS_SECURITY_TOKEN_CHARS 64u
#define XDOWS_SECURITY_MAX_LOG_MODULE_CHARS 32u
#define XDOWS_SECURITY_MAX_LOG_MESSAGE_CHARS 256u
#define XDOWS_SECURITY_MAX_PROCESS_NAME_CHARS 260u
#define XDOWS_SECURITY_PROCESS_BATCH_SIZE 64u
#define XDOWS_SECURITY_EVENT_BATCH_SIZE 16u
#define XDOWS_SECURITY_MAX_BOOT_VOLUME_ROOTS 4u
#define XDOWS_SECURITY_MAX_BOOT_VOLUME_ROOT_CHARS 128u
#define XDOWS_SECURITY_MAX_REGISTRY_RULES 32u
#define XDOWS_SECURITY_MAX_REGISTRY_PATH_CHARS 260u
#define XDOWS_SECURITY_MAX_REGISTRY_VALUE_CHARS 260u

//
// Declarative behavior-rule interpreter (capability 0x1000). User mode sends
// a whole rule set through IOCTL_XDOWS_SECURITY_SET_BEHAVIOR_RULES; the
// kernel stores a validated copy and evaluates it in addition to the fixed
// in-kernel command-line rules. Purely additive: no existing rule, struct,
// enum, or IOCTL changes meaning.
//
#define XDOWS_SECURITY_MAX_BEHAVIOR_RULES 32u
#define XDOWS_SECURITY_MAX_RULE_TERMS 3u
#define XDOWS_SECURITY_MAX_RULE_TERM_CHARS 96u

//
// Rule flags.
//
// KILL_ACTOR: a user-confirmed Block for this rule additionally requests the
// counter-termination of the acting process (decision ResultCode sentinel,
// same guard rails as the injection gate).
// FAIL_CLOSED: when the bridge cannot deliver the event or the decision times
// out, deny the operation. Without it the rule is fail-open on infrastructure
// failure and only denies on an explicit Block verdict.
//
#define XDOWS_SECURITY_RULE_FLAG_KILL_ACTOR 0x00000001u
#define XDOWS_SECURITY_RULE_FLAG_FAIL_CLOSED 0x00000002u

//
// Operations a rule applies to. A rule whose Operations mask does not cover
// the operation being evaluated never matches.
//
#define XDOWS_SECURITY_RULE_OPERATION_PROCESS_CREATE 0x00000001u
#define XDOWS_SECURITY_RULE_OPERATION_FILE_CREATE 0x00000002u
#define XDOWS_SECURITY_RULE_OPERATION_FILE_WRITE 0x00000004u
#define XDOWS_SECURITY_RULE_OPERATION_FILE_DELETE 0x00000008u
#define XDOWS_SECURITY_RULE_OPERATION_FILE_RENAME 0x00000010u
#define XDOWS_SECURITY_RULE_OPERATION_ALL 0x0000001Fu

typedef enum _XDOWS_SECURITY_RULE_MATCH_KIND {
    //
    // The whole axis is unconstrained (no terms required).
    //
    XdowsSecurityRuleMatchAny = 0,
    //
    // Target term matches the path tail (extension-style, e.g. ".locked").
    //
    XdowsSecurityRuleMatchSuffix = 1,
    //
    // Target term matches a backslash-bounded path segment (e.g. "Startup").
    //
    XdowsSecurityRuleMatchSegment = 2,
    //
    // Target term matches the path start.
    //
    XdowsSecurityRuleMatchPrefix = 3,
    //
    // Target term matches anywhere in the path.
    //
    XdowsSecurityRuleMatchContains = 4
} XDOWS_SECURITY_RULE_MATCH_KIND;

//
// One matching axis of a rule. TermCount == 0 leaves the axis unconstrained.
// On the Initiator axis a term equals an image leaf name (e.g. "cmd.exe") or,
// when it contains a backslash, matches as a case-insensitive actor-path
// suffix. On the CommandLine axis every term must appear as a substring.
// On the Target axis the terms are interpreted with the rule's
// TargetMatchKind; a rule matches when ANY target term matches.
//
typedef struct _XDOWS_SECURITY_RULE_TERM_AXIS {
    ULONG TermCount;
    ULONG Reserved;
    WCHAR Terms[XDOWS_SECURITY_MAX_RULE_TERMS][XDOWS_SECURITY_MAX_RULE_TERM_CHARS];
} XDOWS_SECURITY_RULE_TERM_AXIS, *PXDOWS_SECURITY_RULE_TERM_AXIS;

//
// Declarative rule: Initiator x CommandLine x Target, scoped by Operations,
// optionally rate-limited by Threshold/WindowMs and escalated by Flags.
//
typedef struct _XDOWS_SECURITY_BEHAVIOR_RULE {
    ULONG RuleId;
    //
    // Behavior type reported to user mode when the rule fires. Use a
    // XDOWS_SECURITY_BEHAVIOR_TYPE value; types 16+ are the extensible range.
    //
    ULONG BehaviorType;
    ULONG Flags;
    ULONG Operations;
    //
    // 0 = fire on every match. > 0 = fire only after Threshold matches by the
    // same process inside WindowMs (sliding window, like the ransomware
    // monitor). WindowMs is clamped to 60000.
    //
    ULONG Threshold;
    ULONG WindowMs;
    ULONG TargetMatchKind;
    ULONG Reserved;
    XDOWS_SECURITY_RULE_TERM_AXIS Initiator;
    XDOWS_SECURITY_RULE_TERM_AXIS Target;
    XDOWS_SECURITY_RULE_TERM_AXIS CommandLine;
} XDOWS_SECURITY_BEHAVIOR_RULE, *PXDOWS_SECURITY_BEHAVIOR_RULE;

//
// Initiator exclusion list (capability 0x2000). Terminates the user-mode
// consultation for the configured scopes when the acting process matches, so
// known-heavy applications (games, downloaders, IMEs, build tools) stop
// reaching the decision window. Exclusions never disable the critical
// command-line threat rules or the kernel-side denials.
//
#define XDOWS_SECURITY_MAX_INITIATOR_EXCLUSIONS 32u
#define XDOWS_SECURITY_MAX_EXCLUSION_CHARS 160u

#define XDOWS_SECURITY_EXCLUSION_SCOPE_PROCESS 0x00000001u
#define XDOWS_SECURITY_EXCLUSION_SCOPE_FILE 0x00000002u
#define XDOWS_SECURITY_EXCLUSION_SCOPE_HANDLE 0x00000004u
#define XDOWS_SECURITY_EXCLUSION_SCOPE_REGISTRY 0x00000008u
#define XDOWS_SECURITY_EXCLUSION_SCOPE_ALL 0x0000000Fu

typedef struct _XDOWS_SECURITY_INITIATOR_EXCLUSION {
    ULONG ScopeMask;
    ULONG Reserved;
    //
    // Image leaf name (e.g. "steam.exe") or, when the pattern contains a
    // backslash, a case-insensitive actor-path suffix (e.g.
    // "\Steam\steamapps\common\").
    //
    WCHAR Pattern[XDOWS_SECURITY_MAX_EXCLUSION_CHARS];
} XDOWS_SECURITY_INITIATOR_EXCLUSION, *PXDOWS_SECURITY_INITIATOR_EXCLUSION;

//
// ResultCode sentinel set by user mode on a Block verdict to additionally
// request that the driver counter-terminate the acting process. Honoured by
// the injection/handle gates and by the registry gate for critical
// persistence keys. Mirrored by DriverProtocol.KillActorResultCode in the
// main app repository. The safety guards (never the registered client, a
// critical system process, a self-protected process, or PID <= 4) are
// enforced kernel-side, so a stray sentinel cannot be abused.
//
#define XDOWS_DECISION_RESULT_KILL_ACTOR 0x4B494C4Cu

#define XDOWS_SECURITY_DEVICE_NAME L"\\Device\\XdowsSecurityDriver"
#define XDOWS_SECURITY_SYMBOLIC_NAME L"\\DosDevices\\Global\\XdowsSecurityDriver"
#define XDOWS_SECURITY_LEGACY_SYMBOLIC_NAME L"\\DosDevices\\XdowsSecurityDriver"
#define XDOWS_SECURITY_USER_DEVICE_PATH L"\\\\.\\XdowsSecurityDriver"

#define FILE_DEVICE_XDOWS_SECURITY 0x8000u

#define IOCTL_XDOWS_SECURITY_REGISTER_CLIENT \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_HEARTBEAT \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_GET_NEXT_EVENT \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_SUBMIT_DECISION \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_GET_STATE \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_DISCONNECT_CLIENT \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_REGISTER_PROTECTED_PROCESS \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_SET_VOLUNTARY_EXIT \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_AUTHORIZED_SHUTDOWN \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_GET_NEXT_LOG \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_SET_STARTUP_PROTECTION \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_QUERY_PROCESSES \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_OPERATE_PROCESS \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_SET_BOOT_PROTECTION \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_SET_REGISTRY_PROTECTION \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_GET_NEXT_EVENTS \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_SET_BEHAVIOR_RULES \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XDOWS_SECURITY_SET_INITIATOR_EXCLUSIONS \
    CTL_CODE(FILE_DEVICE_XDOWS_SECURITY, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

DEFINE_GUID(GUID_DEVINTERFACE_XdowsSecurityDriver,
    0xec5db072, 0x8119, 0x4d65, 0xa7, 0xae, 0x67, 0xd7, 0xf3, 0x10, 0x05, 0xe1);
// {ec5db072-8119-4d65-a7ae-67d7f31005e1}

typedef enum _XDOWS_SECURITY_EVENT_TYPE {
    XdowsSecurityEventNone = 0,
    XdowsSecurityEventProcessCreate = 1,
    XdowsSecurityEventFileCreate = 2,
    XdowsSecurityEventFileWrite = 3,
    XdowsSecurityEventFileRename = 4,
    XdowsSecurityEventProcessHandle = 5,
    XdowsSecurityEventThreadHandle = 6,
    XdowsSecurityEventImageLoad = 7,
    XdowsSecurityEventDriverLog = 8,
    XdowsSecurityEventBehavior = 9,
    XdowsSecurityEventBootWrite = 10,
    XdowsSecurityEventRegistryWrite = 11
} XDOWS_SECURITY_EVENT_TYPE;

typedef enum _XDOWS_SECURITY_REGISTRY_OPERATION {
    XdowsSecurityRegistryOperationNone = 0,
    XdowsSecurityRegistryOperationCreateKey = 1,
    XdowsSecurityRegistryOperationSetValue = 2,
    XdowsSecurityRegistryOperationDeleteValue = 3,
    XdowsSecurityRegistryOperationDeleteKey = 4,
    XdowsSecurityRegistryOperationRenameKey = 5,
    XdowsSecurityRegistryOperationRestoreKey = 6,
    XdowsSecurityRegistryOperationReplaceKey = 7,
    XdowsSecurityRegistryOperationUnloadKey = 8
} XDOWS_SECURITY_REGISTRY_OPERATION;

typedef enum _XDOWS_SECURITY_BEHAVIOR_TYPE {
    XdowsSecurityBehaviorNone = 0,
    XdowsSecurityBehaviorVssDeletion = 1,
    XdowsSecurityBehaviorHiddenPowerShell = 2,
    XdowsSecurityBehaviorEncodedCommand = 3,
    XdowsSecurityBehaviorPolicyBypass = 4,
    XdowsSecurityBehaviorDownloadExecute = 5,
    XdowsSecurityBehaviorLolbinAbuse = 6,
    XdowsSecurityBehaviorProcessInjection = 7,
    XdowsSecurityBehaviorThreadInjection = 8,
    //
    // Office/PDF/browser document opened by an application that spawns a
    // script host (cmd/powershell/wscript/rundll32). Classic exploit chain.
    //
    XdowsSecurityBehaviorParentProcessChain = 9,
    //
    // autorun.inf creation on a removable/media volume. Kernel emits a
    // FileCreate event flagged AutorunInf so user mode can hold for an
    // explicit allow/block decision (fail-closed on timeout).
    //
    XdowsSecurityBehaviorAutorunInf = 10,
    //
    // A handle request for PROCESS_TERMINATE against a protected process.
    // Kernel strips the right; on repeated attempts it may kill the actor.
    //
    XdowsSecurityBehaviorProtectedProcessTerminate = 11,
    //
    // A handle request for dangerous rights (VM_WRITE/CREATE_THREAD/...) against
    // a critical system process (lsass, csrss, winlogon, ...). Kernel consults
    // user mode for an allow/strip decision and may kill the actor.
    //
    XdowsSecurityBehaviorSensitiveProcessHandle = 12,
    //
    // Recursive directory deletion (rd/rmdir /s /q) targeting a location
    // with more than 500 files. Kernel flags the command line; user mode
    // counts the target and prompts.
    //
    XdowsSecurityBehaviorDestructiveDirectoryDelete = 13,
    //
    // Ownership / ACL escalation tools: takeown, icacls. Legitimate admin
    // commands, but prime post-exploitation primitives.
    //
    XdowsSecurityBehaviorOwnershipEscalation = 14,
    //
    // System-state control commands: shutdown, net user. Legitimate admin
    // commands, but prime destructive post-exploitation primitives.
    //
    XdowsSecurityBehaviorSystemControlCommand = 15,
    //
    // mountvol with the /s switch: mounts the EFI system partition (optionally
    // on a remote disk), which is the persistence surface for bootkits.
    // Essentially never legitimate on an endpoint; fail-closed.
    //
    XdowsSecurityBehaviorEfiMount = 16,
    //
    // sysprep with /oobe and/or /generalize: re-provisions the machine and
    // wipes activation, provisioning, and local configuration on next boot.
    // Occasionally legitimate in IT deployment, but destructive enough that
    // an explicit user decision is required; fail-closed.
    //
    XdowsSecurityBehaviorOobeReset = 17,
    //
    // A script host (cmd/powershell/wscript/mshta/...) mass-deleting files
    // under the Windows directory. Detected by the in-kernel ransomware
    // rate monitor (separate, stricter slot table); currently a pure kernel
    // denial with no user-mode round trip. Reserved for a future event
    // emission; user mode mirrors the value for protocol symmetry.
    //
    XdowsSecurityBehaviorSystemDirectoryRansomware = 18
} XDOWS_SECURITY_BEHAVIOR_TYPE;

typedef enum _XDOWS_SECURITY_DECISION_TYPE {
    XdowsSecurityDecisionUnknown = 0,
    XdowsSecurityDecisionAllow = 1,
    XdowsSecurityDecisionBlock = 2,
    XdowsSecurityDecisionTimeout = 3,
    XdowsSecurityDecisionPending = 4
} XDOWS_SECURITY_DECISION_TYPE;

typedef enum _XDOWS_SECURITY_MODEL_MODE {
    XdowsSecurityModelStandard = 0,
    XdowsSecurityModelFlash = 1,
    XdowsSecurityModelPro = 2,
    XdowsSecurityModelAdaptive = 3
} XDOWS_SECURITY_MODEL_MODE;

typedef enum _XDOWS_SECURITY_EVENT_FLAGS {
    XdowsSecurityEventFlagNone = 0x00000000u,
    XdowsSecurityEventFlagFileOpenNameAvailable = 0x00000001u,
    XdowsSecurityEventFlagUserModeRequired = 0x00000002u,
    XdowsSecurityEventFlagThreatConfirmed = 0x00000004u,
    XdowsSecurityEventFlagAutorunInf = 0x00000008u
} XDOWS_SECURITY_EVENT_FLAGS;

typedef enum _XDOWS_SECURITY_LOG_SEVERITY {
    XdowsSecurityLogDebug = 0,
    XdowsSecurityLogInfo = 1,
    XdowsSecurityLogWarning = 2,
    XdowsSecurityLogError = 3,
    XdowsSecurityLogFatal = 4
} XDOWS_SECURITY_LOG_SEVERITY;

typedef enum _XDOWS_SECURITY_PROCESS_OPERATION {
    XdowsSecurityProcessOperationNone = 0,
    XdowsSecurityProcessOperationSuspend = 1,
    XdowsSecurityProcessOperationResume = 2,
    XdowsSecurityProcessOperationTerminate = 3
} XDOWS_SECURITY_PROCESS_OPERATION;

typedef struct _XDOWS_SECURITY_PROTOCOL_HEADER {
    ULONG Size;
    ULONG Version;
} XDOWS_SECURITY_PROTOCOL_HEADER, *PXDOWS_SECURITY_PROTOCOL_HEADER;

//
// Declarative rule set downcall (capability 0x1000). Declared here rather
// than next to XDOWS_SECURITY_BEHAVIOR_RULE because the protocol header
// typedef must be visible first.
//
typedef struct _XDOWS_SECURITY_BEHAVIOR_RULE_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG Enabled;
    ULONG RuleCount;
    ULONG Reserved;
    XDOWS_SECURITY_BEHAVIOR_RULE Rules[XDOWS_SECURITY_MAX_BEHAVIOR_RULES];
} XDOWS_SECURITY_BEHAVIOR_RULE_REQUEST, *PXDOWS_SECURITY_BEHAVIOR_RULE_REQUEST;

typedef struct _XDOWS_SECURITY_INITIATOR_EXCLUSION_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG Count;
    ULONG Reserved;
    XDOWS_SECURITY_INITIATOR_EXCLUSION Entries[XDOWS_SECURITY_MAX_INITIATOR_EXCLUSIONS];
} XDOWS_SECURITY_INITIATOR_EXCLUSION_REQUEST, *PXDOWS_SECURITY_INITIATOR_EXCLUSION_REQUEST;

typedef struct _XDOWS_SECURITY_REGISTER_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG ClientProcessId;
    ULONG Flags;
    ULONG HeartbeatTimeoutMs;
    ULONG Reserved;
} XDOWS_SECURITY_REGISTER_REQUEST, *PXDOWS_SECURITY_REGISTER_REQUEST;

typedef struct _XDOWS_SECURITY_REGISTER_RESPONSE {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG Status;
    ULONG ProtocolVersion;
    ULONG DefaultKernelWaitTimeoutMs;
    ULONG Capabilities;
    ULONGLONG DriverBuildId;
    WCHAR ShutdownToken[XDOWS_SECURITY_TOKEN_CHARS + 1];
} XDOWS_SECURITY_REGISTER_RESPONSE, *PXDOWS_SECURITY_REGISTER_RESPONSE;

typedef struct _XDOWS_SECURITY_HEARTBEAT_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG ClientProcessId;
    ULONG Reserved;
} XDOWS_SECURITY_HEARTBEAT_REQUEST, *PXDOWS_SECURITY_HEARTBEAT_REQUEST;

typedef struct _XDOWS_SECURITY_EVENT {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONGLONG EventId;
    ULONGLONG CorrelationId;
    ULONG EventType;
    ULONG Flags;
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG CreatingProcessId;
    ULONG CreatingThreadId;
    ULONG KernelWaitTimeoutMs;
    ULONG BehaviorType;
    ULONG RegistryOperation;
    ULONG Reserved;
    WCHAR RegistryValueName[XDOWS_SECURITY_MAX_REGISTRY_VALUE_CHARS];
    WCHAR ImagePath[XDOWS_SECURITY_MAX_PATH_CHARS];
    WCHAR ActorImagePath[XDOWS_SECURITY_MAX_PATH_CHARS];
    WCHAR CommandLine[XDOWS_SECURITY_MAX_COMMAND_CHARS];
} XDOWS_SECURITY_EVENT, *PXDOWS_SECURITY_EVENT;

typedef struct _XDOWS_SECURITY_DECISION {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONGLONG EventId;
    ULONG Decision;
    ULONG CacheTtlMs;
    ULONG ResultCode;
    ULONG Reserved;
    WCHAR Reason[XDOWS_SECURITY_MAX_REASON_CHARS];
} XDOWS_SECURITY_DECISION, *PXDOWS_SECURITY_DECISION;

typedef struct _XDOWS_SECURITY_STATE {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG ClientConnected;
    ULONG PendingEventCount;
    ULONG DroppedEventCount;
    ULONG ProcessProtectionEnabled;
    ULONG FileProtectionEnabled;
    ULONG SelfProtectionEnabled;
    ULONG ProtectedProcessId;
    ULONG StartupProtectionEnabled;
    ULONG BootProtectionEnabled;
    ULONG ActiveModules;
    ULONG ProtocolVersion;
    ULONG Capabilities;
    ULONGLONG DriverBuildId;
    ULONG ReceivedByType[XDOWS_SECURITY_EVENT_TYPE_COUNT];
    ULONG DroppedByType[XDOWS_SECURITY_EVENT_TYPE_COUNT];
    ULONG TimedOutByType[XDOWS_SECURITY_EVENT_TYPE_COUNT];
} XDOWS_SECURITY_STATE, *PXDOWS_SECURITY_STATE;

typedef struct _XDOWS_SECURITY_PROTECTED_PROCESS_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG ProcessId;
    ULONG MainThreadId;
    ULONG Flags;
    ULONG Reserved;
} XDOWS_SECURITY_PROTECTED_PROCESS_REQUEST, *PXDOWS_SECURITY_PROTECTED_PROCESS_REQUEST;

typedef struct _XDOWS_SECURITY_VOLUNTARY_EXIT_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG ProcessId;
    ULONG IsVoluntaryExit;
    ULONG Reserved;
} XDOWS_SECURITY_VOLUNTARY_EXIT_REQUEST, *PXDOWS_SECURITY_VOLUNTARY_EXIT_REQUEST;

typedef struct _XDOWS_SECURITY_SHUTDOWN_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG Flags;
    ULONG Reserved;
    WCHAR ShutdownToken[XDOWS_SECURITY_TOKEN_CHARS + 1];
} XDOWS_SECURITY_SHUTDOWN_REQUEST, *PXDOWS_SECURITY_SHUTDOWN_REQUEST;

typedef struct _XDOWS_SECURITY_STARTUP_PROTECTION_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG ProcessId;
    ULONG Enabled;
    ULONG Reserved;
} XDOWS_SECURITY_STARTUP_PROTECTION_REQUEST, *PXDOWS_SECURITY_STARTUP_PROTECTION_REQUEST;

typedef struct _XDOWS_SECURITY_BOOT_PROTECTION_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG Enabled;
    ULONG DiskNumber;
    ULONG VolumeRootCount;
    ULONG Reserved;
    WCHAR VolumeRoots[XDOWS_SECURITY_MAX_BOOT_VOLUME_ROOTS]
                     [XDOWS_SECURITY_MAX_BOOT_VOLUME_ROOT_CHARS];
} XDOWS_SECURITY_BOOT_PROTECTION_REQUEST, *PXDOWS_SECURITY_BOOT_PROTECTION_REQUEST;

typedef struct _XDOWS_SECURITY_REGISTRY_PROTECTION_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG Enabled;
    ULONG RuleCount;
    ULONG Reserved;
    WCHAR RulePaths[XDOWS_SECURITY_MAX_REGISTRY_RULES]
                    [XDOWS_SECURITY_MAX_REGISTRY_PATH_CHARS];
} XDOWS_SECURITY_REGISTRY_PROTECTION_REQUEST, *PXDOWS_SECURITY_REGISTRY_PROTECTION_REQUEST;

typedef struct _XDOWS_SECURITY_PROCESS_QUERY_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG Cursor;
    ULONG Reserved;
    WCHAR AuthorizationToken[XDOWS_SECURITY_TOKEN_CHARS + 1];
} XDOWS_SECURITY_PROCESS_QUERY_REQUEST, *PXDOWS_SECURITY_PROCESS_QUERY_REQUEST;

typedef struct _XDOWS_SECURITY_PROCESS_ENTRY {
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG SessionId;
    ULONG ThreadCount;
    ULONG HandleCount;
    ULONG BasePriority;
    ULONGLONG WorkingSetBytes;
    ULONGLONG PrivateBytes;
    WCHAR ImageName[XDOWS_SECURITY_MAX_PROCESS_NAME_CHARS];
} XDOWS_SECURITY_PROCESS_ENTRY, *PXDOWS_SECURITY_PROCESS_ENTRY;

typedef struct _XDOWS_SECURITY_PROCESS_QUERY_RESPONSE {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG Count;
    ULONG NextCursor;
    ULONG HasMore;
    ULONG Reserved;
    XDOWS_SECURITY_PROCESS_ENTRY Entries[XDOWS_SECURITY_PROCESS_BATCH_SIZE];
} XDOWS_SECURITY_PROCESS_QUERY_RESPONSE, *PXDOWS_SECURITY_PROCESS_QUERY_RESPONSE;

typedef struct _XDOWS_SECURITY_PROCESS_OPERATION_REQUEST {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG ProcessId;
    ULONG Operation;
    WCHAR AuthorizationToken[XDOWS_SECURITY_TOKEN_CHARS + 1];
} XDOWS_SECURITY_PROCESS_OPERATION_REQUEST, *PXDOWS_SECURITY_PROCESS_OPERATION_REQUEST;

//
// Batch event drain for IOCTL_XDOWS_SECURITY_GET_NEXT_EVENTS.
//
// The caller provides a buffer of at least
// sizeof(XDOWS_SECURITY_PROTOCOL_HEADER) + sizeof(XDOWS_SECURITY_EVENT);
// the driver fills Count entries and returns the number of bytes written
// via IoStatus.Information. Entries beyond Count are not touched and must
// not be read. The batch size keeps the whole structure under the 85 KB
// .NET Large Object Heap threshold, so a client can pool the buffer.
//
typedef struct _XDOWS_SECURITY_EVENT_BATCH {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONG Count;
    ULONG Reserved;
    XDOWS_SECURITY_EVENT Events[XDOWS_SECURITY_EVENT_BATCH_SIZE];
} XDOWS_SECURITY_EVENT_BATCH, *PXDOWS_SECURITY_EVENT_BATCH;

typedef struct _XDOWS_SECURITY_LOG_ENTRY {
    XDOWS_SECURITY_PROTOCOL_HEADER Header;
    ULONGLONG EventId;
    ULONGLONG CorrelationId;
    ULONG Severity;
    ULONG DroppedCount;
    LARGE_INTEGER Timestamp;
    WCHAR Module[XDOWS_SECURITY_MAX_LOG_MODULE_CHARS];
    WCHAR Message[XDOWS_SECURITY_MAX_LOG_MESSAGE_CHARS];
} XDOWS_SECURITY_LOG_ENTRY, *PXDOWS_SECURITY_LOG_ENTRY;
