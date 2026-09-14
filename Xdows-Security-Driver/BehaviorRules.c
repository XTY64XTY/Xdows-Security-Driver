/*++

Module Name:

    behaviorrules.c

Abstract:

    In-kernel command-line behavior inspection for process-launch events.

    The engine copies the command line into a stack buffer, lowercases it
    in-place, then runs a sequence of substring tests. The rules are
    intentionally conservative: only patterns with a very low legitimate-use
    rate are matched, so the fast-path block does not introduce false
    positives on normal user activity.

    Rule design notes:
      * VSS deletion is the highest-priority rule because it is the
        canonical ransomware precursor and must reach the user-decision path
        before the command can execute.
      * PowerShell -enc / -encodedcommand and -ExecutionPolicy Bypass are
        matched only when the command line contains "powershell" or "pwsh",
        to avoid flagging legitimate tools that accept similar arguments.
        PolicyBypass is detected like the other rules; user mode makes the
        final decision, while infrastructure failure remains fail-open only
        for this lower-confidence rule.
      * Download-and-execute patterns (DownloadString, Net.WebClient,
        certutil -urlcache, mshta http) are LOLBin abuse indicators that
        rarely appear in benign command lines.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "BehaviorRules.h"
#include <ntstrsafe.h>

//
// Maximum command-line length we inspect. The bridge protocol allows up to
// 1024 wide chars; we cap the inspected buffer at the same size so a
// truncated command line is still evaluated.
//
#define XDOWS_BEHAVIOR_MAX_CMD_CHARS  XDOWS_SECURITY_MAX_COMMAND_CHARS

//
// EPROCESS image-name truncation length used by PsGetProcessImageFileName.
// Matches the constant in InjectionProtect.c.
//
#define XDOWS_BEHAVIOR_IMAGE_NAME_MAX_CHARS 15u

static volatile LONG g_BehaviorProtectionEnabled;

//
// Declarative rule interpreter state (capability 0x1000) and initiator
// exclusion list (capability 0x2000). Both are replaced as a whole by the
// registered client and read on the hot paths, so a push lock guards the
// swap: the evaluator takes it shared, configuration takes it exclusive.
//
static XDOWS_SECURITY_BEHAVIOR_RULE g_BehaviorRules[XDOWS_SECURITY_MAX_BEHAVIOR_RULES];
static ULONG g_BehaviorRuleCount;
static XDOWS_SECURITY_INITIATOR_EXCLUSION g_InitiatorExclusions[XDOWS_SECURITY_MAX_INITIATOR_EXCLUSIONS];
static ULONG g_InitiatorExclusionCount;
static EX_PUSH_LOCK g_RuleSetLock;
static BOOLEAN g_RuleSetLockInitialized;

//
// Sliding-window counters for rules that declare a Threshold. Keyed by
// (RuleId, ProcessId); a small fixed table keeps the hot path allocation
// free, matching the ransomware monitor's design.
//
#define XDOWS_BEHAVIOR_RATE_SLOTS 32u

typedef struct _XDOWS_BEHAVIOR_RATE_SLOT {
    ULONG         RuleId;
    ULONG         ProcessId;
    ULONG         Count;
    LARGE_INTEGER WindowStart;
    BOOLEAN       Flagged;
} XDOWS_BEHAVIOR_RATE_SLOT, *PXDOWS_BEHAVIOR_RATE_SLOT;

static XDOWS_BEHAVIOR_RATE_SLOT g_BehaviorRateSlots[XDOWS_BEHAVIOR_RATE_SLOTS];
static KSPIN_LOCK g_BehaviorRateLock;

//
// PsGetProcessImageFileName is declared in ntifs.h only. Returns the cached
// image name (truncated to 15 chars) of a process.
//
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

//
// PsLookupProcessByProcessId is declared in ntifs.h only; forward-declared
// here. Exported by ntoskrnl.lib.
//
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

//
// Case-insensitive ASCII leaf-name comparison capped at the EPROCESS
// truncation length (15 chars). Path may be a full \Device\... path or a
// plain file name; only the final component is compared.
//
static
BOOLEAN
XdowsBehaviorLeafNameEquals(
    _In_ PCUNICODE_STRING Path,
    _In_ PCSTR KnownName
    )
{
    SIZE_T pathChars;
    SIZE_T leafStart;
    SIZE_T i;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return FALSE;
    }

    pathChars = Path->Length / sizeof(WCHAR);
    leafStart = 0;
    for (i = 0; i < pathChars; i++) {
        if (Path->Buffer[i] == L'\\') {
            leafStart = i + 1;
        }
    }

    for (i = 0; i < XDOWS_BEHAVIOR_IMAGE_NAME_MAX_CHARS; i++) {
        CHAR left;
        CHAR right = KnownName[i];
        WCHAR wc;

        if (leafStart + i >= pathChars) {
            return right == 0;
        }
        wc = Path->Buffer[leafStart + i];
        if (wc > 0x7F) {
            return FALSE;
        }
        left = (CHAR)wc;
        if (left >= 'a' && left <= 'z') {
            left = (CHAR)(left - ('a' - 'A'));
        }
        if (right >= 'a' && right <= 'z') {
            right = (CHAR)(right - ('a' - 'A'));
        }
        if (left != right) {
            return FALSE;
        }
    }

    return KnownName[XDOWS_BEHAVIOR_IMAGE_NAME_MAX_CHARS] == 0;
}

static
BOOLEAN
XdowsBehaviorImageNameEquals(
    _In_ PCSTR ImageName,
    _In_ PCSTR KnownName
    )
{
    SIZE_T i;

    for (i = 0; i < XDOWS_BEHAVIOR_IMAGE_NAME_MAX_CHARS; i++) {
        CHAR left = ImageName[i];
        CHAR right = KnownName[i];
        CHAR upperL;
        CHAR upperR;

        if (left == 0 || right == 0) {
            return left == right;
        }
        upperL = (left >= 'a' && left <= 'z')
            ? (CHAR)(left - ('a' - 'A'))
            : left;
        upperR = (right >= 'a' && right <= 'z')
            ? (CHAR)(right - ('a' - 'A'))
            : right;
        if (upperL != upperR) {
            return FALSE;
        }
    }

    return TRUE;
}

NTSTATUS
XdowsBehaviorProtectInitialize(
    VOID
    )
{
    if (!g_RuleSetLockInitialized) {
        ExInitializePushLock(&g_RuleSetLock);
        KeInitializeSpinLock(&g_BehaviorRateLock);
        g_BehaviorRuleCount = 0;
        g_InitiatorExclusionCount = 0;
        RtlZeroMemory(g_BehaviorRules, sizeof(g_BehaviorRules));
        RtlZeroMemory(g_InitiatorExclusions, sizeof(g_InitiatorExclusions));
        RtlZeroMemory(g_BehaviorRateSlots, sizeof(g_BehaviorRateSlots));
        g_RuleSetLockInitialized = TRUE;
    }
    (VOID)InterlockedExchange(&g_BehaviorProtectionEnabled, 1);
    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Behavior",
        L"R0 behavior protection active.");
    return STATUS_SUCCESS;
}

VOID
XdowsBehaviorProtectShutdown(
    VOID
    )
{
    (VOID)InterlockedExchange(&g_BehaviorProtectionEnabled, 0);
    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Behavior",
        L"R0 behavior protection stopped.");
}

BOOLEAN
XdowsBehaviorProtectIsEnabled(
    VOID
    )
{
    return InterlockedCompareExchange(&g_BehaviorProtectionEnabled, 0, 0) != 0;
}

//
// Case-insensitive substring search within a lowercased wide buffer.
// Returns TRUE if Needle is found anywhere inside Haystack.
//
static
BOOLEAN
XdowsBehaviorContainsW(
    _In_reads_(HaystackLen) PCWSTR Haystack,
    _In_ SIZE_T HaystackLen,
    _In_ PCWSTR Needle
    )
{
    SIZE_T needleLen;

    if (Haystack == NULL || Needle == NULL || HaystackLen == 0) {
        return FALSE;
    }

    needleLen = wcslen(Needle);
    if (needleLen == 0 || needleLen > HaystackLen) {
        return FALSE;
    }

    for (SIZE_T i = 0; i + needleLen <= HaystackLen; i++) {
        if (RtlEqualMemory(&Haystack[i], Needle, needleLen * sizeof(WCHAR))) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// Lowercase a UNICODE_STRING buffer into a destination wide buffer.
// Non-ASCII characters are left unchanged (ASCII-only lowercasing is
// sufficient for the rule set, which targets English command tokens).
//
static
VOID
XdowsBehaviorLowercaseInto(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ SIZE_T DestChars,
    _In_opt_ PCUNICODE_STRING Source
    )
{
    SIZE_T copyChars;

    if (DestChars == 0 || Dest == NULL) {
        return;
    }
    Dest[0] = UNICODE_NULL;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    copyChars = Source->Length / sizeof(WCHAR);
    if (copyChars >= DestChars) {
        copyChars = DestChars - 1;
    }

    for (SIZE_T i = 0; i < copyChars; i++) {
        WCHAR c = Source->Buffer[i];
        if (c >= L'A' && c <= L'Z') {
            c += (WCHAR)(L'a' - L'A');
        }
        Dest[i] = c;
    }
    Dest[copyChars] = UNICODE_NULL;
}

//
// Rule engine entry point. See header for the rule catalogue.
//
XDOWS_SECURITY_BEHAVIOR_TYPE
XdowsBehaviorInspectCommandLine(
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    WCHAR cmd[XDOWS_BEHAVIOR_MAX_CMD_CHARS];
    SIZE_T cmdLen;

    if (CommandLine == NULL || CommandLine->Buffer == NULL ||
        CommandLine->Length == 0) {
        return XdowsSecurityBehaviorNone;
    }

    XdowsBehaviorLowercaseInto(cmd, RTL_NUMBER_OF(cmd), CommandLine);
    cmdLen = wcsnlen(cmd, RTL_NUMBER_OF(cmd));
    if (cmdLen == 0) {
        return XdowsSecurityBehaviorNone;
    }

    //
    // Rule 1: VSS / shadow-copy deletion (ransomware precursor).
    //   vssadmin delete shadows
    //   wmic shadowcopy delete
    //   wbadmin delete catalog
    //
    // The substrings are tightened to include the object ("shadows" /
    // "shadowcopy" / "catalog") so a command line that merely mentions
    // "vssadmin" and "delete" in unrelated contexts (e.g. a script path)
    // does not trip the rule.
    //
    if ((XdowsBehaviorContainsW(cmd, cmdLen, L"vssadmin") &&
         XdowsBehaviorContainsW(cmd, cmdLen, L"delete") &&
         XdowsBehaviorContainsW(cmd, cmdLen, L"shadow")) ||
        (XdowsBehaviorContainsW(cmd, cmdLen, L"shadowcopy") &&
         XdowsBehaviorContainsW(cmd, cmdLen, L"delete")) ||
        (XdowsBehaviorContainsW(cmd, cmdLen, L"wbadmin") &&
         XdowsBehaviorContainsW(cmd, cmdLen, L"delete") &&
         XdowsBehaviorContainsW(cmd, cmdLen, L"catalog"))) {
        return XdowsSecurityBehaviorVssDeletion;
    }

    //
    // Rule 2: Hidden PowerShell window.
    //   -windowstyle hidden  |  -w hidden  |  -win hidden
    //
    if ((XdowsBehaviorContainsW(cmd, cmdLen, L"powershell") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"pwsh")) &&
        (XdowsBehaviorContainsW(cmd, cmdLen, L"-windowstyle hidden") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"-w hidden") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"-win hidden"))) {
        return XdowsSecurityBehaviorHiddenPowerShell;
    }

    //
    // Rule 3: Base64-encoded PowerShell command.
    //   -enc <data>  |  -encodedcommand <data>
    // Scoped to powershell/pwsh to avoid false positives from unrelated
    // tools that accept an "-enc" argument.
    //
    if ((XdowsBehaviorContainsW(cmd, cmdLen, L"-enc ") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"-encodedcommand ")) &&
        (XdowsBehaviorContainsW(cmd, cmdLen, L"powershell") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"pwsh"))) {
        return XdowsSecurityBehaviorEncodedCommand;
    }

    //
    // Rule 4: Execution-policy bypass.
    //   -executionpolicy bypass  |  -ep bypass  |  -epbypass
    // Scoped to powershell/pwsh. Note: this rule is detected and logged
    // but NOT blocked in the kernel fast-path (see ProcessProtect.c) --
    // -ExecutionPolicy Bypass is a common legitimate pattern in enterprise
    // admin scripts. The user-mode model correlates it with other signals.
    //
    if ((XdowsBehaviorContainsW(cmd, cmdLen, L"-executionpolicy bypass") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"-ep bypass") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"-epbypass")) &&
        (XdowsBehaviorContainsW(cmd, cmdLen, L"powershell") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"pwsh"))) {
        return XdowsSecurityBehaviorPolicyBypass;
    }

    //
    // Rule 5: Download-and-execute indicators.
    //   DownloadString / DownloadFile / Invoke-WebRequest /
    //   Net.WebClient / Start-BitsTransfer
    //
    if (XdowsBehaviorContainsW(cmd, cmdLen, L"downloadstring") ||
        XdowsBehaviorContainsW(cmd, cmdLen, L"downloadfile") ||
        XdowsBehaviorContainsW(cmd, cmdLen, L"invoke-webrequest") ||
        XdowsBehaviorContainsW(cmd, cmdLen, L"net.webclient") ||
        XdowsBehaviorContainsW(cmd, cmdLen, L"start-bitstransfer")) {
        return XdowsSecurityBehaviorDownloadExecute;
    }

    //
    // Rule 6: LOLBin abuse.
    //   certutil -urlcache  (download disguised as cache verification)
    //   mshta http|javascript|vbscript  (scriptlet download via HTA)
    //   rundll32 javascript:  (rare legitimate use)
    //
    if (XdowsBehaviorContainsW(cmd, cmdLen, L"certutil") &&
        XdowsBehaviorContainsW(cmd, cmdLen, L"-urlcache")) {
        return XdowsSecurityBehaviorLolbinAbuse;
    }

    if (XdowsBehaviorContainsW(cmd, cmdLen, L"mshta") &&
        (XdowsBehaviorContainsW(cmd, cmdLen, L"http") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"javascript") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"vbscript"))) {
        return XdowsSecurityBehaviorLolbinAbuse;
    }

    if (XdowsBehaviorContainsW(cmd, cmdLen, L"rundll32") &&
        XdowsBehaviorContainsW(cmd, cmdLen, L"javascript:")) {
        return XdowsSecurityBehaviorLolbinAbuse;
    }

    //
    // Rule 7: Recursive directory deletion. rd/rmdir with /s (recursive) and
    // /q (quiet) is the canonical destructive wipe primitive used by both
    // ransomware and cleanup scripts. User mode counts the target directory
    // and prompts only when the blast radius exceeds 500 files; the kernel
    // simply flags any matching command line. Matched as "rd "/"rd/" tokens
    // so "rd" inside unrelated words does not trip the rule.
    //
    if (XdowsBehaviorContainsW(cmd, cmdLen, L"/s") &&
        XdowsBehaviorContainsW(cmd, cmdLen, L"/q") &&
        (XdowsBehaviorContainsW(cmd, cmdLen, L"rd /") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"rd/") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"rmdir /") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"rmdir/"))) {
        return XdowsSecurityBehaviorDestructiveDirectoryDelete;
    }

    //
    // Rule 8: Ownership / ACL escalation tools. takeown and icacls are the
    // standard post-exploitation pair for hijacking files and registry keys.
    // Legitimate use is common enough that user mode gates on actor trust.
    //
    if (XdowsBehaviorContainsW(cmd, cmdLen, L"takeown") ||
        XdowsBehaviorContainsW(cmd, cmdLen, L"icacls")) {
        return XdowsSecurityBehaviorOwnershipEscalation;
    }

    //
    // Rule 9: System-state control commands. shutdown and net user are
    // frequently used by destructive actors (shutdown /r /t 0, net user
    // attacker /add). User mode gates on actor trust; the kernel flags the
    // command line and blocks the launch until a verdict arrives.
    //
    if (XdowsBehaviorContainsW(cmd, cmdLen, L"shutdown") ||
        XdowsBehaviorContainsW(cmd, cmdLen, L"net user")) {
        return XdowsSecurityBehaviorSystemControlCommand;
    }

    //
    // Rule 10: EFI system partition mounting.
    //   mountvol /S \\?\GLOBALROOT...   (or plain "mountvol /s")
    // Mounting the ESP is the bootkit persistence step: the partition is
    // hidden from Explorer and its contents survive OS reinstalls. There is
    // effectively no consumer-grade legitimate reason to script it.
    // Fail-CLOSED: matched as two independent substrings so any "mountvol"
    // invocation carrying "/s" trips the rule.
    //
    if (XdowsBehaviorContainsW(cmd, cmdLen, L"mountvol") &&
        XdowsBehaviorContainsW(cmd, cmdLen, L"/s")) {
        return XdowsSecurityBehaviorEfiMount;
    }

    //
    // Rule 11: Forced OOBE / provisioning reset.
    //   sysprep /oobe /generalize
    //   sysprep /generalize /oobe /shutdown ...
    // Running sysprep wipes activation, provisioning packages, and local
    // configuration on the next boot -- a destructive "soft factory reset"
    // that attackers use to cover tracks or lock users out. Matched as
    // "sysprep" plus one of the re-provision switches; a bare "sysprep"
    // without switches does not trip the rule.
    // Fail-CLOSED: the destructive switches are the attack, not incidental
    // management tooling.
    //
    if (XdowsBehaviorContainsW(cmd, cmdLen, L"sysprep") &&
        (XdowsBehaviorContainsW(cmd, cmdLen, L"/oobe") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"/generalize") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"/audit"))) {
        return XdowsSecurityBehaviorOobeReset;
    }

    return XdowsSecurityBehaviorNone;
}

//
// Classic document/browser exploit chain: a document viewer, browser, or
// mail client parent spawning a script host child. Legitimate office and
// browser applications never do this; every match is suspicious enough to
// reach the user-decision path.
//
XDOWS_SECURITY_BEHAVIOR_TYPE
XdowsBehaviorInspectParentChain(
    _In_ ULONG ParentProcessId,
    _In_ PCUNICODE_STRING ChildImageName
    )
{
    static const PCSTR scriptHosts[] = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
    };
    static const PCSTR documentParents[] = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
        "acrord32.exe", "wps.exe", "wpp.exe"
    };
    PEPROCESS parent = NULL;
    PCSTR parentImage;
    NTSTATUS status;
    SIZE_T i;

    if (ParentProcessId == 0 ||
        ChildImageName == NULL ||
        ChildImageName->Buffer == NULL) {
        return XdowsSecurityBehaviorNone;
    }

    //
    // First gate: the child must be a script host. This is a cheap leaf-name
    // compare and filters out the vast majority of launches before any PID
    // lookup.
    //
    for (i = 0; i < RTL_NUMBER_OF(scriptHosts); i++) {
        if (XdowsBehaviorLeafNameEquals(ChildImageName, scriptHosts[i])) {
            break;
        }
    }
    if (i == RTL_NUMBER_OF(scriptHosts)) {
        return XdowsSecurityBehaviorNone;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(ParentProcessId), &parent);
    if (!NT_SUCCESS(status) || parent == NULL) {
        return XdowsSecurityBehaviorNone;
    }

    parentImage = PsGetProcessImageFileName(parent);
    if (parentImage == NULL) {
        ObDereferenceObject(parent);
        return XdowsSecurityBehaviorNone;
    }

    for (i = 0; i < RTL_NUMBER_OF(documentParents); i++) {
        if (XdowsBehaviorImageNameEquals(parentImage, documentParents[i])) {
            ObDereferenceObject(parent);
            return XdowsSecurityBehaviorParentProcessChain;
        }
    }

    ObDereferenceObject(parent);
    return XdowsSecurityBehaviorNone;
}

//
// ---------------------------------------------------------------------------
// Declarative rule interpreter and initiator exclusion list.
// ---------------------------------------------------------------------------
//

//
// Bounded, case-insensitive substring test against a raw wide buffer. The
// buffer is not assumed to be null-terminated; Needle must be.
//
static
BOOLEAN
XdowsBehaviorBufferContains(
    _In_reads_(HaystackLen) PCWSTR Haystack,
    _In_ SIZE_T HaystackLen,
    _In_ PCWSTR Needle
    )
{
    SIZE_T needleLen = wcslen(Needle);
    SIZE_T i;

    if (needleLen == 0 || HaystackLen < needleLen) {
        return FALSE;
    }
    for (i = 0; i + needleLen <= HaystackLen; i++) {
        if (_wcsnicmp(Haystack + i, Needle, needleLen) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// Bounded, case-insensitive substring test between two counted wide strings.
//
static
BOOLEAN
XdowsBehaviorStringContains(
    _In_ PCUNICODE_STRING Haystack,
    _In_ PCUNICODE_STRING Needle
    )
{
    SIZE_T haystackLen = Haystack->Length / sizeof(WCHAR);
    SIZE_T needleLen = Needle->Length / sizeof(WCHAR);
    SIZE_T i;

    if (needleLen == 0 || haystackLen < needleLen) {
        return FALSE;
    }
    for (i = 0; i + needleLen <= haystackLen; i++) {
        if (_wcsnicmp(Haystack->Buffer + i, Needle->Buffer, needleLen) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// Bounded backslash-segment test (so "\Windows\" matches but "\WindowsOld\"
// does not). Both inputs are counted, not null-terminated.
//
static
BOOLEAN
XdowsBehaviorPathContainsSegment(
    _In_ PCUNICODE_STRING Path,
    _In_ PCUNICODE_STRING Segment
    )
{
    SIZE_T pathLen = Path->Length / sizeof(WCHAR);
    SIZE_T segmentLen = Segment->Length / sizeof(WCHAR);
    SIZE_T i;

    if (segmentLen == 0 || pathLen < segmentLen + 2) {
        return FALSE;
    }
    for (i = 0; i + segmentLen + 1 < pathLen; i++) {
        if (Path->Buffer[i] != L'\\') {
            continue;
        }
        if (_wcsnicmp(Path->Buffer + i + 1, Segment->Buffer, segmentLen) == 0 &&
            Path->Buffer[i + 1 + segmentLen] == L'\\') {
            return TRUE;
        }
    }
    return FALSE;
}

static
BOOLEAN
XdowsBehaviorTermIsEmpty(
    _In_ PCWSTR Term
    )
{
    return Term[0] == UNICODE_NULL;
}

//
// TRUE when one pattern (image leaf name, or actor-path suffix when it
// contains a backslash) selects the acting process.
//
static
BOOLEAN
XdowsBehaviorPatternMatchesActor(
    _In_ PCWSTR Pattern,
    _In_opt_ PCUNICODE_STRING ActorPath,
    _In_opt_ PCSTR ActorImageName
    )
{
    SIZE_T i;
    UNICODE_STRING patternView;
    UNICODE_STRING pathView;
    CHAR leaf[XDOWS_BEHAVIOR_IMAGE_NAME_MAX_CHARS + 1];

    if (XdowsBehaviorTermIsEmpty(Pattern)) {
        return FALSE;
    }

    for (i = 0; Pattern[i] != UNICODE_NULL; i++) {
        if (Pattern[i] == L'\\') {
            //
            // Path-suffix pattern: requires the full actor image path.
            //
            if (ActorPath == NULL || ActorPath->Buffer == NULL ||
                ActorPath->Length == 0) {
                return FALSE;
            }
            RtlInitUnicodeString(&patternView, Pattern);
            pathView.Buffer = ActorPath->Buffer;
            pathView.Length = ActorPath->Length;
            pathView.MaximumLength = ActorPath->Length;
            return ActorPath->Length >= patternView.Length &&
                RtlSuffixUnicodeString(&patternView, &pathView, TRUE);
        }
    }

    //
    // Leaf-name pattern: bounded to the EPROCESS 15-char truncation so the
    // comparison never reads past the cached image name.
    //
    if (ActorImageName == NULL) {
        return FALSE;
    }
    for (i = 0; i < XDOWS_BEHAVIOR_IMAGE_NAME_MAX_CHARS; i++) {
        if (Pattern[i] == UNICODE_NULL) {
            break;
        }
        if (Pattern[i] > 0x7F) {
            return FALSE;
        }
        leaf[i] = (CHAR)Pattern[i];
    }
    if (Pattern[i] != UNICODE_NULL) {
        return FALSE;
    }
    leaf[i] = '\0';
    return XdowsBehaviorImageNameEquals(ActorImageName, leaf);
}

static
BOOLEAN
XdowsBehaviorRuleInitiatorMatches(
    _In_ PXDOWS_SECURITY_BEHAVIOR_RULE Rule,
    _In_opt_ PCUNICODE_STRING ActorPath,
    _In_opt_ PCSTR ActorImageName
    )
{
    ULONG i;

    if (Rule->Initiator.TermCount == 0) {
        return TRUE;
    }
    for (i = 0; i < Rule->Initiator.TermCount; i++) {
        if (XdowsBehaviorPatternMatchesActor(
                Rule->Initiator.Terms[i],
                ActorPath,
                ActorImageName)) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// Every command-line term must appear in the (lowercased) command line.
// An unconstrained axis, or an axis whose terms are all empty, matches.
//
static
BOOLEAN
XdowsBehaviorRuleCommandLineMatches(
    _In_ PXDOWS_SECURITY_BEHAVIOR_RULE Rule,
    _In_reads_(CommandLength) PCWSTR CommandLineLower,
    _In_ SIZE_T CommandLength
    )
{
    ULONG i;

    if (Rule->CommandLine.TermCount == 0) {
        return TRUE;
    }
    for (i = 0; i < Rule->CommandLine.TermCount; i++) {
        PCWSTR term = Rule->CommandLine.Terms[i];
        if (XdowsBehaviorTermIsEmpty(term)) {
            continue;
        }
        if (!XdowsBehaviorBufferContains(CommandLineLower, CommandLength, term)) {
            return FALSE;
        }
    }
    return TRUE;
}

static
BOOLEAN
XdowsBehaviorRuleTargetMatches(
    _In_ PXDOWS_SECURITY_BEHAVIOR_RULE Rule,
    _In_opt_ PCUNICODE_STRING TargetPath
    )
{
    ULONG i;
    UNICODE_STRING pathView;
    UNICODE_STRING termView;

    if (Rule->Target.TermCount == 0) {
        return TRUE;
    }
    if (TargetPath == NULL || TargetPath->Buffer == NULL ||
        TargetPath->Length == 0) {
        return FALSE;
    }

    pathView.Buffer = TargetPath->Buffer;
    pathView.Length = TargetPath->Length;
    pathView.MaximumLength = TargetPath->Length;

    for (i = 0; i < Rule->Target.TermCount; i++) {
        PCWSTR term = Rule->Target.Terms[i];

        if (XdowsBehaviorTermIsEmpty(term)) {
            continue;
        }
        RtlInitUnicodeString(&termView, term);

        switch (Rule->TargetMatchKind) {
        case XdowsSecurityRuleMatchSuffix:
            if (TargetPath->Length >= termView.Length &&
                RtlSuffixUnicodeString(&termView, &pathView, TRUE)) {
                return TRUE;
            }
            break;
        case XdowsSecurityRuleMatchSegment:
            if (XdowsBehaviorPathContainsSegment(&pathView, &termView)) {
                return TRUE;
            }
            break;
        case XdowsSecurityRuleMatchPrefix:
            if (TargetPath->Length >= termView.Length &&
                RtlPrefixUnicodeString(&termView, &pathView, TRUE)) {
                return TRUE;
            }
            break;
        case XdowsSecurityRuleMatchContains:
            if (XdowsBehaviorStringContains(&pathView, &termView)) {
                return TRUE;
            }
            break;
        default:
            return FALSE;
        }
    }
    return FALSE;
}

//
// Sliding-window gate for rules that declare a Threshold. Returns TRUE when
// the rule has reached its threshold inside the window (and keeps returning
// TRUE for the rest of the window, so an ongoing burst stays blocked).
//
static
BOOLEAN
XdowsBehaviorRuleRateAllows(
    _In_ ULONG RuleId,
    _In_ ULONG ProcessId,
    _In_ ULONG Threshold,
    _In_ ULONG WindowMs
    )
{
    KIRQL oldIrql;
    ULONG slot;
    ULONG window;
    BOOLEAN allowed = FALSE;
    LARGE_INTEGER now;
    ULONGLONG nowMs;
    ULONGLONG startMs;
    ULONGLONG elapsedMs;

    if (Threshold <= 1) {
        return TRUE;
    }
    window = WindowMs;
    if (window == 0) {
        window = 1000u;
    } else if (window > 60000u) {
        window = 60000u;
    }

    KeQuerySystemTime(&now);
    nowMs = (ULONGLONG)(now.QuadPart / 10000);

    KeAcquireSpinLock(&g_BehaviorRateLock, &oldIrql);

    for (slot = 0; slot < XDOWS_BEHAVIOR_RATE_SLOTS; slot++) {
        if (g_BehaviorRateSlots[slot].RuleId == RuleId &&
            g_BehaviorRateSlots[slot].ProcessId == ProcessId) {
            break;
        }
    }
    if (slot == XDOWS_BEHAVIOR_RATE_SLOTS) {
        for (slot = 0; slot < XDOWS_BEHAVIOR_RATE_SLOTS; slot++) {
            if (g_BehaviorRateSlots[slot].RuleId == 0) {
                g_BehaviorRateSlots[slot].RuleId = RuleId;
                g_BehaviorRateSlots[slot].ProcessId = ProcessId;
                g_BehaviorRateSlots[slot].Count = 0;
                g_BehaviorRateSlots[slot].WindowStart = now;
                g_BehaviorRateSlots[slot].Flagged = FALSE;
                break;
            }
        }
    }

    if (slot < XDOWS_BEHAVIOR_RATE_SLOTS) {
        PXDOWS_BEHAVIOR_RATE_SLOT entry = &g_BehaviorRateSlots[slot];

        startMs = (ULONGLONG)(entry->WindowStart.QuadPart / 10000);
        elapsedMs = (nowMs >= startMs) ? (nowMs - startMs) : 0;

        if (elapsedMs >= window) {
            entry->Count = 1;
            entry->WindowStart = now;
            entry->Flagged = FALSE;
        } else if (entry->Flagged) {
            allowed = TRUE;
        } else {
            entry->Count++;
            if (entry->Count >= Threshold) {
                entry->Flagged = TRUE;
                allowed = TRUE;
            }
        }
    }

    KeReleaseSpinLock(&g_BehaviorRateLock, oldIrql);
    return allowed;
}

//
// Validate one axis: bounded term count and a null-terminated, non-empty
// string inside the fixed term buffer for every active term.
//
static
NTSTATUS
XdowsBehaviorValidateAxis(
    _In_ PXDOWS_SECURITY_RULE_TERM_AXIS Axis
    )
{
    ULONG i;

    if (Axis->TermCount > XDOWS_SECURITY_MAX_RULE_TERMS) {
        return STATUS_INVALID_PARAMETER;
    }
    for (i = 0; i < Axis->TermCount; i++) {
        size_t length = 0;
        SIZE_T c;

        if (!NT_SUCCESS(RtlStringCchLengthW(
                Axis->Terms[i],
                XDOWS_SECURITY_MAX_RULE_TERM_CHARS,
                &length))) {
            return STATUS_INVALID_PARAMETER;
        }
        if (length == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        //
        // A term must be countable and must not contain a literal wildcard;
        // the interpreter only supports literal matching, so accepting "*.exe"
        // would silently never match and hide a configuration mistake.
        //
        for (c = 0; c < length; c++) {
            if (Axis->Terms[i][c] == L'*' || Axis->Terms[i][c] == L'?') {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
XdowsBehaviorConfigureRules(
    _In_ PXDOWS_SECURITY_BEHAVIOR_RULE_REQUEST Request
    )
{
    ULONG i;

    if (Request == NULL || Request->Enabled > 1 ||
        Request->RuleCount > XDOWS_SECURITY_MAX_BEHAVIOR_RULES) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_RuleSetLockInitialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    for (i = 0; i < Request->RuleCount; i++) {
        PXDOWS_SECURITY_BEHAVIOR_RULE rule = &Request->Rules[i];

        if (rule->RuleId == 0 || rule->BehaviorType == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (rule->TargetMatchKind > XdowsSecurityRuleMatchContains) {
            return STATUS_INVALID_PARAMETER;
        }
        if ((rule->Operations & ~XDOWS_SECURITY_RULE_OPERATION_ALL) != 0 ||
            rule->Operations == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if ((rule->Flags & ~(XDOWS_SECURITY_RULE_FLAG_KILL_ACTOR |
                             XDOWS_SECURITY_RULE_FLAG_FAIL_CLOSED)) != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (rule->Threshold != 0 && rule->Threshold > 10000u) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!NT_SUCCESS(XdowsBehaviorValidateAxis(&rule->Initiator)) ||
            !NT_SUCCESS(XdowsBehaviorValidateAxis(&rule->Target)) ||
            !NT_SUCCESS(XdowsBehaviorValidateAxis(&rule->CommandLine))) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RuleSetLock);
    RtlZeroMemory(g_BehaviorRules, sizeof(g_BehaviorRules));
    if (Request->Enabled != 0 && Request->RuleCount != 0) {
        RtlCopyMemory(
            g_BehaviorRules,
            Request->Rules,
            sizeof(XDOWS_SECURITY_BEHAVIOR_RULE) * Request->RuleCount);
        g_BehaviorRuleCount = Request->RuleCount;
    } else {
        g_BehaviorRuleCount = 0;
    }
    ExReleasePushLockExclusive(&g_RuleSetLock);
    KeLeaveCriticalRegion();

    RtlZeroMemory(g_BehaviorRateSlots, sizeof(g_BehaviorRateSlots));

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Behavior",
        L"Declarative behavior rule set applied.");
    return STATUS_SUCCESS;
}

NTSTATUS
XdowsBehaviorConfigureInitiatorExclusions(
    _In_ PXDOWS_SECURITY_INITIATOR_EXCLUSION_REQUEST Request
    )
{
    ULONG i;

    if (Request == NULL ||
        Request->Count > XDOWS_SECURITY_MAX_INITIATOR_EXCLUSIONS) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_RuleSetLockInitialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    for (i = 0; i < Request->Count; i++) {
        PXDOWS_SECURITY_INITIATOR_EXCLUSION entry = &Request->Entries[i];
        size_t length = 0;

        if ((entry->ScopeMask & ~XDOWS_SECURITY_EXCLUSION_SCOPE_ALL) != 0 ||
            entry->ScopeMask == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!NT_SUCCESS(RtlStringCchLengthW(
                entry->Pattern,
                XDOWS_SECURITY_MAX_EXCLUSION_CHARS,
                &length)) ||
            length == 0) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RuleSetLock);
    RtlZeroMemory(g_InitiatorExclusions, sizeof(g_InitiatorExclusions));
    if (Request->Count != 0) {
        RtlCopyMemory(
            g_InitiatorExclusions,
            Request->Entries,
            sizeof(XDOWS_SECURITY_INITIATOR_EXCLUSION) * Request->Count);
        g_InitiatorExclusionCount = Request->Count;
    } else {
        g_InitiatorExclusionCount = 0;
    }
    ExReleasePushLockExclusive(&g_RuleSetLock);
    KeLeaveCriticalRegion();

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"Behavior",
        L"Initiator exclusion list applied.");
    return STATUS_SUCCESS;
}

BOOLEAN
XdowsBehaviorIsInitiatorExcluded(
    _In_ ULONG Scope,
    _In_opt_ PCUNICODE_STRING ActorPath,
    _In_opt_ PCSTR ActorImageName
    )
{
    ULONG i;
    BOOLEAN excluded = FALSE;

    if (!g_RuleSetLockInitialized || g_InitiatorExclusionCount == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_RuleSetLock);
    for (i = 0; i < g_InitiatorExclusionCount; i++) {
        PXDOWS_SECURITY_INITIATOR_EXCLUSION entry = &g_InitiatorExclusions[i];

        if ((entry->ScopeMask & Scope) == 0) {
            continue;
        }
        if (XdowsBehaviorPatternMatchesActor(
                entry->Pattern,
                ActorPath,
                ActorImageName)) {
            excluded = TRUE;
            break;
        }
    }
    ExReleasePushLockShared(&g_RuleSetLock);
    KeLeaveCriticalRegion();
    return excluded;
}

BOOLEAN
XdowsBehaviorEvaluateCustomRules(
    _In_opt_ PCUNICODE_STRING ActorPath,
    _In_opt_ PCSTR ActorImageName,
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_opt_ PCUNICODE_STRING TargetPath,
    _In_ ULONG Operation,
    _In_ ULONG ActorProcessId,
    _Out_opt_ PULONG MatchedRuleId,
    _Out_opt_ PULONG MatchedRuleFlags,
    _Out_opt_ PULONG MatchedBehaviorType
    )
{
    WCHAR commandLower[XDOWS_BEHAVIOR_MAX_CMD_CHARS];
    SIZE_T commandLength = 0;
    ULONG matchedId = 0;
    ULONG matchedFlags = 0;
    ULONG matchedBehavior = 0;
    ULONG matchedThreshold = 0;
    ULONG matchedWindowMs = 0;
    ULONG i;
    BOOLEAN matched = FALSE;

    if (MatchedRuleId != NULL) {
        *MatchedRuleId = 0;
    }
    if (MatchedRuleFlags != NULL) {
        *MatchedRuleFlags = 0;
    }
    if (MatchedBehaviorType != NULL) {
        *MatchedBehaviorType = 0;
    }
    if (!g_RuleSetLockInitialized || g_BehaviorRuleCount == 0) {
        return FALSE;
    }

    if (CommandLine != NULL && CommandLine->Buffer != NULL &&
        CommandLine->Length != 0) {
        XdowsBehaviorLowercaseInto(
            commandLower,
            RTL_NUMBER_OF(commandLower),
            CommandLine);
        commandLength = wcsnlen(commandLower, RTL_NUMBER_OF(commandLower));
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_RuleSetLock);
    for (i = 0; i < g_BehaviorRuleCount; i++) {
        PXDOWS_SECURITY_BEHAVIOR_RULE rule = &g_BehaviorRules[i];

        if ((rule->Operations & Operation) == 0) {
            continue;
        }
        if (!XdowsBehaviorRuleInitiatorMatches(rule, ActorPath, ActorImageName)) {
            continue;
        }
        if (!XdowsBehaviorRuleCommandLineMatches(rule, commandLower, commandLength)) {
            continue;
        }
        if (!XdowsBehaviorRuleTargetMatches(rule, TargetPath)) {
            continue;
        }

        matchedId = rule->RuleId;
        matchedFlags = rule->Flags;
        matchedBehavior = rule->BehaviorType;
        matchedThreshold = rule->Threshold;
        matchedWindowMs = rule->WindowMs;
        break;
    }
    ExReleasePushLockShared(&g_RuleSetLock);
    KeLeaveCriticalRegion();

    //
    // The rate gate runs after the lock is released: KeAcquireSpinLock raises
    // IRQL to DISPATCH_LEVEL, which must not happen while a push lock is held.
    //
    if (matchedId != 0 && matchedThreshold != 0 &&
        !XdowsBehaviorRuleRateAllows(
            matchedId,
            ActorProcessId,
            matchedThreshold,
            matchedWindowMs)) {
        matchedId = 0;
    }

    if (matchedId != 0) {
        matched = TRUE;
        if (MatchedRuleId != NULL) {
            *MatchedRuleId = matchedId;
        }
        if (MatchedRuleFlags != NULL) {
            *MatchedRuleFlags = matchedFlags;
        }
        if (MatchedBehaviorType != NULL) {
            *MatchedBehaviorType = matchedBehavior;
        }
    }
    return matched;
}

PCWSTR
XdowsBehaviorTypeName(
    _In_ XDOWS_SECURITY_BEHAVIOR_TYPE Type
    )
{
    switch (Type) {
    case XdowsSecurityBehaviorVssDeletion:       return L"VssDeletion";
    case XdowsSecurityBehaviorHiddenPowerShell:  return L"HiddenPowerShell";
    case XdowsSecurityBehaviorEncodedCommand:    return L"EncodedCommand";
    case XdowsSecurityBehaviorPolicyBypass:      return L"PolicyBypass";
    case XdowsSecurityBehaviorDownloadExecute:   return L"DownloadExecute";
    case XdowsSecurityBehaviorLolbinAbuse:       return L"LolbinAbuse";
    case XdowsSecurityBehaviorProcessInjection:  return L"ProcessInjection";
    case XdowsSecurityBehaviorThreadInjection:   return L"ThreadInjection";
    case XdowsSecurityBehaviorParentProcessChain: return L"ParentProcessChain";
    case XdowsSecurityBehaviorAutorunInf:         return L"AutorunInf";
    case XdowsSecurityBehaviorProtectedProcessTerminate: return L"ProtectedProcessTerminate";
    case XdowsSecurityBehaviorSensitiveProcessHandle:   return L"SensitiveProcessHandle";
    case XdowsSecurityBehaviorDestructiveDirectoryDelete: return L"DestructiveDirectoryDelete";
    case XdowsSecurityBehaviorOwnershipEscalation:  return L"OwnershipEscalation";
    case XdowsSecurityBehaviorSystemControlCommand: return L"SystemControlCommand";
    case XdowsSecurityBehaviorEfiMount:            return L"EfiMount";
    case XdowsSecurityBehaviorOobeReset:           return L"OobeReset";
    case XdowsSecurityBehaviorSystemDirectoryRansomware: return L"SystemDirectoryRansomware";
    default:                             return L"None";
    }
}

//
// TRUE if the EPROCESS 15-char image name is one of the Windows script
// hosts used by the in-kernel system-directory ransomware monitor. Shares
// the same membership list as the parent-chain rule so both detections
// agree on what a script host is.
//
BOOLEAN
XdowsBehaviorImageNameIsScriptHost(
    _In_ PCSTR ImageName
    )
{
    static const PCSTR scriptHosts[] = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
    };
    SIZE_T i;

    if (ImageName == NULL) {
        return FALSE;
    }
    for (i = 0; i < RTL_NUMBER_OF(scriptHosts); i++) {
        if (XdowsBehaviorImageNameEquals(ImageName, scriptHosts[i])) {
            return TRUE;
        }
    }
    return FALSE;
}
