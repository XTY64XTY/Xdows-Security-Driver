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
