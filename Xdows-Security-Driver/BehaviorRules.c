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
        canonical ransomware precursor and must be blocked before the
        user-mode model scan completes.
      * PowerShell -enc / -encodedcommand and -ExecutionPolicy Bypass are
        matched only when the command line contains "powershell" or "pwsh",
        to avoid flagging legitimate tools that accept similar arguments.
        PolicyBypass is detected and logged but not blocked in the kernel
        fast-path; the user-mode model makes the final decision.
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
XDOWS_BEHAVIOR_TYPE
XdowsBehaviorInspectCommandLine(
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    WCHAR cmd[XDOWS_BEHAVIOR_MAX_CMD_CHARS];
    SIZE_T cmdLen;

    if (CommandLine == NULL || CommandLine->Buffer == NULL ||
        CommandLine->Length == 0) {
        return XdowsBehaviorNone;
    }

    XdowsBehaviorLowercaseInto(cmd, RTL_NUMBER_OF(cmd), CommandLine);
    cmdLen = wcsnlen(cmd, RTL_NUMBER_OF(cmd));
    if (cmdLen == 0) {
        return XdowsBehaviorNone;
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
        return XdowsBehaviorVssDeletion;
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
        return XdowsBehaviorHiddenPowerShell;
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
        return XdowsBehaviorEncodedCommand;
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
        return XdowsBehaviorPolicyBypass;
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
        return XdowsBehaviorDownloadExecute;
    }

    //
    // Rule 6: LOLBin abuse.
    //   certutil -urlcache  (download disguised as cache verification)
    //   mshta http|javascript|vbscript  (scriptlet download via HTA)
    //   rundll32 javascript:  (rare legitimate use)
    //
    if (XdowsBehaviorContainsW(cmd, cmdLen, L"certutil") &&
        XdowsBehaviorContainsW(cmd, cmdLen, L"-urlcache")) {
        return XdowsBehaviorLolbinAbuse;
    }

    if (XdowsBehaviorContainsW(cmd, cmdLen, L"mshta") &&
        (XdowsBehaviorContainsW(cmd, cmdLen, L"http") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"javascript") ||
         XdowsBehaviorContainsW(cmd, cmdLen, L"vbscript"))) {
        return XdowsBehaviorLolbinAbuse;
    }

    if (XdowsBehaviorContainsW(cmd, cmdLen, L"rundll32") &&
        XdowsBehaviorContainsW(cmd, cmdLen, L"javascript:")) {
        return XdowsBehaviorLolbinAbuse;
    }

    return XdowsBehaviorNone;
}

PCWSTR
XdowsBehaviorTypeName(
    _In_ XDOWS_BEHAVIOR_TYPE Type
    )
{
    switch (Type) {
    case XdowsBehaviorVssDeletion:       return L"VssDeletion";
    case XdowsBehaviorHiddenPowerShell:  return L"HiddenPowerShell";
    case XdowsBehaviorEncodedCommand:    return L"EncodedCommand";
    case XdowsBehaviorPolicyBypass:      return L"PolicyBypass";
    case XdowsBehaviorDownloadExecute:   return L"DownloadExecute";
    case XdowsBehaviorLolbinAbuse:       return L"LolbinAbuse";
    default:                             return L"None";
    }
}
