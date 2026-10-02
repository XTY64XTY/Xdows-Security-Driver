/*++

Module Name:

    ransomwaremonitor.h

Abstract:

    Per-process sliding-window file-write rate monitor for ransomware
    detection.

    Tracks document-file modifications per originator process within a
    bounded time window. When a process exceeds the write-count threshold
    inside the window, subsequent writes from that process are flagged as
    ransomware behavior, allowing the file minifilter to block them
    immediately without waiting for the user-mode model scan.

    The monitor uses a fixed-size slot table protected by a spinlock. No
    dynamic allocation occurs on the hot path. Expired slots are reclaimed
    lazily on lookup.

Environment:

    Kernel-mode Driver Framework

--*/

#pragma once

EXTERN_C_START

//
// Configuration constants. The window and threshold mirror the values used
// by mainstream EDR products: a legitimate process rarely modifies more
// than a handful of document files per second, while ransomware typically
// touches dozens within the first few seconds of execution.
//
#define XDOWS_RANSOM_WINDOW_MS         3000u
#define XDOWS_RANSOM_FILE_THRESHOLD    10u
#define XDOWS_RANSOM_MAX_TRACKED_PIDS  64u

//
// System-directory dimension (script-host mass delete under \Windows\).
// The threshold is deliberately much looser than the user-data threshold:
// Windows\ carries far more legitimate churn (servicing, component store
// cleanup) than user folders, but a *script host* crossing 50 destructive
// opens inside 3 seconds under the OS directory is a wipe, not churn.
//
#define XDOWS_RANSOM_SYS_WINDOW_MS         3000u
#define XDOWS_RANSOM_SYS_FILE_THRESHOLD    50u

//
// Initialize the monitor. Must be called exactly once at driver start.
//
VOID
RansomwareMonitorInitialize(
    VOID
    );

//
// Record a document-file write by the given process and return TRUE if the
// process has exceeded the ransomware threshold within the sliding window.
//
// Once a process is flagged, it remains flagged until the window expires,
// so subsequent calls for the same process return TRUE immediately without
// further counting. This lets the minifilter block the entire encryption
// burst after the first threshold crossing.
//
// Path is the file being written; it is only consulted for the document-
// extension check and is not retained.
//
BOOLEAN
RansomwareMonitorRecordWrite(
    _In_ ULONG OriginatorPid,
    _In_opt_ PCUNICODE_STRING Path
    );

//
// Check whether a process is currently flagged for ransomware behavior
// without recording a new write. Used by the pre-create path to block
// opens from an already-flagged process before the write happens.
//
BOOLEAN
RansomwareMonitorIsFlagged(
    _In_ ULONG OriginatorPid
    );

//
// Record a destructive open (DELETE access) issued by a script host against
// a file under the Windows directory, and return TRUE when the process has
// crossed the system-directory threshold within the system window. The
// caller has already established that the requestor is a script host; this
// function re-checks the \Windows\ path condition and returns FALSE without
// recording when the target is elsewhere.
//
BOOLEAN
RansomwareMonitorRecordSystemDelete(
    _In_ ULONG OriginatorPid,
    _In_opt_ PCUNICODE_STRING Path
    );

//
// Clear the tracking state for a process (e.g. on process exit). Clears
// both the user-data and the system-directory slot tables.
//
VOID
RansomwareMonitorResetProcess(
    _In_ ULONG OriginatorPid
    );

EXTERN_C_END
