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
// Initialize the monitor. Must be called exactly once at driver start.
//
VOID
XdowsRansomwareMonitorInitialize(
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
XdowsRansomwareMonitorRecordWrite(
    _In_ ULONG OriginatorPid,
    _In_opt_ PCUNICODE_STRING Path
    );

//
// Check whether a process is currently flagged for ransomware behavior
// without recording a new write. Used by the pre-create path to block
// opens from an already-flagged process before the write happens.
//
BOOLEAN
XdowsRansomwareMonitorIsFlagged(
    _In_ ULONG OriginatorPid
    );

//
// Clear the tracking state for a process (e.g. on process exit).
//
VOID
XdowsRansomwareMonitorResetProcess(
    _In_ ULONG OriginatorPid
    );

EXTERN_C_END
