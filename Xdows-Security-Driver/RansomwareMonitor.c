/*++

Module Name:

    ransomwaremonitor.c

Abstract:

    Per-process sliding-window file-write rate monitor for ransomware
    detection.

    Design:
      * Fixed-size slot array (64 entries), no dynamic allocation.
      * Spinlock-protected; safe to call from minifilter callbacks which
        run at PASSIVE_LEVEL (IRP_MJ_CREATE pre-op).
      * Each slot records the originator PID, a write counter, a window
        start timestamp, and a "flagged" bit. The window is sliding: on
        each lookup, if the elapsed time exceeds the window, the slot is
        reset and counting restarts from 1.
      * Document extensions are checked via a compile-time table of
        RTL_CONSTANT_STRING entries; only document files increment the
        counter, so background log/config writes do not trip the monitor.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "RansomwareMonitor.h"
#include <ntstrsafe.h>

typedef struct _XDOWS_RANSOM_SLOT {
    ULONG             ProcessId;
    ULONG             FileCount;
    LARGE_INTEGER     WindowStart;
    BOOLEAN           Flagged;
} XDOWS_RANSOM_SLOT, *PXDOWS_RANSOM_SLOT;

static XDOWS_RANSOM_SLOT g_RansomSlots[XDOWS_RANSOM_MAX_TRACKED_PIDS];

//
// Second dimension: destructive opens (DELETE access) by script hosts
// against the Windows directory. Kept in a separate slot table so a
// process can be tracked independently in both dimensions without one
// counter starving the other.
//
static XDOWS_RANSOM_SLOT g_RansomSysSlots[XDOWS_RANSOM_MAX_TRACKED_PIDS];

static KSPIN_LOCK         g_RansomLock;

//
// Document-type extensions. Only writes to these extensions increment the
// per-process counter. The list targets user-facing data formats that
// ransomware encrypts; system binaries and temp files are excluded.
//
// Class coverage: office/text (documents), photo/audio/video (media),
// archives, databases, design/CAD. The media class was widened to the
// formats mainstream encryptors additionally chase (lossless audio, camera
// RAW successors, web imagery, additional video containers). All thresholds
// live in RansomwareMonitor.h as named constants.
//
static const UNICODE_STRING g_DocumentExtensions[] = {
    RTL_CONSTANT_STRING(L".doc"),   RTL_CONSTANT_STRING(L".docx"),
    RTL_CONSTANT_STRING(L".xls"),   RTL_CONSTANT_STRING(L".xlsx"),
    RTL_CONSTANT_STRING(L".ppt"),   RTL_CONSTANT_STRING(L".pptx"),
    RTL_CONSTANT_STRING(L".pdf"),   RTL_CONSTANT_STRING(L".odt"),
    RTL_CONSTANT_STRING(L".ods"),   RTL_CONSTANT_STRING(L".odp"),
    RTL_CONSTANT_STRING(L".rtf"),   RTL_CONSTANT_STRING(L".txt"),
    RTL_CONSTANT_STRING(L".csv"),   RTL_CONSTANT_STRING(L".epub"),
    RTL_CONSTANT_STRING(L".jpg"),   RTL_CONSTANT_STRING(L".jpeg"),
    RTL_CONSTANT_STRING(L".png"),   RTL_CONSTANT_STRING(L".bmp"),
    RTL_CONSTANT_STRING(L".gif"),   RTL_CONSTANT_STRING(L".tiff"),
    RTL_CONSTANT_STRING(L".heic"),  RTL_CONSTANT_STRING(L".webp"),
    RTL_CONSTANT_STRING(L".mp3"),   RTL_CONSTANT_STRING(L".mp4"),
    RTL_CONSTANT_STRING(L".avi"),   RTL_CONSTANT_STRING(L".mov"),
    RTL_CONSTANT_STRING(L".mkv"),   RTL_CONSTANT_STRING(L".wav"),
    RTL_CONSTANT_STRING(L".flac"),  RTL_CONSTANT_STRING(L".aac"),
    RTL_CONSTANT_STRING(L".m4a"),   RTL_CONSTANT_STRING(L".m4v"),
    RTL_CONSTANT_STRING(L".wmv"),   RTL_CONSTANT_STRING(L".mpg"),
    RTL_CONSTANT_STRING(L".mpeg"),  RTL_CONSTANT_STRING(L".3gp"),
    RTL_CONSTANT_STRING(L".flv"),
    RTL_CONSTANT_STRING(L".zip"),   RTL_CONSTANT_STRING(L".rar"),
    RTL_CONSTANT_STRING(L".7z"),    RTL_CONSTANT_STRING(L".tar"),
    RTL_CONSTANT_STRING(L".gz"),
    RTL_CONSTANT_STRING(L".sql"),   RTL_CONSTANT_STRING(L".mdb"),
    RTL_CONSTANT_STRING(L".accdb"),
    RTL_CONSTANT_STRING(L".psd"),   RTL_CONSTANT_STRING(L".ai"),
    RTL_CONSTANT_STRING(L".indd"),
    RTL_CONSTANT_STRING(L".dwg"),   RTL_CONSTANT_STRING(L".dxf"),
    RTL_CONSTANT_STRING(L".vsd"),   RTL_CONSTANT_STRING(L".one")
};

static
BOOLEAN
XdowsRansomIsDocumentPath(
    _In_opt_ PCUNICODE_STRING Path
    )
{
    ULONG i;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_DocumentExtensions); i++) {
        if (Path->Length >= g_DocumentExtensions[i].Length &&
            RtlSuffixUnicodeString(
                (PUNICODE_STRING)&g_DocumentExtensions[i],
                (PUNICODE_STRING)Path, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// TRUE if the normalized path contains the given directory segment bounded
// by backslashes (so "\Windows\" matches but "\WindowsOld\" does not). The
// path is not guaranteed to be null-terminated, so every access is
// bounds-checked against Length.
//
static
BOOLEAN
XdowsRansomPathContainsSegment(
    _In_ PCUNICODE_STRING Path,
    _In_ PCWSTR Segment
    )
{
    SIZE_T pathLen;
    SIZE_T segmentLen;
    SIZE_T i;

    if (Path == NULL || Path->Buffer == NULL || Segment == NULL) {
        return FALSE;
    }

    pathLen = Path->Length / sizeof(WCHAR);
    segmentLen = wcslen(Segment);
    if (segmentLen == 0 || pathLen < segmentLen + 2) {
        return FALSE;
    }

    for (i = 0; i + segmentLen + 1 < pathLen; i++) {
        if (Path->Buffer[i] != L'\\') {
            continue;
        }
        if (_wcsnicmp(Path->Buffer + i + 1, Segment, segmentLen) == 0 &&
            Path->Buffer[i + 1 + segmentLen] == L'\\') {
            return TRUE;
        }
    }
    return FALSE;
}

//
// TRUE when the target of a destructive open lives under the Windows
// directory (including WinSxS, System32, SysWOW64 -- every "\Windows\"
// subtree). Covers the OS directory on any volume; the segment match is
// case-insensitive.
//
static
BOOLEAN
XdowsRansomIsSystemDirectoryPath(
    _In_opt_ PCUNICODE_STRING Path
    )
{
    return XdowsRansomPathContainsSegment(Path, L"Windows");
}

//
// Shared sliding-window bookkeeping for both slot tables. Records one
// counted event for OriginatorPid in Table and returns TRUE when the
// process has crossed its threshold (window/threshold constants chosen by
// the caller dimension) within the window, or was already flagged.
// Caller must not hold g_RansomLock.
//
static
FORCEINLINE
ULONGLONG
XdowsRansomTimeToMs(
    _In_ LARGE_INTEGER SystemTime
    );

static
BOOLEAN
XdowsRansomRecordInTable(
    _Inout_ XDOWS_RANSOM_SLOT Table[],
    _In_ ULONG OriginatorPid,
    _In_ LARGE_INTEGER Now,
    _In_ ULONGLONG WindowMs,
    _In_ ULONG Threshold
    )
{
    KIRQL oldIrql;
    ULONG slot;
    BOOLEAN flagged = FALSE;
    ULONGLONG nowMs;
    ULONGLONG startMs;
    ULONGLONG elapsedMs;

    nowMs = XdowsRansomTimeToMs(Now);

    KeAcquireSpinLock(&g_RansomLock, &oldIrql);

    //
    // Find an existing slot for this PID, or claim the first empty one.
    //
    for (slot = 0; slot < XDOWS_RANSOM_MAX_TRACKED_PIDS; slot++) {
        if (Table[slot].ProcessId == OriginatorPid) {
            break;
        }
    }

    if (slot == XDOWS_RANSOM_MAX_TRACKED_PIDS) {
        //
        // No existing slot: claim the first empty one.
        //
        for (slot = 0; slot < XDOWS_RANSOM_MAX_TRACKED_PIDS; slot++) {
            if (Table[slot].ProcessId == 0) {
                Table[slot].ProcessId = OriginatorPid;
                Table[slot].FileCount = 0;
                Table[slot].WindowStart = Now;
                Table[slot].Flagged = FALSE;
                break;
            }
        }
    }

    if (slot < XDOWS_RANSOM_MAX_TRACKED_PIDS) {
        PXDOWS_RANSOM_SLOT entry = &Table[slot];

        //
        // If already flagged and the window has not expired, keep blocking.
        //
        if (entry->Flagged) {
            startMs = XdowsRansomTimeToMs(entry->WindowStart);
            elapsedMs = (nowMs >= startMs) ? (nowMs - startMs) : 0;
            if (elapsedMs < WindowMs) {
                flagged = TRUE;
            } else {
                //
                // Window expired: reset and start a new counting cycle.
                //
                entry->FileCount = 1;
                entry->WindowStart = Now;
                entry->Flagged = FALSE;
            }
        } else {
            startMs = XdowsRansomTimeToMs(entry->WindowStart);
            elapsedMs = (nowMs >= startMs) ? (nowMs - startMs) : 0;

            if (elapsedMs >= WindowMs) {
                //
                // Window expired: restart counting from this write.
                //
                entry->FileCount = 1;
                entry->WindowStart = Now;
                entry->Flagged = FALSE;
            } else {
                entry->FileCount++;
                if (entry->FileCount >= Threshold) {
                    entry->Flagged = TRUE;
                    flagged = TRUE;
                }
            }
        }
    }

    KeReleaseSpinLock(&g_RansomLock, oldIrql);
    return flagged;
}

//
// Convert a KeQuerySystemTime value to milliseconds.
// System time is in 100-nanosecond intervals; divide by 10,000 to get ms.
//
static
FORCEINLINE
ULONGLONG
XdowsRansomTimeToMs(
    _In_ LARGE_INTEGER SystemTime
    )
{
    return (ULONGLONG)(SystemTime.QuadPart / 10000);
}

VOID
XdowsRansomwareMonitorInitialize(
    VOID
    )
{
    RtlZeroMemory(g_RansomSlots, sizeof(g_RansomSlots));
    RtlZeroMemory(g_RansomSysSlots, sizeof(g_RansomSysSlots));
    KeInitializeSpinLock(&g_RansomLock);
}

BOOLEAN
XdowsRansomwareMonitorRecordWrite(
    _In_ ULONG OriginatorPid,
    _In_opt_ PCUNICODE_STRING Path
    )
{
    LARGE_INTEGER now;

    if (OriginatorPid == 0) {
        return FALSE;
    }

    //
    // Only document-file writes count toward the threshold. Non-document
    // writes (e.g. .log, .tmp) are ignored to avoid false positives from
    // normal application housekeeping.
    //
    if (!XdowsRansomIsDocumentPath(Path)) {
        return FALSE;
    }

    KeQuerySystemTime(&now);
    return XdowsRansomRecordInTable(
        g_RansomSlots,
        OriginatorPid,
        now,
        XDOWS_RANSOM_WINDOW_MS,
        XDOWS_RANSOM_FILE_THRESHOLD);
}

BOOLEAN
XdowsRansomwareMonitorRecordSystemDelete(
    _In_ ULONG OriginatorPid,
    _In_opt_ PCUNICODE_STRING Path
    )
{
    LARGE_INTEGER now;

    if (OriginatorPid == 0) {
        return FALSE;
    }

    //
    // The caller established the script-host condition; the \Windows\
    // target condition is re-checked here so the monitor stays the single
    // owner of the path rule.
    //
    if (!XdowsRansomIsSystemDirectoryPath(Path)) {
        return FALSE;
    }

    KeQuerySystemTime(&now);
    return XdowsRansomRecordInTable(
        g_RansomSysSlots,
        OriginatorPid,
        now,
        XDOWS_RANSOM_SYS_WINDOW_MS,
        XDOWS_RANSOM_SYS_FILE_THRESHOLD);
}

VOID
XdowsRansomwareMonitorResetProcess(
    _In_ ULONG OriginatorPid
    )
{
    KIRQL oldIrql;
    ULONG slot;

    KeAcquireSpinLock(&g_RansomLock, &oldIrql);

    for (slot = 0; slot < XDOWS_RANSOM_MAX_TRACKED_PIDS; slot++) {
        if (g_RansomSlots[slot].ProcessId == OriginatorPid) {
            g_RansomSlots[slot].ProcessId = 0;
            g_RansomSlots[slot].FileCount = 0;
            g_RansomSlots[slot].Flagged = FALSE;
            break;
        }
    }

    for (slot = 0; slot < XDOWS_RANSOM_MAX_TRACKED_PIDS; slot++) {
        if (g_RansomSysSlots[slot].ProcessId == OriginatorPid) {
            g_RansomSysSlots[slot].ProcessId = 0;
            g_RansomSysSlots[slot].FileCount = 0;
            g_RansomSysSlots[slot].Flagged = FALSE;
            break;
        }
    }

    KeReleaseSpinLock(&g_RansomLock, oldIrql);
}

BOOLEAN
XdowsRansomwareMonitorIsFlagged(
    _In_ ULONG OriginatorPid
    )
{
    KIRQL oldIrql;
    ULONG slot;
    BOOLEAN flagged = FALSE;
    LARGE_INTEGER now;
    ULONGLONG nowMs;
    ULONGLONG startMs;
    ULONGLONG elapsedMs;

    if (OriginatorPid == 0) {
        return FALSE;
    }

    KeQuerySystemTime(&now);
    nowMs = XdowsRansomTimeToMs(now);

    KeAcquireSpinLock(&g_RansomLock, &oldIrql);

    for (slot = 0; slot < XDOWS_RANSOM_MAX_TRACKED_PIDS; slot++) {
        if (g_RansomSlots[slot].ProcessId == OriginatorPid &&
            g_RansomSlots[slot].Flagged) {
            //
            // Verify the window has not expired. If it has, clear the flag
            // so the process can start fresh.
            //
            startMs = XdowsRansomTimeToMs(g_RansomSlots[slot].WindowStart);
            elapsedMs = (nowMs >= startMs) ? (nowMs - startMs) : 0;

            if (elapsedMs < XDOWS_RANSOM_WINDOW_MS) {
                flagged = TRUE;
            } else {
                g_RansomSlots[slot].Flagged = FALSE;
                g_RansomSlots[slot].FileCount = 0;
            }
            break;
        }
    }

    if (!flagged) {
        for (slot = 0; slot < XDOWS_RANSOM_MAX_TRACKED_PIDS; slot++) {
            if (g_RansomSysSlots[slot].ProcessId == OriginatorPid &&
                g_RansomSysSlots[slot].Flagged) {
                startMs = XdowsRansomTimeToMs(g_RansomSysSlots[slot].WindowStart);
                elapsedMs = (nowMs >= startMs) ? (nowMs - startMs) : 0;

                if (elapsedMs < XDOWS_RANSOM_SYS_WINDOW_MS) {
                    flagged = TRUE;
                } else {
                    g_RansomSysSlots[slot].Flagged = FALSE;
                    g_RansomSysSlots[slot].FileCount = 0;
                }
                break;
            }
        }
    }

    KeReleaseSpinLock(&g_RansomLock, oldIrql);
    return flagged;
}
