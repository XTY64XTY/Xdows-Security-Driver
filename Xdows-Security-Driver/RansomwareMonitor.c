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
static KSPIN_LOCK         g_RansomLock;

//
// Document-type extensions. Only writes to these extensions increment the
// per-process counter. The list targets user-facing data formats that
// ransomware encrypts; system binaries and temp files are excluded.
//
static const UNICODE_STRING g_DocumentExtensions[] = {
    RTL_CONSTANT_STRING(L".doc"),   RTL_CONSTANT_STRING(L".docx"),
    RTL_CONSTANT_STRING(L".xls"),   RTL_CONSTANT_STRING(L".xlsx"),
    RTL_CONSTANT_STRING(L".ppt"),   RTL_CONSTANT_STRING(L".pptx"),
    RTL_CONSTANT_STRING(L".pdf"),   RTL_CONSTANT_STRING(L".odt"),
    RTL_CONSTANT_STRING(L".ods"),   RTL_CONSTANT_STRING(L".odp"),
    RTL_CONSTANT_STRING(L".rtf"),   RTL_CONSTANT_STRING(L".txt"),
    RTL_CONSTANT_STRING(L".csv"),
    RTL_CONSTANT_STRING(L".jpg"),   RTL_CONSTANT_STRING(L".jpeg"),
    RTL_CONSTANT_STRING(L".png"),   RTL_CONSTANT_STRING(L".bmp"),
    RTL_CONSTANT_STRING(L".gif"),   RTL_CONSTANT_STRING(L".tiff"),
    RTL_CONSTANT_STRING(L".mp3"),   RTL_CONSTANT_STRING(L".mp4"),
    RTL_CONSTANT_STRING(L".avi"),   RTL_CONSTANT_STRING(L".mov"),
    RTL_CONSTANT_STRING(L".mkv"),
    RTL_CONSTANT_STRING(L".zip"),   RTL_CONSTANT_STRING(L".rar"),
    RTL_CONSTANT_STRING(L".7z"),    RTL_CONSTANT_STRING(L".tar"),
    RTL_CONSTANT_STRING(L".gz"),
    RTL_CONSTANT_STRING(L".sql"),   RTL_CONSTANT_STRING(L".mdb"),
    RTL_CONSTANT_STRING(L".accdb"),
    RTL_CONSTANT_STRING(L".psd"),   RTL_CONSTANT_STRING(L".ai"),
    RTL_CONSTANT_STRING(L".indd"),
    RTL_CONSTANT_STRING(L".dwg"),   RTL_CONSTANT_STRING(L".dxf"),
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
    KeInitializeSpinLock(&g_RansomLock);
}

BOOLEAN
XdowsRansomwareMonitorRecordWrite(
    _In_ ULONG OriginatorPid,
    _In_opt_ PCUNICODE_STRING Path
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

    //
    // Only document-file writes count toward the threshold. Non-document
    // writes (e.g. .log, .tmp) are ignored to avoid false positives from
    // normal application housekeeping.
    //
    if (!XdowsRansomIsDocumentPath(Path)) {
        return FALSE;
    }

    KeQuerySystemTime(&now);
    nowMs = XdowsRansomTimeToMs(now);

    KeAcquireSpinLock(&g_RansomLock, &oldIrql);

    //
    // Find an existing slot for this PID, or claim the first empty one.
    //
    for (slot = 0; slot < XDOWS_RANSOM_MAX_TRACKED_PIDS; slot++) {
        if (g_RansomSlots[slot].ProcessId == OriginatorPid) {
            break;
        }
    }

    if (slot == XDOWS_RANSOM_MAX_TRACKED_PIDS) {
        //
        // No existing slot: claim the first empty one.
        //
        for (slot = 0; slot < XDOWS_RANSOM_MAX_TRACKED_PIDS; slot++) {
            if (g_RansomSlots[slot].ProcessId == 0) {
                g_RansomSlots[slot].ProcessId = OriginatorPid;
                g_RansomSlots[slot].FileCount = 0;
                g_RansomSlots[slot].WindowStart = now;
                g_RansomSlots[slot].Flagged = FALSE;
                break;
            }
        }
    }

    if (slot < XDOWS_RANSOM_MAX_TRACKED_PIDS) {
        PXDOWS_RANSOM_SLOT entry = &g_RansomSlots[slot];

        //
        // If already flagged and the window has not expired, keep blocking.
        //
        if (entry->Flagged) {
            startMs = XdowsRansomTimeToMs(entry->WindowStart);
            elapsedMs = (nowMs >= startMs) ? (nowMs - startMs) : 0;
            if (elapsedMs < XDOWS_RANSOM_WINDOW_MS) {
                flagged = TRUE;
            } else {
                //
                // Window expired: reset and start a new counting cycle.
                //
                entry->FileCount = 1;
                entry->WindowStart = now;
                entry->Flagged = FALSE;
            }
        } else {
            startMs = XdowsRansomTimeToMs(entry->WindowStart);
            elapsedMs = (nowMs >= startMs) ? (nowMs - startMs) : 0;

            if (elapsedMs >= XDOWS_RANSOM_WINDOW_MS) {
                //
                // Window expired: restart counting from this write.
                //
                entry->FileCount = 1;
                entry->WindowStart = now;
                entry->Flagged = FALSE;
            } else {
                entry->FileCount++;
                if (entry->FileCount >= XDOWS_RANSOM_FILE_THRESHOLD) {
                    entry->Flagged = TRUE;
                    flagged = TRUE;
                }
            }
        }
    }

    KeReleaseSpinLock(&g_RansomLock, oldIrql);
    return flagged;
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

    KeReleaseSpinLock(&g_RansomLock, oldIrql);
    return flagged;
}
