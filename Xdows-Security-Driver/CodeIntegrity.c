/*++

Module Name:

    codeintegrity.c

Abstract:

    Authenticode verification through the Windows Code Integrity module
    (ci.dll). Injection protection uses the cached verdict to suppress noisy
    consultations for signed source processes.

    CiValidateFileObject and CiFreePolicyInfo are private, version-sensitive
    exports. They are resolved at runtime, and any resolution, registration,
    allocation, or validation failure degrades to an unknown verdict. The
    injection module then follows its normal user-mode policy path.

    Object-manager pre-operation callbacks execute with normal kernel APCs
    disabled. CiValidateFileObject can map and read the entire executable, so
    it must never be called there. A process-notify callback queues validation
    to a system worker; the injection hot path only performs a bounded cache
    lookup keyed by PID and process creation time.

    The driver starts on demand (SERVICE_DEMAND_START), so the image file of
    nearly every running process already existed before this module loaded
    and will never be seen by the create-notify callback. An initial sweep
    therefore enumerates existing processes through
    ZwQuerySystemInformation(SystemProcessInformation) and resolves each PID
    with PsLookupProcessByProcessId. PsGetNextProcess must NOT be used here:
    despite being declared in the WDK headers, it is not present in the
    ntoskrnl export table on current Windows builds, so resolving it through
    MmGetSystemRoutineAddress always fails and the sweep silently degrades
    into a no-op - which left every pre-existing process without a cached
    verdict and defeated the whole fast-allow path.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "codeintegrity.h"
#include <ntimage.h>
#include <bcrypt.h>
#include <ntstrsafe.h>

#define XDOWS_SYSTEM_MODULE_INFORMATION_CLASS 11u
#define XDOWS_SYSTEM_PROCESS_INFORMATION_CLASS 5u
#define XDOWS_CI_MODULE_NAME "ci.dll"
#define XDOWS_CI_POOL_TAG 'iCsX'
#define XDOWS_CI_POLICY_ACCEPT_ANY_ROOT_CERTIFICATE 0x00000020u
#define XDOWS_CI_THUMBPRINT_BYTES 64u
#define XDOWS_CI_CACHE_SLOTS 512u
#define XDOWS_CI_MAX_QUEUED_WORK 64
#define XDOWS_CI_CALG_SHA256 0x800Cu
#define XDOWS_CI_DIGEST_BYTES 32u
#define XDOWS_CI_HEADER_BUFFER_BYTES (16u * 1024u)
#define XDOWS_CI_READ_CHUNK_BYTES (64u * 1024u)

typedef NTSTATUS (NTAPI *XDOWS_ZW_QUERY_SYSTEM_INFORMATION)(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI *XDOWS_PS_LOOKUP_PROCESS_BY_ID)(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

typedef NTSTATUS (NTAPI *XDOWS_PS_REFERENCE_PROCESS_FILE_POINTER)(
    _In_ PEPROCESS Process,
    _Outptr_ PFILE_OBJECT* FileObject
    );

typedef struct _XDOWS_MINCRYPT_POLICY_INFO {
    ULONG Size;
    NTSTATUS VerificationStatus;
    ULONG PolicyBits;
    PVOID ChainInfo;
    LARGE_INTEGER RevocationTime;
    LARGE_INTEGER ValidFromTime;
    LARGE_INTEGER ValidToTime;
} XDOWS_MINCRYPT_POLICY_INFO, *PXDOWS_MINCRYPT_POLICY_INFO;

typedef NTSTATUS (NTAPI *XDOWS_CI_VALIDATE_FILE_OBJECT)(
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG PolicyFlags,
    _In_ ULONG LevelCheck,
    _Inout_ PXDOWS_MINCRYPT_POLICY_INFO PolicyInfo,
    _Inout_ PXDOWS_MINCRYPT_POLICY_INFO TimeStampPolicyInfo,
    _Out_ PLARGE_INTEGER SigningTime,
    _Out_writes_bytes_(*ThumbprintSize) PUCHAR Thumbprint,
    _Inout_ PULONG ThumbprintSize,
    _Out_ PULONG ThumbprintAlgorithm
    );

typedef VOID (NTAPI *XDOWS_CI_FREE_POLICY_INFO)(
    _Inout_ PXDOWS_MINCRYPT_POLICY_INFO PolicyInfo
    );

//
// CiVerifyHashInCatalog, modern prototype (build 6.1.7601.18519 and later,
// i.e. every Windows 10/11). Takes an Authenticode file digest and reports
// whether it is covered by a verified OS catalog. All output structures are
// optional; passing NULL avoids the matching release obligation.
//
typedef NTSTATUS (NTAPI *XDOWS_CI_VERIFY_HASH_IN_CATALOG)(
    _In_reads_bytes_(HashSize) PUCHAR Hash,
    _In_ ULONG HashSize,
    _In_ USHORT AlgorithmId,
    _In_ ULONG ReloadCatalogs,
    _In_ ULONG SecureProcess,
    _In_ ULONG AcceptRoots,
    _Inout_opt_ PXDOWS_MINCRYPT_POLICY_INFO PolicyInfo,
    _Out_opt_ PUNICODE_STRING CatalogName,
    _Out_opt_ PLARGE_INTEGER SigningTime,
    _Inout_opt_ PXDOWS_MINCRYPT_POLICY_INFO TimeStampPolicyInfo
    );

//
// Declared in ntifs.h only; forward-declared here like PsGetThreadProcess
// in InjectionProtect.c. Returns the cached \Device\... image path of a
// process without file-system access.
//
NTKERNELAPI
NTSTATUS
SeLocateProcessImageName(
    _In_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING* pImageFileName
    );

//
// Also declared in ntifs.h only. Returns the truncated (15-char) image
// file name cached in the EPROCESS; used solely for diagnostic logging.
//
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

typedef struct _XDOWS_CI_VERDICT_SLOT {
    ULONG ProcessId;
    ULONGLONG CreateTime;
    ULONGLONG LastUsed;
    BOOLEAN Trusted;
    BOOLEAN InUse;
} XDOWS_CI_VERDICT_SLOT, *PXDOWS_CI_VERDICT_SLOT;

typedef struct _XDOWS_CI_WORK_ITEM {
    PIO_WORKITEM WorkItem;
    PEPROCESS Process;
    PFILE_OBJECT FileObject;
    ULONG ProcessId;
    ULONGLONG CreateTime;
} XDOWS_CI_WORK_ITEM, *PXDOWS_CI_WORK_ITEM;

typedef struct _XDOWS_CI_CONTEXT {
    EX_PUSH_LOCK Lock;
    EX_RUNDOWN_REF WorkRundown;
    XDOWS_CI_VERDICT_SLOT Verdicts[XDOWS_CI_CACHE_SLOTS];
    XDOWS_ZW_QUERY_SYSTEM_INFORMATION QuerySystemInformation;
    XDOWS_PS_LOOKUP_PROCESS_BY_ID LookupProcessById;
    XDOWS_PS_REFERENCE_PROCESS_FILE_POINTER ReferenceProcessFilePointer;
    XDOWS_CI_VALIDATE_FILE_OBJECT ValidateFileObject;
    XDOWS_CI_FREE_POLICY_INFO FreePolicyInfo;
    XDOWS_CI_VERIFY_HASH_IN_CATALOG VerifyHashInCatalog;
    ULONGLONG CacheSequence;
    volatile LONG AcceptingWork;
    volatile LONG QueuedWork;
    ULONG SweepTotal;
    ULONG SweepEmbeddedTrusted;
    ULONG SweepCatalogTrusted;
    ULONG SweepUntrusted;
    ULONG SweepErrors;
    BOOLEAN NotifyRegistered;
    BOOLEAN Initialized;
} XDOWS_CI_CONTEXT, *PXDOWS_CI_CONTEXT;

typedef struct _XDOWS_RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} XDOWS_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _XDOWS_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    XDOWS_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} XDOWS_RTL_PROCESS_MODULES;

//
// Leading portion of SYSTEM_PROCESS_INFORMATION (x64). The layout of these
// fields is stable from Vista through Windows 11; only the fields needed to
// walk the list and read UniqueProcessId are mirrored here. UniqueProcessId
// sits at offset 0x50 on both x64 and ARM64.
//
typedef struct _XDOWS_CI_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
} XDOWS_CI_SYSTEM_PROCESS_INFORMATION, *PXDOWS_CI_SYSTEM_PROCESS_INFORMATION;

static XDOWS_CI_CONTEXT g_CodeIntegrity;

static
PVOID
XdowsCiGetSystemRoutine(
    _In_z_ PCWSTR Name
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, Name);
    return MmGetSystemRoutineAddress(&routineName);
}

static
NTSTATUS
XdowsCiFindModule(
    _In_z_ PCSTR ModuleName,
    _Out_ PVOID* ImageBase,
    _Out_ PULONG ImageSize
    )
{
    XDOWS_RTL_PROCESS_MODULES* modules = NULL;
    ULONG length = 0;
    ULONG allocatedLength = 0;
    ULONG maximumModules;
    ULONG attempt;
    NTSTATUS status;
    ULONG i;

    *ImageBase = NULL;
    *ImageSize = 0;

    status = g_CodeIntegrity.QuerySystemInformation(
        XDOWS_SYSTEM_MODULE_INFORMATION_CLASS, NULL, 0, &length);
    if (length == 0) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    for (attempt = 0; attempt < 3; attempt++) {
        length += 16 * sizeof(XDOWS_RTL_PROCESS_MODULE_INFORMATION);
        allocatedLength = length;
        modules = (XDOWS_RTL_PROCESS_MODULES*)ExAllocatePool2(
            POOL_FLAG_PAGED, allocatedLength, XDOWS_CI_POOL_TAG);
        if (modules == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = g_CodeIntegrity.QuerySystemInformation(
            XDOWS_SYSTEM_MODULE_INFORMATION_CLASS,
            modules,
            allocatedLength,
            &length);
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            break;
        }

        ExFreePoolWithTag(modules, XDOWS_CI_POOL_TAG);
        modules = NULL;
    }

    if (!NT_SUCCESS(status) || modules == NULL) {
        if (modules != NULL) {
            ExFreePoolWithTag(modules, XDOWS_CI_POOL_TAG);
        }
        return status;
    }

    maximumModules = allocatedLength >= (ULONG)FIELD_OFFSET(XDOWS_RTL_PROCESS_MODULES, Modules)
        ? (allocatedLength - (ULONG)FIELD_OFFSET(XDOWS_RTL_PROCESS_MODULES, Modules)) /
            sizeof(XDOWS_RTL_PROCESS_MODULE_INFORMATION)
        : 0;
    if (modules->NumberOfModules > maximumModules) {
        ExFreePoolWithTag(modules, XDOWS_CI_POOL_TAG);
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    status = STATUS_NOT_FOUND;
    for (i = 0; i < modules->NumberOfModules; i++) {
        XDOWS_RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[i];
        PCSTR fileName;
        SIZE_T availableLength;
        SIZE_T moduleNameLength = strlen(ModuleName);

        if (module->OffsetToFileName >= RTL_NUMBER_OF(module->FullPathName)) {
            continue;
        }

        fileName = (PCSTR)&module->FullPathName[module->OffsetToFileName];
        availableLength = RTL_NUMBER_OF(module->FullPathName) -
            module->OffsetToFileName;
        if (moduleNameLength + 1 > availableLength ||
            _strnicmp(fileName, ModuleName, moduleNameLength) != 0 ||
            fileName[moduleNameLength] != '\0') {
            continue;
        }

        *ImageBase = module->ImageBase;
        *ImageSize = module->ImageSize;
        status = (*ImageBase != NULL && *ImageSize != 0)
            ? STATUS_SUCCESS
            : STATUS_NOT_FOUND;
        break;
    }

    ExFreePoolWithTag(modules, XDOWS_CI_POOL_TAG);
    return status;
}

static
PVOID
XdowsCiResolveExport(
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize,
    _In_z_ PCSTR FunctionName
    )
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_DATA_DIRECTORY exportData;
    PIMAGE_EXPORT_DIRECTORY exports;
    PULONG names;
    PUSHORT ordinals;
    PULONG functions;
    SIZE_T functionNameLength;
    ULONG i;

#define XDOWS_CI_RVA_FITS(_rva, _bytes) \
    ((_rva) < ImageSize && (_bytes) <= ImageSize - (_rva))

    if (ImageSize < sizeof(IMAGE_DOS_HEADER)) {
        return NULL;
    }
    dos = (PIMAGE_DOS_HEADER)ImageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew <= 0 ||
        !XDOWS_CI_RVA_FITS((ULONG)dos->e_lfanew, sizeof(IMAGE_NT_HEADERS))) {
        return NULL;
    }

    nt = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return NULL;
    }

    exportData = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!XDOWS_CI_RVA_FITS(exportData->VirtualAddress, sizeof(*exports))) {
        return NULL;
    }
    exports = (PIMAGE_EXPORT_DIRECTORY)(
        (PUCHAR)ImageBase + exportData->VirtualAddress);

    if (exports->NumberOfNames > ImageSize / sizeof(ULONG) ||
        exports->NumberOfNames > ImageSize / sizeof(USHORT) ||
        exports->NumberOfFunctions > ImageSize / sizeof(ULONG) ||
        !XDOWS_CI_RVA_FITS(exports->AddressOfNames,
            exports->NumberOfNames * sizeof(ULONG)) ||
        !XDOWS_CI_RVA_FITS(exports->AddressOfNameOrdinals,
            exports->NumberOfNames * sizeof(USHORT)) ||
        !XDOWS_CI_RVA_FITS(exports->AddressOfFunctions,
            exports->NumberOfFunctions * sizeof(ULONG))) {
        return NULL;
    }

    names = (PULONG)((PUCHAR)ImageBase + exports->AddressOfNames);
    ordinals = (PUSHORT)((PUCHAR)ImageBase + exports->AddressOfNameOrdinals);
    functions = (PULONG)((PUCHAR)ImageBase + exports->AddressOfFunctions);
    functionNameLength = strlen(FunctionName);

    for (i = 0; i < exports->NumberOfNames; i++) {
        USHORT ordinal;
        ULONG functionRva;
        PCSTR candidate;

        if (!XDOWS_CI_RVA_FITS(names[i], functionNameLength + 1)) {
            continue;
        }
        candidate = (PCSTR)((PUCHAR)ImageBase + names[i]);
        if (memcmp(candidate, FunctionName, functionNameLength) != 0 ||
            candidate[functionNameLength] != '\0') {
            continue;
        }

        ordinal = ordinals[i];
        if (ordinal >= exports->NumberOfFunctions) {
            return NULL;
        }
        functionRva = functions[ordinal];
        if (!XDOWS_CI_RVA_FITS(functionRva, 1) ||
            (functionRva >= exportData->VirtualAddress &&
             functionRva - exportData->VirtualAddress < exportData->Size)) {
            return NULL;
        }
        return (PUCHAR)ImageBase + functionRva;
    }

    return NULL;
#undef XDOWS_CI_RVA_FITS
}

static
BOOLEAN
XdowsCiLookupVerdict(
    _In_ ULONG ProcessId,
    _In_ ULONGLONG CreateTime,
    _Out_ PBOOLEAN Trusted
    )
{
    BOOLEAN hit = FALSE;
    ULONG i;

    *Trusted = FALSE;
    ExAcquirePushLockExclusive(&g_CodeIntegrity.Lock);
    for (i = 0; i < XDOWS_CI_CACHE_SLOTS; i++) {
        PXDOWS_CI_VERDICT_SLOT slot = &g_CodeIntegrity.Verdicts[i];

        if (!slot->InUse ||
            slot->ProcessId != ProcessId ||
            slot->CreateTime != CreateTime) {
            continue;
        }

        slot->LastUsed = ++g_CodeIntegrity.CacheSequence;
        *Trusted = slot->Trusted;
        hit = TRUE;
        break;
    }
    ExReleasePushLockExclusive(&g_CodeIntegrity.Lock);
    return hit;
}

static
VOID
XdowsCiRecordVerdict(
    _In_ ULONG ProcessId,
    _In_ ULONGLONG CreateTime,
    _In_ BOOLEAN Trusted
    )
{
    PXDOWS_CI_VERDICT_SLOT chosen = NULL;
    PXDOWS_CI_VERDICT_SLOT oldest = NULL;
    ULONGLONG oldestSequence = MAXULONGLONG;
    ULONG i;

    ExAcquirePushLockExclusive(&g_CodeIntegrity.Lock);
    for (i = 0; i < XDOWS_CI_CACHE_SLOTS; i++) {
        PXDOWS_CI_VERDICT_SLOT slot = &g_CodeIntegrity.Verdicts[i];

        if (slot->InUse &&
            slot->ProcessId == ProcessId &&
            slot->CreateTime == CreateTime) {
            chosen = slot;
            break;
        }
        if (!slot->InUse && chosen == NULL) {
            chosen = slot;
        }
        if (slot->InUse && slot->LastUsed < oldestSequence) {
            oldestSequence = slot->LastUsed;
            oldest = slot;
        }
    }

    if (chosen == NULL) {
        chosen = oldest;
    }
    if (chosen != NULL) {
        chosen->ProcessId = ProcessId;
        chosen->CreateTime = CreateTime;
        chosen->LastUsed = ++g_CodeIntegrity.CacheSequence;
        chosen->Trusted = Trusted;
        chosen->InUse = TRUE;
    }
    ExReleasePushLockExclusive(&g_CodeIntegrity.Lock);
}

static
VOID
XdowsCiRemoveVerdict(
    _In_ ULONG ProcessId,
    _In_ ULONGLONG CreateTime
    )
{
    ULONG i;

    ExAcquirePushLockExclusive(&g_CodeIntegrity.Lock);
    for (i = 0; i < XDOWS_CI_CACHE_SLOTS; i++) {
        PXDOWS_CI_VERDICT_SLOT slot = &g_CodeIntegrity.Verdicts[i];

        if (slot->InUse &&
            slot->ProcessId == ProcessId &&
            slot->CreateTime == CreateTime) {
            RtlZeroMemory(slot, sizeof(*slot));
            break;
        }
    }
    ExReleasePushLockExclusive(&g_CodeIntegrity.Lock);
}

static
NTSTATUS
XdowsCiValidateFileObject(
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN Trusted
    )
{
    XDOWS_MINCRYPT_POLICY_INFO signerPolicy;
    XDOWS_MINCRYPT_POLICY_INFO timestampPolicy;
    LARGE_INTEGER signingTime;
    UCHAR thumbprint[XDOWS_CI_THUMBPRINT_BYTES];
    ULONG thumbprintSize = sizeof(thumbprint);
    ULONG thumbprintAlgorithm = 0;
    NTSTATUS status;

    *Trusted = FALSE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || KeAreAllApcsDisabled()) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&signerPolicy, sizeof(signerPolicy));
    RtlZeroMemory(&timestampPolicy, sizeof(timestampPolicy));
    RtlZeroMemory(thumbprint, sizeof(thumbprint));
    signingTime.QuadPart = 0;

    status = g_CodeIntegrity.ValidateFileObject(
        FileObject,
        XDOWS_CI_POLICY_ACCEPT_ANY_ROOT_CERTIFICATE,
        0,
        &signerPolicy,
        &timestampPolicy,
        &signingTime,
        thumbprint,
        &thumbprintSize,
        &thumbprintAlgorithm);

    *Trusted = NT_SUCCESS(status) && NT_SUCCESS(signerPolicy.VerificationStatus);

    g_CodeIntegrity.FreePolicyInfo(&timestampPolicy);
    g_CodeIntegrity.FreePolicyInfo(&signerPolicy);

    // A successful CI call with a failing VerificationStatus is a completed,
    // negative verification. A failing call is an ABI/runtime failure and
    // must remain unknown so an incompatible ci.dll cannot become policy.
    return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
}

//
// Hash one [Start, End) byte range of an open synchronous file handle into
// the CNG hash object.
//
static
NTSTATUS
XdowsCiHashFileRange(
    _In_ BCRYPT_HASH_HANDLE Hash,
    _In_ HANDLE File,
    _In_ ULONGLONG Start,
    _In_ ULONGLONG End
    )
{
    PUCHAR chunk;
    ULONGLONG position = Start;
    NTSTATUS status = STATUS_SUCCESS;

    if (End <= Start) {
        return STATUS_SUCCESS;
    }

    chunk = ExAllocatePool2(
        POOL_FLAG_PAGED, XDOWS_CI_READ_CHUNK_BYTES, XDOWS_CI_POOL_TAG);
    if (chunk == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (position < End) {
        IO_STATUS_BLOCK ioStatus;
        LARGE_INTEGER byteOffset;
        ULONG toRead;

        if (End - position > XDOWS_CI_READ_CHUNK_BYTES) {
            toRead = XDOWS_CI_READ_CHUNK_BYTES;
        } else {
            toRead = (ULONG)(End - position);
        }

        byteOffset.QuadPart = (LONGLONG)position;
        status = ZwReadFile(
            File, NULL, NULL, NULL, &ioStatus,
            chunk, toRead, &byteOffset, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        if (ioStatus.Information == 0) {
            status = STATUS_END_OF_FILE;
            break;
        }

        status = BCryptHashData(Hash, chunk, (ULONG)ioStatus.Information, 0);
        if (!NT_SUCCESS(status)) {
            break;
        }
        position += ioStatus.Information;
    }

    ExFreePoolWithTag(chunk, XDOWS_CI_POOL_TAG);
    return status;
}

//
// Compute the Authenticode SHA-256 digest of the file behind an open handle.
// Authenticode excludes the PE CheckSum field and the Certificate Table
// (whose file offset and size live in DataDirectory[4]) from the hashed
// byte stream; everything else is hashed in order.
//
static
NTSTATUS
XdowsCiComputeAuthenticodeDigest(
    _In_ HANDLE File,
    _In_ ULONGLONG FileSize,
    _Out_writes_bytes_(XDOWS_CI_DIGEST_BYTES) PUCHAR Digest
    )
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR objectBuffer = NULL;
    PUCHAR header = NULL;
    ULONG objectLength = 0;
    ULONG resultLength = 0;
    ULONGLONG checksumOffset;
    ULONGLONG securityDirectoryOffset;
    ULONGLONG certificateOffset;
    ULONGLONG certificateSize;
    ULONG certificateRva;
    ULONG optionalOffset;
    ULONG dataDirectoryOffset;
    USHORT magic;
    LONGLONG e_lfanew;
    NTSTATUS status;

    header = ExAllocatePool2(
        POOL_FLAG_PAGED, XDOWS_CI_HEADER_BUFFER_BYTES, XDOWS_CI_POOL_TAG);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Read and validate enough of the PE header to locate the CheckSum field
    // and the Security directory entry.
    //
    {
        IO_STATUS_BLOCK ioStatus;
        LARGE_INTEGER byteOffset = { 0 };
        ULONG headerBytes =
            FileSize < XDOWS_CI_HEADER_BUFFER_BYTES
                ? (ULONG)FileSize
                : XDOWS_CI_HEADER_BUFFER_BYTES;

        status = ZwReadFile(
            File, NULL, NULL, NULL, &ioStatus,
            header, headerBytes, &byteOffset, NULL);
        if (!NT_SUCCESS(status) || ioStatus.Information < 0x40) {
            status = STATUS_INVALID_IMAGE_NOT_MZ;
            goto Exit;
        }

        if (header[0] != 'M' || header[1] != 'Z') {
            status = STATUS_INVALID_IMAGE_NOT_MZ;
            goto Exit;
        }

        e_lfanew = (LONGLONG)*(UNALIGNED ULONG*)(header + 0x3C);
        if (e_lfanew < 0 ||
            e_lfanew + 24 + 96 > (LONGLONG)ioStatus.Information ||
            *(UNALIGNED ULONG*)(header + e_lfanew) != 0x00004550) { // "PE\0\0"
            status = STATUS_INVALID_IMAGE_PROTECT;
            goto Exit;
        }

        optionalOffset = (ULONG)e_lfanew + 24;
        magic = *(UNALIGNED USHORT*)(header + optionalOffset);
        if (magic == 0x20B) {          // PE32+
            dataDirectoryOffset = optionalOffset + 112;
        } else if (magic == 0x10B) {   // PE32
            dataDirectoryOffset = optionalOffset + 96;
        } else {
            status = STATUS_INVALID_IMAGE_PROTECT;
            goto Exit;
        }

        if (dataDirectoryOffset + 5 * 8 > (ULONG)ioStatus.Information) {
            status = STATUS_INVALID_IMAGE_PROTECT;
            goto Exit;
        }

        checksumOffset = optionalOffset + 64;
        securityDirectoryOffset = dataDirectoryOffset + 4 * 8;
        certificateRva = *(UNALIGNED ULONG*)(
            header + securityDirectoryOffset);
        certificateSize = *(UNALIGNED ULONG*)(
            header + securityDirectoryOffset + 4);
    }

    // The Certificate Table VirtualAddress is a file offset by definition;
    // reject entries that do not fit the file to stay defensive.
    if (certificateSize == 0 ||
        certificateRva >= FileSize ||
        certificateSize > FileSize ||
        certificateRva + certificateSize > FileSize) {
        certificateOffset = FileSize;
        certificateSize = 0;
    } else {
        certificateOffset = certificateRva;
    }

    //
    // Create the SHA-256 hash object. The object buffer is queried and
    // allocated explicitly so no CNG internal allocation contract is assumed.
    //
    status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&objectLength,
        sizeof(objectLength),
        &resultLength,
        0);
    if (!NT_SUCCESS(status) || objectLength == 0) {
        goto Exit;
    }

    objectBuffer = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, objectLength, XDOWS_CI_POOL_TAG);
    if (objectBuffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    status = BCryptCreateHash(
        algorithm, &hash, objectBuffer, objectLength, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    //
    // Hash in Authenticode order: skip CheckSum (4 bytes), skip the Security
    // data-directory entry itself (8 bytes), then skip the Certificate Table.
    // Including that directory entry produces a different digest from the one
    // stored in Windows catalogs, which made every catalog-signed system image
    // look untrusted even though CiVerifyHashInCatalog was available.
    //
    status = XdowsCiHashFileRange(hash, File, 0, checksumOffset);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = XdowsCiHashFileRange(
        hash, File, checksumOffset + 4, securityDirectoryOffset);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = XdowsCiHashFileRange(
        hash,
        File,
        securityDirectoryOffset + 8,
        certificateSize != 0 ? certificateOffset : FileSize);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (certificateSize != 0) {
        status = XdowsCiHashFileRange(
            hash, File, certificateOffset + certificateSize, FileSize);
    }
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = BCryptFinishHash(hash, Digest, XDOWS_CI_DIGEST_BYTES, 0);

Exit:
    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    if (objectBuffer != NULL) {
        ExFreePoolWithTag(objectBuffer, XDOWS_CI_POOL_TAG);
    }
    if (algorithm != NULL) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (header != NULL) {
        ExFreePoolWithTag(header, XDOWS_CI_POOL_TAG);
    }
    return status;
}

//
// Catalog-signature fallback: opens the process image by its cached
// \Device\... path, computes the Authenticode SHA-256 digest, and asks
// ci.dll whether the digest is covered by a verified OS catalog. Covers
// svchost.exe / services.exe / csrss.exe style binaries that carry no
// embedded signer certificate.
//
static
NTSTATUS
XdowsCiVerifyProcessCatalog(
    _In_ PEPROCESS Process,
    _Out_ PBOOLEAN Trusted
    )
{
    PUNICODE_STRING imagePath = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    FILE_STANDARD_INFORMATION standardInfo;
    HANDLE file = NULL;
    UCHAR digest[XDOWS_CI_DIGEST_BYTES];
    NTSTATUS status;

    *Trusted = FALSE;
    if (g_CodeIntegrity.VerifyHashInCatalog == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = SeLocateProcessImageName(Process, &imagePath);
    if (!NT_SUCCESS(status) || imagePath == NULL ||
        imagePath->Buffer == NULL || imagePath->Length == 0) {
        if (imagePath != NULL) {
            ExFreePool(imagePath);
        }
        return status != STATUS_SUCCESS ? status : STATUS_NOT_FOUND;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        imagePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwCreateFile(
        &file,
        FILE_READ_DATA | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED,
        NULL,
        0);
    ExFreePool(imagePath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwQueryInformationFile(
        file,
        &ioStatus,
        &standardInfo,
        sizeof(standardInfo),
        FileStandardInformation);
    if (!NT_SUCCESS(status) || standardInfo.EndOfFile.QuadPart <= 0) {
        ZwClose(file);
        return NT_SUCCESS(status) ? STATUS_INVALID_FILE_FOR_SECTION : status;
    }

    status = XdowsCiComputeAuthenticodeDigest(
        file, (ULONGLONG)standardInfo.EndOfFile.QuadPart, digest);
    ZwClose(file);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Default catalog policy (ReloadCatalogs=0, SecureProcess=0,
    // AcceptRoots=0): the digest must be present in an already-loaded
    // catalog signed by a standard root. NT_SUCCESS means catalog-covered.
    //
    status = g_CodeIntegrity.VerifyHashInCatalog(
        digest,
        XDOWS_CI_DIGEST_BYTES,
        (USHORT)XDOWS_CI_CALG_SHA256,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL);
    if (NT_SUCCESS(status)) {
        *Trusted = TRUE;
        return STATUS_SUCCESS;
    }
    return STATUS_SUCCESS; // completed negative verification
}

//
// Shared catalog fallback. When the embedded-signature verdict is missing
// or negative, retry through the OS catalog (CiVerifyHashInCatalog). An
// ABI/runtime failure of the fallback keeps the embedded result so an
// incompatible ci.dll cannot widen trust.
//
// Process may be NULL; the process is then looked up by ProcessId and
// released here (runtime create-notify work items only keep the id).
//
static
VOID
XdowsCiApplyCatalogFallback(
    _In_opt_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_ PNTSTATUS Status,
    _Inout_ PBOOLEAN Trusted,
    _Out_opt_ PBOOLEAN CatalogApplied
    )
{
    PEPROCESS process = Process;
    BOOLEAN catalogTrusted = FALSE;
    NTSTATUS catalogStatus;

    if (CatalogApplied != NULL) {
        *CatalogApplied = FALSE;
    }

    if (NT_SUCCESS(*Status) && *Trusted) {
        return; // embedded verdict already positive
    }

    if (process == NULL) {
        if (!NT_SUCCESS(g_CodeIntegrity.LookupProcessById(
                ProcessId, &process))) {
            return;
        }
    }

    catalogStatus = XdowsCiVerifyProcessCatalog(process, &catalogTrusted);
    if (Process == NULL) {
        ObDereferenceObject(process);
    }

    if (NT_SUCCESS(catalogStatus)) {
        *Status = STATUS_SUCCESS;
        *Trusted = catalogTrusted;
        if (CatalogApplied != NULL) {
            *CatalogApplied = TRUE;
        }
    }
}

static
VOID
XdowsCiValidateAndCache(
    _In_ PEPROCESS Process
    )
{
    PFILE_OBJECT fileObject = NULL;
    BOOLEAN trusted = FALSE;
    BOOLEAN catalogApplied = FALSE;
    NTSTATUS status;

    status = g_CodeIntegrity.ReferenceProcessFilePointer(Process, &fileObject);
    if (!NT_SUCCESS(status) || fileObject == NULL) {
        g_CodeIntegrity.SweepErrors++;
        return;
    }

    status = XdowsCiValidateFileObject(fileObject, &trusted);
    ObDereferenceObject(fileObject);

    XdowsCiApplyCatalogFallback(
        Process,
        PsGetProcessId(Process),
        &status,
        &trusted,
        &catalogApplied);

    g_CodeIntegrity.SweepTotal++;
    if (!NT_SUCCESS(status)) {
        g_CodeIntegrity.SweepErrors++;
    } else if (trusted) {
        if (catalogApplied) {
            g_CodeIntegrity.SweepCatalogTrusted++;
        } else {
            g_CodeIntegrity.SweepEmbeddedTrusted++;
        }
    } else {
        WCHAR message[96];
        PCSTR imageName = PsGetProcessImageFileName(Process);

        g_CodeIntegrity.SweepUntrusted++;
        if (imageName != NULL) {
            (VOID)RtlStringCchPrintfW(
                message,
                RTL_NUMBER_OF(message),
                L"Initial sweep untrusted image (catalog miss): %S",
                imageName);
            XdowsLogWrite(
                XdowsSecurityLogWarning, 0, 0, L"CodeIntegrity", message);
        }
    }

    if (NT_SUCCESS(status)) {
        XdowsCiRecordVerdict(
            HandleToULong(PsGetProcessId(Process)),
            PsGetProcessCreateTimeQuadPart(Process),
            trusted);
    }
}

//
// Initial sweep: validate every process that already existed when the driver
// loaded. The create-notify callback only covers future creations, and this
// driver starts on demand, so without this sweep the cache would stay empty
// for the majority of system processes and the injection fast-allow path
// would never engage for them.
//
static
VOID
XdowsCiValidateExistingProcesses(
    VOID
    )
{
    PXDOWS_CI_SYSTEM_PROCESS_INFORMATION info = NULL;
    ULONG length = 0;
    ULONG allocatedLength = 0;
    PUCHAR bufferEnd;
    PUCHAR entry;
    NTSTATUS status;
    ULONG attempt;

    status = g_CodeIntegrity.QuerySystemInformation(
        XDOWS_SYSTEM_PROCESS_INFORMATION_CLASS, NULL, 0, &length);
    if (length == 0) {
        return;
    }

    for (attempt = 0; attempt < 3; attempt++) {
        allocatedLength = length + 0x400u;
        info = (PXDOWS_CI_SYSTEM_PROCESS_INFORMATION)ExAllocatePool2(
            POOL_FLAG_PAGED, allocatedLength, XDOWS_CI_POOL_TAG);
        if (info == NULL) {
            return;
        }

        status = g_CodeIntegrity.QuerySystemInformation(
            XDOWS_SYSTEM_PROCESS_INFORMATION_CLASS,
            info,
            allocatedLength,
            &length);
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            break;
        }

        ExFreePoolWithTag(info, XDOWS_CI_POOL_TAG);
        info = NULL;
    }

    if (!NT_SUCCESS(status) || info == NULL) {
        if (info != NULL) {
            ExFreePoolWithTag(info, XDOWS_CI_POOL_TAG);
        }
        return;
    }

    bufferEnd = (PUCHAR)info + allocatedLength;
    entry = (PUCHAR)info;

    while (entry + sizeof(XDOWS_CI_SYSTEM_PROCESS_INFORMATION) <= bufferEnd) {
        PXDOWS_CI_SYSTEM_PROCESS_INFORMATION process =
            (PXDOWS_CI_SYSTEM_PROCESS_INFORMATION)entry;
        ULONG nextOffset = process->NextEntryOffset;

        if (process->UniqueProcessId != NULL) {
            PEPROCESS processObject = NULL;

            if (NT_SUCCESS(g_CodeIntegrity.LookupProcessById(
                    process->UniqueProcessId,
                    &processObject))) {
                XdowsCiValidateAndCache(processObject);
                ObDereferenceObject(processObject);
            }
        }

        if (nextOffset == 0 ||
            nextOffset < sizeof(XDOWS_CI_SYSTEM_PROCESS_INFORMATION) ||
            entry + nextOffset >= bufferEnd) {
            break;
        }
        entry += nextOffset;
    }

    ExFreePoolWithTag(info, XDOWS_CI_POOL_TAG);

    //
    // Diagnostics: the split between embedded and catalog verdicts is the
    // primary signal for verifying that ci.dll catalog fallback works on
    // the target machine.
    //
    {
        WCHAR message[128];
        (VOID)RtlStringCchPrintfW(
            message,
            RTL_NUMBER_OF(message),
            L"Initial sweep: total=%u embedded=%u catalog=%u untrusted=%u errors=%u",
            g_CodeIntegrity.SweepTotal,
            g_CodeIntegrity.SweepEmbeddedTrusted,
            g_CodeIntegrity.SweepCatalogTrusted,
            g_CodeIntegrity.SweepUntrusted,
            g_CodeIntegrity.SweepErrors);
        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"CodeIntegrity", message);
    }
}

static
VOID
XdowsCiWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PXDOWS_CI_WORK_ITEM item = (PXDOWS_CI_WORK_ITEM)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (item->FileObject != NULL) {
        BOOLEAN trusted;
        NTSTATUS status;

        status = XdowsCiValidateFileObject(item->FileObject, &trusted);

        //
        // Same catalog fallback as the initial sweep: processes created at
        // runtime must also reach a trusted verdict when they are only
        // catalog-signed (taskhostw.exe, conhost.exe, ...).
        //
        XdowsCiApplyCatalogFallback(
            NULL,
            (HANDLE)UlongToHandle(item->ProcessId),
            &status,
            &trusted,
            NULL);

        if (NT_SUCCESS(status)) {
            XdowsCiRecordVerdict(
                item->ProcessId,
                item->CreateTime,
                trusted);
        }
        ObDereferenceObject(item->FileObject);
    } else if (item->Process != NULL) {
        XdowsCiValidateAndCache(item->Process);
        ObDereferenceObject(item->Process);
    } else {
        XdowsCiValidateExistingProcesses();
    }

    IoFreeWorkItem(item->WorkItem);
    ExFreePoolWithTag(item, XDOWS_CI_POOL_TAG);
    (VOID)InterlockedDecrement(&g_CodeIntegrity.QueuedWork);
    ExReleaseRundownProtection(&g_CodeIntegrity.WorkRundown);
}

static
VOID
XdowsCiQueueValidation(
    _In_opt_ PEPROCESS Process,
    _In_opt_ PFILE_OBJECT FileObject
    )
{
    PXDOWS_CI_WORK_ITEM item;
    PDEVICE_OBJECT deviceObject;
    LONG queued;

    if (InterlockedCompareExchange(&g_CodeIntegrity.AcceptingWork, 0, 0) == 0 ||
        !ExAcquireRundownProtection(&g_CodeIntegrity.WorkRundown)) {
        return;
    }

    queued = InterlockedIncrement(&g_CodeIntegrity.QueuedWork);
    if (queued > XDOWS_CI_MAX_QUEUED_WORK) {
        (VOID)InterlockedDecrement(&g_CodeIntegrity.QueuedWork);
        ExReleaseRundownProtection(&g_CodeIntegrity.WorkRundown);
        return;
    }

    item = (PXDOWS_CI_WORK_ITEM)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*item), XDOWS_CI_POOL_TAG);
    if (item == NULL) {
        (VOID)InterlockedDecrement(&g_CodeIntegrity.QueuedWork);
        ExReleaseRundownProtection(&g_CodeIntegrity.WorkRundown);
        return;
    }
    RtlZeroMemory(item, sizeof(*item));

    deviceObject = WdfDeviceWdmGetDeviceObject(g_XdowsDriverContext.Device);
    item->WorkItem = IoAllocateWorkItem(deviceObject);
    if (item->WorkItem == NULL) {
        ExFreePoolWithTag(item, XDOWS_CI_POOL_TAG);
        (VOID)InterlockedDecrement(&g_CodeIntegrity.QueuedWork);
        ExReleaseRundownProtection(&g_CodeIntegrity.WorkRundown);
        return;
    }

    if (FileObject != NULL && Process != NULL) {
        ObReferenceObject(FileObject);
        item->FileObject = FileObject;
        item->ProcessId = HandleToULong(PsGetProcessId(Process));
        item->CreateTime = PsGetProcessCreateTimeQuadPart(Process);
    } else if (Process != NULL) {
        ObReferenceObject(Process);
        item->Process = Process;
    }
    IoQueueWorkItem(
        item->WorkItem,
        XdowsCiWorkItemRoutine,
        DelayedWorkQueue,
        item);
}

static
VOID
XdowsCiProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    if (CreateInfo != NULL) {
        if (CreateInfo->FileObject != NULL) {
            XdowsCiQueueValidation(Process, CreateInfo->FileObject);
        }
    } else {
        XdowsCiRemoveVerdict(
            HandleToULong(ProcessId),
            PsGetProcessCreateTimeQuadPart(Process));
    }
}

NTSTATUS
XdowsCodeIntegrityInitialize(
    VOID
    )
{
    PVOID ciBase = NULL;
    ULONG ciSize = 0;
    NTSTATUS status;

    if (g_CodeIntegrity.Initialized) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_CodeIntegrity, sizeof(g_CodeIntegrity));
    ExInitializePushLock(&g_CodeIntegrity.Lock);
    ExInitializeRundownProtection(&g_CodeIntegrity.WorkRundown);
    g_CodeIntegrity.Initialized = TRUE;

    g_CodeIntegrity.QuerySystemInformation =
        (XDOWS_ZW_QUERY_SYSTEM_INFORMATION)XdowsCiGetSystemRoutine(
            L"ZwQuerySystemInformation");
    g_CodeIntegrity.LookupProcessById =
        (XDOWS_PS_LOOKUP_PROCESS_BY_ID)XdowsCiGetSystemRoutine(
            L"PsLookupProcessByProcessId");
    g_CodeIntegrity.ReferenceProcessFilePointer =
        (XDOWS_PS_REFERENCE_PROCESS_FILE_POINTER)XdowsCiGetSystemRoutine(
            L"PsReferenceProcessFilePointer");

    if (g_CodeIntegrity.QuerySystemInformation == NULL ||
        g_CodeIntegrity.LookupProcessById == NULL ||
        g_CodeIntegrity.ReferenceProcessFilePointer == NULL) {
        XdowsLogWrite(XdowsSecurityLogWarning, 0, 0, L"CodeIntegrity",
            L"Required kernel routines unavailable; CI signature cache disabled.");
        return STATUS_SUCCESS;
    }

    status = XdowsCiFindModule(XDOWS_CI_MODULE_NAME, &ciBase, &ciSize);
    if (!NT_SUCCESS(status)) {
        XdowsLogWriteStatus(XdowsSecurityLogWarning, 0, 0, L"CodeIntegrity",
            L"ci.dll module base not found; signature cache disabled", status);
        return STATUS_SUCCESS;
    }

    g_CodeIntegrity.ValidateFileObject =
        (XDOWS_CI_VALIDATE_FILE_OBJECT)XdowsCiResolveExport(
            ciBase, ciSize, "CiValidateFileObject");
    g_CodeIntegrity.FreePolicyInfo =
        (XDOWS_CI_FREE_POLICY_INFO)XdowsCiResolveExport(
            ciBase, ciSize, "CiFreePolicyInfo");
    if (g_CodeIntegrity.ValidateFileObject == NULL ||
        g_CodeIntegrity.FreePolicyInfo == NULL) {
        g_CodeIntegrity.ValidateFileObject = NULL;
        g_CodeIntegrity.FreePolicyInfo = NULL;
        g_CodeIntegrity.VerifyHashInCatalog = NULL;
        XdowsLogWrite(XdowsSecurityLogWarning, 0, 0, L"CodeIntegrity",
            L"ci.dll validation exports unavailable; signature cache disabled.");
        return STATUS_SUCCESS;
    }

    // Optional enhancement: catalog verification covers catalog-signed OS
    // binaries (svchost.exe, services.exe, csrss.exe, ...) whose PE carries
    // only a hash stub. Missing export only disables the fallback.
    g_CodeIntegrity.VerifyHashInCatalog =
        (XDOWS_CI_VERIFY_HASH_IN_CATALOG)XdowsCiResolveExport(
            ciBase, ciSize, "CiVerifyHashInCatalog");

    (VOID)InterlockedExchange(&g_CodeIntegrity.AcceptingWork, 1);
    status = PsSetCreateProcessNotifyRoutineEx(XdowsCiProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        (VOID)InterlockedExchange(&g_CodeIntegrity.AcceptingWork, 0);
        g_CodeIntegrity.ValidateFileObject = NULL;
        g_CodeIntegrity.FreePolicyInfo = NULL;
        g_CodeIntegrity.VerifyHashInCatalog = NULL;
        XdowsLogWriteStatus(XdowsSecurityLogWarning, 0, 0, L"CodeIntegrity",
            L"Process notification registration failed; signature cache disabled",
            status);
        return STATUS_SUCCESS;
    }

    g_CodeIntegrity.NotifyRegistered = TRUE;
    XdowsCiQueueValidation(NULL, NULL);
    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"CodeIntegrity",
        L"Asynchronous ci.dll Authenticode validation active.");
    return STATUS_SUCCESS;
}

VOID
XdowsCodeIntegrityShutdown(
    VOID
    )
{
    if (!g_CodeIntegrity.Initialized) {
        return;
    }

    (VOID)InterlockedExchange(&g_CodeIntegrity.AcceptingWork, 0);
    if (g_CodeIntegrity.NotifyRegistered) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(XdowsCiProcessNotify, TRUE);
        g_CodeIntegrity.NotifyRegistered = FALSE;
    }

    ExWaitForRundownProtectionRelease(&g_CodeIntegrity.WorkRundown);
    g_CodeIntegrity.ValidateFileObject = NULL;
    g_CodeIntegrity.FreePolicyInfo = NULL;
    g_CodeIntegrity.VerifyHashInCatalog = NULL;
    RtlZeroMemory(g_CodeIntegrity.Verdicts, sizeof(g_CodeIntegrity.Verdicts));
    g_CodeIntegrity.Initialized = FALSE;

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"CodeIntegrity",
        L"Code Integrity signature cache stopped.");
}

BOOLEAN
XdowsCodeIntegrityIsAvailable(
    VOID
    )
{
    return g_CodeIntegrity.Initialized &&
        g_CodeIntegrity.NotifyRegistered &&
        g_CodeIntegrity.ValidateFileObject != NULL &&
        g_CodeIntegrity.FreePolicyInfo != NULL;
}

BOOLEAN
XdowsCodeIntegrityQueryProcessTrust(
    _In_ PEPROCESS Process,
    _Out_ PBOOLEAN Trusted
    )
{
    *Trusted = FALSE;
    if (Process == NULL || !XdowsCodeIntegrityIsAvailable()) {
        return FALSE;
    }

    return XdowsCiLookupVerdict(
        HandleToULong(PsGetProcessId(Process)),
        PsGetProcessCreateTimeQuadPart(Process),
        Trusted);
}
