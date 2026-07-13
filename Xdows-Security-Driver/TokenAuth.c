/*++

Module Name:

    tokenauth.c

Abstract:

    One-time shutdown token issuance and constant-time validation.

    This module is intentionally self-contained: it depends only on the kernel
    cryptography primitives and the shared log facility. It registers no
    system callbacks and owns no global kernel state beyond its own context,
    so a failure here never affects other protection modules.

    Lifecycle:

        Empty --Initialize()--> Armed --CopyOneTimeToken()--> Issued
          ^                                                       |
          |__________________Invalidate()________________________|
          |
        Validate() succeeds while State is Armed or Issued.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "tokenauth.h"
#include <bcrypt.h>
#include <ntstrsafe.h>

//
// Token geometry. A 32-byte random seed renders as 64 hex characters, which
// matches XDOWS_SECURITY_TOKEN_CHARS exported to user mode.
//
#define XDOWS_TOKEN_SEED_BYTES     32u
#define XDOWS_TOKEN_DIGEST_BYTES    32u

//
// Explicit lifecycle state. Replaces the previous pair of boolean flags with
// a single value, making the one-time semantics impossible to misuse.
//
typedef enum _XDOWS_TOKEN_LIFECYCLE {
    XdowsTokenLifecycleEmpty = 0,
    XdowsTokenLifecycleArmed,
    XdowsTokenLifecycleIssued
} XDOWS_TOKEN_LIFECYCLE;

typedef struct _XDOWS_TOKEN_AUTH_CONTEXT {
    EX_PUSH_LOCK         Lock;
    volatile XDOWS_TOKEN_LIFECYCLE State;
    UCHAR                Digest[XDOWS_TOKEN_DIGEST_BYTES];
    WCHAR                Plaintext[XDOWS_SECURITY_TOKEN_CHARS + 1];
} XDOWS_TOKEN_AUTH_CONTEXT, *PXDOWS_TOKEN_AUTH_CONTEXT;

static XDOWS_TOKEN_AUTH_CONTEXT g_TokenAuthContext;

//
// Compute a SHA-256 digest over an arbitrary byte range using a transient
// provider. Token operations are rare (issue once at registration, validate
// only on authorized shutdown), so the per-call provider cost is negligible
// and avoids carrying global crypto handles that would need teardown ordering.
//
static
NTSTATUS
XdowsTokenAuthDigestBytes(
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ ULONG Length,
    _Out_writes_bytes_(XDOWS_TOKEN_DIGEST_BYTES) PUCHAR Digest
    )
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hasher = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptCreateHash(alg, &hasher, NULL, 0, NULL, 0, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hasher, (PUCHAR)Data, Length, 0);
    }
    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hasher, Digest, XDOWS_TOKEN_DIGEST_BYTES, 0);
    }

    if (hasher != NULL) {
        BCryptDestroyHash(hasher);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return status;
}

//
// Render a byte buffer as lowercase hex. Iterating nibble-first keeps the loop
// branch-free.
//
static
VOID
XdowsTokenAuthEncodeHex(
    _In_reads_(XDOWS_TOKEN_SEED_BYTES) PCUCHAR Seed,
    _Out_writes_(XDOWS_SECURITY_TOKEN_CHARS + 1) PWCHAR Text
    )
{
    static const WCHAR HexAlphabet[] = L"0123456789abcdef";
    ULONG i;

    for (i = 0; i < XDOWS_TOKEN_SEED_BYTES; i++) {
        Text[i * 2]     = HexAlphabet[(Seed[i] >> 4) & 0xF];
        Text[i * 2 + 1] = HexAlphabet[Seed[i] & 0xF];
    }
    Text[XDOWS_SECURITY_TOKEN_CHARS] = UNICODE_NULL;
}

static
VOID
XdowsTokenAuthSecureWipe(
    _Inout_updates_bytes_(Length) PUCHAR Buffer,
    _In_ SIZE_T Length
    )
{
    if (Buffer != NULL && Length > 0) {
        RtlSecureZeroMemory(Buffer, Length);
    }
}

NTSTATUS
XdowsTokenAuthInitialize(
    VOID
    )
{
    UCHAR seed[XDOWS_TOKEN_SEED_BYTES];
    NTSTATUS status;

    RtlZeroMemory(&g_TokenAuthContext, sizeof(g_TokenAuthContext));
    ExInitializePushLock(&g_TokenAuthContext.Lock);
    g_TokenAuthContext.State = XdowsTokenLifecycleEmpty;

    status = BCryptGenRandom(NULL, seed, sizeof(seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        XdowsTokenAuthSecureWipe(seed, sizeof(seed));
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"TokenAuth",
            L"Random seed generation failed", status);
        return status;
    }

    XdowsTokenAuthEncodeHex(seed, g_TokenAuthContext.Plaintext);

    status = XdowsTokenAuthDigestBytes(
        (PUCHAR)g_TokenAuthContext.Plaintext,
        XDOWS_SECURITY_TOKEN_CHARS * sizeof(WCHAR),
        g_TokenAuthContext.Digest);
    if (!NT_SUCCESS(status)) {
        XdowsTokenAuthSecureWipe(seed, sizeof(seed));
        XdowsTokenAuthSecureWipe((PUCHAR)g_TokenAuthContext.Plaintext,
            sizeof(g_TokenAuthContext.Plaintext));
        XdowsTokenAuthSecureWipe(g_TokenAuthContext.Digest,
            sizeof(g_TokenAuthContext.Digest));
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"TokenAuth",
            L"Token digest computation failed", status);
        return status;
    }

    XdowsTokenAuthSecureWipe(seed, sizeof(seed));
    g_TokenAuthContext.State = XdowsTokenLifecycleArmed;

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"TokenAuth", L"Shutdown token armed.");
    return STATUS_SUCCESS;
}

VOID
XdowsTokenAuthShutdown(
    VOID
    )
{
    XdowsTokenAuthInvalidate();
}

NTSTATUS
XdowsTokenAuthCopyOneTimeToken(
    _Out_writes_(TokenChars) PWCHAR Token,
    _In_ ULONG TokenChars
    )
{
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Token == NULL || TokenChars < XDOWS_SECURITY_TOKEN_CHARS + 1) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Token[0] = UNICODE_NULL;

    //
    // The one-time semantics are enforced atomically under the lock: the
    // state transition and plaintext wipe happen together, so a racing
    // Validate never observes a half-issued token.
    //
    ExAcquirePushLockExclusive(&g_TokenAuthContext.Lock);
    if (g_TokenAuthContext.State == XdowsTokenLifecycleArmed) {
        RtlCopyMemory(Token, g_TokenAuthContext.Plaintext,
            XDOWS_SECURITY_TOKEN_CHARS * sizeof(WCHAR));
        Token[XDOWS_SECURITY_TOKEN_CHARS] = UNICODE_NULL;

        XdowsTokenAuthSecureWipe((PUCHAR)g_TokenAuthContext.Plaintext,
            sizeof(g_TokenAuthContext.Plaintext));
        g_TokenAuthContext.State = XdowsTokenLifecycleIssued;
        status = STATUS_SUCCESS;
    }
    ExReleasePushLockExclusive(&g_TokenAuthContext.Lock);

    if (NT_SUCCESS(status)) {
        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"TokenAuth",
            L"Shutdown token issued to registered client.");
    }
    return status;
}

BOOLEAN
XdowsTokenAuthValidate(
    _In_reads_z_(XDOWS_SECURITY_TOKEN_CHARS + 1) PCWSTR Token
    )
{
    UCHAR candidate[XDOWS_TOKEN_DIGEST_BYTES];
    UCHAR diff = 0;
    NTSTATUS status;
    size_t length = 0;
    ULONG i;
    BOOLEAN verdict = FALSE;

    if (Token == NULL) {
        return FALSE;
    }

    //
    // Length check first: a wrong-length token can never match and must not
    // reach the digest path. BCRYPT_USE_SYSTEM_PREFERRED_RNG tokens are always
    // exactly XDOWS_SECURITY_TOKEN_CHARS wide.
    //
    if (!NT_SUCCESS(RtlStringCchLengthW(Token, XDOWS_SECURITY_TOKEN_CHARS + 1, &length)) ||
        length != XDOWS_SECURITY_TOKEN_CHARS) {
        return FALSE;
    }

    //
    // Candidate digest is computed outside the lock so the shared lock only
    // guards the 32-byte comparison, keeping contention negligible.
    //
    status = XdowsTokenAuthDigestBytes(
        (PUCHAR)Token,
        XDOWS_SECURITY_TOKEN_CHARS * sizeof(WCHAR),
        candidate);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    ExAcquirePushLockShared(&g_TokenAuthContext.Lock);
    if (g_TokenAuthContext.State != XdowsTokenLifecycleEmpty) {
        //
        // Constant-time compare: accumulate XOR across all bytes so the loop
        // body does not branch on secret data.
        //
        for (i = 0; i < XDOWS_TOKEN_DIGEST_BYTES; i++) {
            diff |= (UCHAR)(candidate[i] ^ g_TokenAuthContext.Digest[i]);
        }
        verdict = (diff == 0);
    }
    ExReleasePushLockShared(&g_TokenAuthContext.Lock);

    XdowsTokenAuthSecureWipe(candidate, sizeof(candidate));
    return verdict;
}

VOID
XdowsTokenAuthInvalidate(
    VOID
    )
{
    ExAcquirePushLockExclusive(&g_TokenAuthContext.Lock);
    XdowsTokenAuthSecureWipe((PUCHAR)g_TokenAuthContext.Plaintext,
        sizeof(g_TokenAuthContext.Plaintext));
    XdowsTokenAuthSecureWipe(g_TokenAuthContext.Digest,
        sizeof(g_TokenAuthContext.Digest));
    g_TokenAuthContext.State = XdowsTokenLifecycleEmpty;
    ExReleasePushLockExclusive(&g_TokenAuthContext.Lock);

    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"TokenAuth", L"Shutdown token cleared.");
}

NTSTATUS
XdowsTokenAuthRotate(
    VOID
    )
{
    XdowsTokenAuthInvalidate();
    return XdowsTokenAuthInitialize();
}
