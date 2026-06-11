#include "driver.h"
#include "tokenauth.h"
#include <bcrypt.h>
#include <ntstrsafe.h>

#define XDOWS_TOKEN_BYTES 32
#define XDOWS_TOKEN_HASH_BYTES 32

static WCHAR g_Token[XDOWS_SECURITY_TOKEN_CHARS + 1];
static UCHAR g_TokenHash[XDOWS_TOKEN_HASH_BYTES];
static BOOLEAN g_TokenReady;
static BOOLEAN g_TokenReturned;

static
NTSTATUS
XdowsTokenHashBytes(
    _In_reads_bytes_(Length) PUCHAR Data,
    _In_ ULONG Length,
    _Out_writes_bytes_(XDOWS_TOKEN_HASH_BYTES) PUCHAR Hash
    )
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hash, Data, Length, 0);
    }
    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hash, Hash, XDOWS_TOKEN_HASH_BYTES, 0);
    }

    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status;
}

static
VOID
XdowsTokenBytesToHex(
    _In_reads_(XDOWS_TOKEN_BYTES) PUCHAR Bytes,
    _Out_writes_(XDOWS_SECURITY_TOKEN_CHARS + 1) PWCHAR Token
    )
{
    static const WCHAR Hex[] = L"0123456789abcdef";

    for (ULONG i = 0; i < XDOWS_TOKEN_BYTES; i++) {
        Token[i * 2] = Hex[(Bytes[i] >> 4) & 0xF];
        Token[i * 2 + 1] = Hex[Bytes[i] & 0xF];
    }
    Token[XDOWS_SECURITY_TOKEN_CHARS] = UNICODE_NULL;
}

NTSTATUS
XdowsTokenAuthInitialize(
    VOID
    )
{
    UCHAR tokenBytes[XDOWS_TOKEN_BYTES];
    NTSTATUS status;

    RtlZeroMemory(g_Token, sizeof(g_Token));
    RtlZeroMemory(g_TokenHash, sizeof(g_TokenHash));
    g_TokenReady = FALSE;
    g_TokenReturned = FALSE;

    status = BCryptGenRandom(NULL, tokenBytes, sizeof(tokenBytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    XdowsTokenBytesToHex(tokenBytes, g_Token);
    status = XdowsTokenHashBytes((PUCHAR)g_Token, XDOWS_SECURITY_TOKEN_CHARS * sizeof(WCHAR), g_TokenHash);
    RtlSecureZeroMemory(tokenBytes, sizeof(tokenBytes));

    if (NT_SUCCESS(status)) {
        g_TokenReady = TRUE;
        XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"TokenAuth", L"Shutdown token initialized.");
    } else {
        XdowsLogWriteStatus(XdowsSecurityLogError, 0, 0, L"TokenAuth", L"Shutdown token initialization failed", status);
    }

    return status;
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
    if (Token == NULL || TokenChars < XDOWS_SECURITY_TOKEN_CHARS + 1) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!g_TokenReady || g_TokenReturned) {
        Token[0] = UNICODE_NULL;
        return STATUS_NOT_FOUND;
    }

    RtlStringCchCopyW(Token, TokenChars, g_Token);
    g_TokenReturned = TRUE;
    RtlSecureZeroMemory(g_Token, sizeof(g_Token));
    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"TokenAuth", L"Shutdown token returned to registered client.");
    return STATUS_SUCCESS;
}

BOOLEAN
XdowsTokenAuthValidate(
    _In_reads_z_(XDOWS_SECURITY_TOKEN_CHARS + 1) PCWSTR Token
    )
{
    UCHAR candidateHash[XDOWS_TOKEN_HASH_BYTES];
    UCHAR diff = 0;
    NTSTATUS status;

    size_t tokenLength = 0;

    if (!g_TokenReady || Token == NULL) {
        return FALSE;
    }

    if (!NT_SUCCESS(RtlStringCchLengthW(Token, XDOWS_SECURITY_TOKEN_CHARS + 1, &tokenLength)) ||
        tokenLength != XDOWS_SECURITY_TOKEN_CHARS) {
        return FALSE;
    }

    status = XdowsTokenHashBytes((PUCHAR)Token, XDOWS_SECURITY_TOKEN_CHARS * sizeof(WCHAR), candidateHash);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    for (ULONG i = 0; i < XDOWS_TOKEN_HASH_BYTES; i++) {
        diff |= (UCHAR)(candidateHash[i] ^ g_TokenHash[i]);
    }

    RtlSecureZeroMemory(candidateHash, sizeof(candidateHash));
    return diff == 0;
}

VOID
XdowsTokenAuthInvalidate(
    VOID
    )
{
    RtlSecureZeroMemory(g_Token, sizeof(g_Token));
    RtlSecureZeroMemory(g_TokenHash, sizeof(g_TokenHash));
    g_TokenReady = FALSE;
    g_TokenReturned = FALSE;
    XdowsLogWrite(XdowsSecurityLogInfo, 0, 0, L"TokenAuth", L"Shutdown token invalidated.");
}
