/*++

Module Name:

    moduleregistry.c

Abstract:

    Ordered protection module initialization and shutdown.

--*/

#include "driver.h"
#include "behaviorrules.h"
#include "fileprotect.h"
#include "injectionprotect.h"
#include "log.h"
#include "registryprotect.h"
#include "selfprotect.h"
#include "tokenauth.h"

typedef enum _XDOWS_MODULE_INDEX {
    ModuleLog = 0,
    ModuleTokenAuth,
    ModuleBehavior,
    ModuleProcess,
    ModuleFile,
    ModuleInjection,
    ModuleSelf,
    ModuleRegistry,
    ModuleCount
} XDOWS_MODULE_INDEX;

static BOOLEAN g_ModuleStarted[ModuleCount];
static volatile LONG g_ActiveModuleMask;

typedef NTSTATUS (*XDOWS_MODULE_INITIALIZER)(VOID);

static
ULONG
ModuleBit(
    _In_ XDOWS_MODULE_INDEX Index
    )
{
    switch (Index) {
    case ModuleTokenAuth:
        return XDOWS_SECURITY_MODULE_TOKEN_AUTH;
    case ModuleBehavior:
        return XDOWS_SECURITY_MODULE_BEHAVIOR;
    case ModuleProcess:
        return XDOWS_SECURITY_MODULE_PROCESS;
    case ModuleFile:
        return XDOWS_SECURITY_MODULE_FILE;
    case ModuleInjection:
        return XDOWS_SECURITY_MODULE_INJECTION;
    case ModuleSelf:
        return XDOWS_SECURITY_MODULE_SELF_PROTECT;
    case ModuleRegistry:
        return XDOWS_SECURITY_MODULE_REGISTRY;
    default:
        return 0;
    }
}

static
VOID
MarkStarted(
    _In_ XDOWS_MODULE_INDEX Index
    )
{
    ULONG bit;

    g_ModuleStarted[Index] = TRUE;
    bit = ModuleBit(Index);
    if (bit != 0) {
        (VOID)InterlockedOr(&g_ActiveModuleMask, (LONG)bit);
    }
}

static
VOID
MarkStopped(
    _In_ XDOWS_MODULE_INDEX Index
    )
{
    ULONG bit;

    g_ModuleStarted[Index] = FALSE;
    bit = ModuleBit(Index);
    if (bit != 0) {
        (VOID)InterlockedAnd(&g_ActiveModuleMask, ~(LONG)bit);
    }
}

static
VOID
TryStartModule(
    _In_ XDOWS_MODULE_INDEX Index,
    _In_z_ PCWSTR Name,
    _In_ XDOWS_MODULE_INITIALIZER Initializer
    )
{
    NTSTATUS status;

    status = Initializer();
    if (NT_SUCCESS(status)) {
        MarkStarted(Index);
        return;
    }

    LogWriteStatus(
        XdowsSecurityLogWarning,
        0,
        0,
        Name,
        L"Protection module startup skipped",
        status);
}

NTSTATUS
ModulesInitialize(
    VOID
    )
{
    NTSTATUS status;

    RtlZeroMemory(g_ModuleStarted, sizeof(g_ModuleStarted));
    (VOID)InterlockedExchange(&g_ActiveModuleMask, 0);

    status = LogInitialize();
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    MarkStarted(ModuleLog);

    TryStartModule(ModuleTokenAuth, L"TokenAuth", TokenAuthInitialize);
    TryStartModule(ModuleBehavior, L"Behavior", BehaviorProtectInitialize);
    TryStartModule(ModuleProcess, L"Process", ProcessProtectInitialize);
    TryStartModule(ModuleFile, L"File", FileProtectInitialize);
    TryStartModule(ModuleInjection, L"Injection", InjectionProtectInitialize);
    TryStartModule(ModuleSelf, L"SelfProtect", SelfProtectInitialize);
    TryStartModule(ModuleRegistry, L"RegistryProtect", RegistryProtectInitialize);

    return STATUS_SUCCESS;

Fail:
    ModulesShutdown();
    return status;
}

VOID
ModulesShutdown(
    VOID
    )
{
    if (g_ModuleStarted[ModuleRegistry]) {
        RegistryProtectShutdown();
        MarkStopped(ModuleRegistry);
    }

    if (g_ModuleStarted[ModuleSelf]) {
        SelfProtectShutdown();
        MarkStopped(ModuleSelf);
    }

    if (g_ModuleStarted[ModuleInjection]) {
        InjectionProtectShutdown();
        MarkStopped(ModuleInjection);
    }

    if (g_ModuleStarted[ModuleFile]) {
        FileProtectShutdown();
        MarkStopped(ModuleFile);
    }

    if (g_ModuleStarted[ModuleProcess]) {
        ProcessProtectShutdown();
        MarkStopped(ModuleProcess);
    }

    if (g_ModuleStarted[ModuleBehavior]) {
        BehaviorProtectShutdown();
        MarkStopped(ModuleBehavior);
    }

    if (g_ModuleStarted[ModuleTokenAuth]) {
        TokenAuthShutdown();
        MarkStopped(ModuleTokenAuth);
    }

    if (g_ModuleStarted[ModuleLog]) {
        LogShutdown();
        g_ModuleStarted[ModuleLog] = FALSE;
    }
}

ULONG
ModulesGetActiveMask(
    VOID
    )
{
    return (ULONG)InterlockedCompareExchange(&g_ActiveModuleMask, 0, 0);
}
