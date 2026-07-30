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
    XdowsModuleLog = 0,
    XdowsModuleTokenAuth,
    XdowsModuleBehavior,
    XdowsModuleProcess,
    XdowsModuleFile,
    XdowsModuleInjection,
    XdowsModuleSelf,
    XdowsModuleRegistry,
    XdowsModuleCount
} XDOWS_MODULE_INDEX;

static BOOLEAN g_ModuleStarted[XdowsModuleCount];
static volatile LONG g_ActiveModuleMask;

typedef NTSTATUS (*XDOWS_MODULE_INITIALIZER)(VOID);

static
ULONG
XdowsModuleBit(
    _In_ XDOWS_MODULE_INDEX Index
    )
{
    switch (Index) {
    case XdowsModuleTokenAuth:
        return XDOWS_SECURITY_MODULE_TOKEN_AUTH;
    case XdowsModuleBehavior:
        return XDOWS_SECURITY_MODULE_BEHAVIOR;
    case XdowsModuleProcess:
        return XDOWS_SECURITY_MODULE_PROCESS;
    case XdowsModuleFile:
        return XDOWS_SECURITY_MODULE_FILE;
    case XdowsModuleInjection:
        return XDOWS_SECURITY_MODULE_INJECTION;
    case XdowsModuleSelf:
        return XDOWS_SECURITY_MODULE_SELF_PROTECT;
    case XdowsModuleRegistry:
        return XDOWS_SECURITY_MODULE_REGISTRY;
    default:
        return 0;
    }
}

static
VOID
XdowsMarkStarted(
    _In_ XDOWS_MODULE_INDEX Index
    )
{
    ULONG bit;

    g_ModuleStarted[Index] = TRUE;
    bit = XdowsModuleBit(Index);
    if (bit != 0) {
        (VOID)InterlockedOr(&g_ActiveModuleMask, (LONG)bit);
    }
}

static
VOID
XdowsMarkStopped(
    _In_ XDOWS_MODULE_INDEX Index
    )
{
    ULONG bit;

    g_ModuleStarted[Index] = FALSE;
    bit = XdowsModuleBit(Index);
    if (bit != 0) {
        (VOID)InterlockedAnd(&g_ActiveModuleMask, ~(LONG)bit);
    }
}

static
VOID
XdowsTryStartModule(
    _In_ XDOWS_MODULE_INDEX Index,
    _In_z_ PCWSTR Name,
    _In_ XDOWS_MODULE_INITIALIZER Initializer
    )
{
    NTSTATUS status;

    status = Initializer();
    if (NT_SUCCESS(status)) {
        XdowsMarkStarted(Index);
        return;
    }

    XdowsLogWriteStatus(
        XdowsSecurityLogWarning,
        0,
        0,
        Name,
        L"Protection module startup skipped",
        status);
}

NTSTATUS
XdowsModulesInitialize(
    VOID
    )
{
    NTSTATUS status;

    RtlZeroMemory(g_ModuleStarted, sizeof(g_ModuleStarted));
    (VOID)InterlockedExchange(&g_ActiveModuleMask, 0);

    status = XdowsLogInitialize();
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    XdowsMarkStarted(XdowsModuleLog);

    XdowsTryStartModule(XdowsModuleTokenAuth, L"TokenAuth", XdowsTokenAuthInitialize);
    XdowsTryStartModule(XdowsModuleBehavior, L"Behavior", XdowsBehaviorProtectInitialize);
    XdowsTryStartModule(XdowsModuleProcess, L"Process", XdowsProcessProtectInitialize);
    XdowsTryStartModule(XdowsModuleFile, L"File", XdowsFileProtectInitialize);
    XdowsTryStartModule(XdowsModuleInjection, L"Injection", XdowsInjectionProtectInitialize);
    XdowsTryStartModule(XdowsModuleSelf, L"SelfProtect", XdowsSelfProtectInitialize);
    XdowsTryStartModule(XdowsModuleRegistry, L"RegistryProtect", XdowsRegistryProtectInitialize);

    return STATUS_SUCCESS;

Fail:
    XdowsModulesShutdown();
    return status;
}

VOID
XdowsModulesShutdown(
    VOID
    )
{
    if (g_ModuleStarted[XdowsModuleRegistry]) {
        XdowsRegistryProtectShutdown();
        XdowsMarkStopped(XdowsModuleRegistry);
    }

    if (g_ModuleStarted[XdowsModuleSelf]) {
        XdowsSelfProtectShutdown();
        XdowsMarkStopped(XdowsModuleSelf);
    }

    if (g_ModuleStarted[XdowsModuleInjection]) {
        XdowsInjectionProtectShutdown();
        XdowsMarkStopped(XdowsModuleInjection);
    }

    if (g_ModuleStarted[XdowsModuleFile]) {
        XdowsFileProtectShutdown();
        XdowsMarkStopped(XdowsModuleFile);
    }

    if (g_ModuleStarted[XdowsModuleProcess]) {
        XdowsProcessProtectShutdown();
        XdowsMarkStopped(XdowsModuleProcess);
    }

    if (g_ModuleStarted[XdowsModuleBehavior]) {
        XdowsBehaviorProtectShutdown();
        XdowsMarkStopped(XdowsModuleBehavior);
    }

    if (g_ModuleStarted[XdowsModuleTokenAuth]) {
        XdowsTokenAuthShutdown();
        XdowsMarkStopped(XdowsModuleTokenAuth);
    }

    if (g_ModuleStarted[XdowsModuleLog]) {
        XdowsLogShutdown();
        g_ModuleStarted[XdowsModuleLog] = FALSE;
    }
}

ULONG
XdowsModulesGetActiveMask(
    VOID
    )
{
    return (ULONG)InterlockedCompareExchange(&g_ActiveModuleMask, 0, 0);
}
