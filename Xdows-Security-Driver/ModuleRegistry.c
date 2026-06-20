/*++

Module Name:

    moduleregistry.c

Abstract:

    Ordered protection module initialization and shutdown.

--*/

#include "driver.h"
#include "fileprotect.h"
#include "injectionprotect.h"
#include "log.h"
#include "selfprotect.h"
#include "tokenauth.h"

typedef enum _XDOWS_MODULE_INDEX {
    XdowsModuleLog = 0,
    XdowsModuleTokenAuth,
    XdowsModuleProcess,
    XdowsModuleFile,
    XdowsModuleInjection,
    XdowsModuleSelf,
    XdowsModuleCount
} XDOWS_MODULE_INDEX;

static BOOLEAN g_ModuleStarted[XdowsModuleCount];

typedef NTSTATUS (*XDOWS_MODULE_INITIALIZER)(VOID);

static
VOID
XdowsMarkStarted(
    _In_ XDOWS_MODULE_INDEX Index
    )
{
    g_ModuleStarted[Index] = TRUE;
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

    status = XdowsLogInitialize();
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    XdowsMarkStarted(XdowsModuleLog);

    XdowsTryStartModule(XdowsModuleTokenAuth, L"TokenAuth", XdowsTokenAuthInitialize);
    XdowsTryStartModule(XdowsModuleProcess, L"Process", XdowsProcessProtectInitialize);
    XdowsTryStartModule(XdowsModuleFile, L"File", XdowsFileProtectInitialize);
    XdowsTryStartModule(XdowsModuleInjection, L"Injection", XdowsInjectionProtectInitialize);
    XdowsTryStartModule(XdowsModuleSelf, L"SelfProtect", XdowsSelfProtectInitialize);

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
    if (g_ModuleStarted[XdowsModuleSelf]) {
        XdowsSelfProtectShutdown();
        g_ModuleStarted[XdowsModuleSelf] = FALSE;
    }

    if (g_ModuleStarted[XdowsModuleInjection]) {
        XdowsInjectionProtectShutdown();
        g_ModuleStarted[XdowsModuleInjection] = FALSE;
    }

    if (g_ModuleStarted[XdowsModuleFile]) {
        XdowsFileProtectShutdown();
        g_ModuleStarted[XdowsModuleFile] = FALSE;
    }

    if (g_ModuleStarted[XdowsModuleProcess]) {
        XdowsProcessProtectShutdown();
        g_ModuleStarted[XdowsModuleProcess] = FALSE;
    }

    if (g_ModuleStarted[XdowsModuleTokenAuth]) {
        XdowsTokenAuthShutdown();
        g_ModuleStarted[XdowsModuleTokenAuth] = FALSE;
    }

    if (g_ModuleStarted[XdowsModuleLog]) {
        XdowsLogShutdown();
        g_ModuleStarted[XdowsModuleLog] = FALSE;
    }
}
