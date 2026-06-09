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
    XdowsModuleTokenAuth = 0,
    XdowsModuleLog,
    XdowsModuleProcess,
    XdowsModuleFile,
    XdowsModuleInjection,
    XdowsModuleSelf,
    XdowsModuleCount
} XDOWS_MODULE_INDEX;

static BOOLEAN g_ModuleStarted[XdowsModuleCount];

static
VOID
XdowsMarkStarted(
    _In_ XDOWS_MODULE_INDEX Index
    )
{
    g_ModuleStarted[Index] = TRUE;
}

NTSTATUS
XdowsModulesInitialize(
    VOID
    )
{
    NTSTATUS status;

    RtlZeroMemory(g_ModuleStarted, sizeof(g_ModuleStarted));

    status = XdowsTokenAuthInitialize();
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    XdowsMarkStarted(XdowsModuleTokenAuth);

    status = XdowsLogInitialize();
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    XdowsMarkStarted(XdowsModuleLog);

    status = XdowsProcessProtectInitialize();
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    XdowsMarkStarted(XdowsModuleProcess);

    status = XdowsFileProtectInitialize();
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    XdowsMarkStarted(XdowsModuleFile);

    status = XdowsInjectionProtectInitialize();
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    XdowsMarkStarted(XdowsModuleInjection);

    status = XdowsSelfProtectInitialize();
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    XdowsMarkStarted(XdowsModuleSelf);

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

    if (g_ModuleStarted[XdowsModuleLog]) {
        XdowsLogShutdown();
        g_ModuleStarted[XdowsModuleLog] = FALSE;
    }

    if (g_ModuleStarted[XdowsModuleTokenAuth]) {
        XdowsTokenAuthShutdown();
        g_ModuleStarted[XdowsModuleTokenAuth] = FALSE;
    }
}
