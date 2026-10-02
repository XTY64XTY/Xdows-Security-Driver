#pragma once

EXTERN_C_START

NTSTATUS InjectionProtectInitialize(VOID);
VOID InjectionProtectShutdown(VOID);

//
// Counter-terminate the acting process after a user-confirmed Block verdict
// that carried XDOWS_DECISION_RESULT_KILL_ACTOR. Refuses to kill the
// registered client, critical system processes, self-protected processes,
// or PID <= 4. Best-effort: callers treat any failure as informational.
//
// Declared here so the registry gate (RegistryProtect.c) can escalate a
// critical persistence-key Block to the same counter-kill without
// duplicating the guard logic.
//
NTSTATUS
InjectionKillActor(
    _In_ ULONG ActorProcessId
    );

EXTERN_C_END
