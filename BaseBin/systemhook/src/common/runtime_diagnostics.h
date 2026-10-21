#ifndef ROOTHIDE_RUNTIME_DIAGNOSTICS_H
#define ROOTHIDE_RUNTIME_DIAGNOSTICS_H

/* Startup errors must not contact notifyd/logd from a dylib constructor. */
void roothide_runtime_diagnostic(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
void roothide_app_startup_diagnostic(const char *process, const char *event, int result);

#if ROOTHIDE_TERMINAL_DIAGNOSTICS
void roothide_terminal_diagnostic(const char *process, const char *event,
    const char *target, int result, int child, int error);
#define RH_TERMINAL_DIAGNOSTIC(...) roothide_terminal_diagnostic(__VA_ARGS__)
#else
#define RH_TERMINAL_DIAGNOSTIC(...) ((void)0)
#endif

#endif
