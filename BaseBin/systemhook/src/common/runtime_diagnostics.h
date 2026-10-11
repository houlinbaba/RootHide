#ifndef ROOTHIDE_RUNTIME_DIAGNOSTICS_H
#define ROOTHIDE_RUNTIME_DIAGNOSTICS_H

/* Startup errors must not contact notifyd/logd from a dylib constructor. */
void roothide_runtime_diagnostic(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
void roothide_app_startup_diagnostic(const char *process, const char *event, int result);

#endif
