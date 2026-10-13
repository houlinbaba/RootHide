#ifndef ROOTHIDE_STAGE_H
#define ROOTHIDE_STAGE_H

#include <stdbool.h>

// Opt-in, process-local diagnostics for App activation and jailbreakd startup.
// The caller supplies a path writable by that process.
#define ROOTHIDE_JAILBREAKD_STAGE_LOG_PATH "/var/mobile/Library/Logs/CrashReporter/Dopamine-jailbreakd-stage.log"
#define ROOTHIDE_BOOTSTRAP_STAGE_LOG_PATH "/var/mobile/Library/Logs/CrashReporter/Dopamine-jailbreakd-bootstrap.log"
#define ROOTHIDE_REBOOT_LOG_NAME "RootHideReboot.log"
#define ROOTHIDE_REBOOT_LOG_ENV "ROOTHIDE_REBOOT_LOG_PATH"
// A fixed private file in the activating App's Documents directory. The path
// travels through sysinfo, then launchd's environment across SETEXEC. No info.h
// dependency here: this logger is also compiled into systemhook.
// Configure returns 0 or an errno value; NULL disables the mirror. Calls
// preserve the caller's errno, and diagnostics never gate primitive recovery.
int roothide_reboot_log_configure(const char *path);
void roothide_reboot_log(const char *format, ...) __attribute__((format(printf, 1, 2)));
int roothide_stage_begin(const char *path, bool append);
// Retain the already-open private log across bootstrap identity restoration.
// duplicate_fd returns a caller-owned close-on-exec descriptor; begin_from_fd
// takes ownership, so the normal end() closes it exactly once.
int roothide_stage_duplicate_fd(void);
void roothide_stage_begin_from_fd(int fd);
void roothide_stage_log(const char *format, ...) __attribute__((format(printf, 1, 2)));
// One event without enabling general tracing in launchd or replacing App state.
void roothide_stage_file_log(const char *path, const char *format, ...) __attribute__((format(printf, 2, 3)));
void roothide_stage_end(void);

#endif
