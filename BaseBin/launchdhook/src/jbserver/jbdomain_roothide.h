#ifndef JBDOMAIN_ROOTHIDE_H
#define JBDOMAIN_ROOTHIDE_H

// launchd's in-process spawn hook has no client audit token. Keep this entry
// separate from the token-checked XPC handler and out of the action table.
int roothide_trust_executable_for_launchd(const char *executablePath);

#endif
