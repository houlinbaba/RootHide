# Runtime identity (B) contract

Action 1 in the Dopamine domain has no wire inputs, output argument 0 `version`
(string), and bool handler result (`result` int64 1). The dispatcher supplies up
to eight argument slots, passes output storage by pointer, copies each output
into its reply and frees/releases it. It runs `dopamine_domain_allowed` before
dispatch (audit-token path plus existing App identity policy).

Append output argument 1 `runtime-identity` (dictionary); preserve argument 0,
all old keys/types, action IDs and bool result. Old clients ignore the extra
dictionary. New clients receiving result=1 with no dictionary report unsupported;
unsupported formats are also unsupported. Wrong types/results are malformed;
absent image identities are unknown. No usable reply remains unclassified.
There is no fallback check-in/get-root/grant consumption or permission change.
The C handler now explicitly returns int 1 to match the dispatcher's existing
int ABI; the original bool true wire result remains 1. The old-server host
substitute models that established wire result, not a foreign host bool ABI.

Format 1 includes a first-load bool and two UUID strings from addresses of the
actual status handler and `proc_credential_restore_self` in the server process.
`dladdr` locates each mapped header (function pointer authentication stripped on
arm64e). Parse LC_UUID and require membership in the executable header segment;
unsupported layouts fail closed as unknown. No file is reopened for identity.
The old `version` read remains solely for its pre-existing output, never identity.
No kernel operation or cross-process access is introduced. UUID is attribution,
not attestation; firstLoad is not READY/session identity. Matching requires an
independent architecture-specific manifest; the UI reports unverified UUIDs.

The explicit menu query is separate from file export/startup. Its UI wait is 5s;
one in-flight worker retains all local result resources until synchronous RPC
returns. Main-queue-only state avoids timeout/late-completion races; weak view
capture prevents use of a discarded screen. A late reply never presents UI.
An indefinitely blocked transport occupies the one-worker budget until App exit;
the implementation does NOT promise a remote deadline or bounded worker time.
Repeated presses cannot accumulate workers. This limitation is visible in UI and
does not alter the global transport or pretend that timeout cancels the server.

Research only, not a deployment/repair candidate. Device-loaded service and
arm64e runtime behavior still require approved platform evidence.
