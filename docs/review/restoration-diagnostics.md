# Restoration diagnostics (A)

Baseline: 21cbdb5cbfc2f4bc17397b60ed1ea12903f2e913. Research only; F1/F3 remain FAIL.

`dopamine_drop_root` now owns a request-local first-failure scope for lookup,
credential read, identity policy, audit-token path lookup and installation. Local
`proc_credential_restore_self` owns a separate scope, including NULL/invalid
snapshot returns; pid=0 denotes this self operation without an extra lookup.
Nested scopes restore their predecessor. The first lower-level error and final
boundary result remain separate. Backlink/translation errors in reference access
gain constant phase labels; the operations themselves are unchanged.

Business branch/call ordering, return conversions, snapshot validation, counted
reference order, rollback order and partial-release flags are unchanged. The new
finish runs after the existing unlock and preserves its caller-visible errno.
No authorization, helper policy, cancellation or App-exit behavior changes.
Only related stage proc/ucred/donor address fields were removed; historical logs
were not changed. A rollback error remains an error with owned state, not a claim
that rollback completed.

Validation: production-code host substitutes execute early restore boundaries,
11 read faults, 6 reference/release faults, 4 write faults, write-plus-rollback
failure, nested restore and drop-root branches. Existing immutable-credential
lifecycle tests remain passing. The pre-change restore fails the new assertion at
runtime. Six compiled mutants (scope removal, first-error overwrite, errno
corruption, disabled logging, domain conflation) are rejected by runtime
assertions. Eight overlapping diagnostic scopes test TLS isolation. These are
host execution results, not Apple SDK/product or device acceptance.
