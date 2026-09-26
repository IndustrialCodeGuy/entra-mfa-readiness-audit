# Contributing

Contributions are welcome, particularly when they improve read-only auditing, compatibility, anonymization, or interpretation of changing Microsoft Graph data.

## Principles

1. Keep the default tool **read-only**.
2. Do not add Graph write scopes to the audit path.
3. Prefer Microsoft Graph v1.0 where the required data is available.
4. Clearly isolate and document beta API use.
5. Do not infer a clean or unsafe state when the available data is indeterminate.
6. Preserve PowerShell 5.1 compatibility unless a change is explicitly documented as PowerShell 7-only.
7. Treat tenant data as sensitive.

## Useful contributions

- New authentication-method labels observed in `authenticationDetails`.
- Compatibility findings from different Entra tenant configurations.
- Conditional Access scope edge cases.
- Better role-targeting analysis using optional least-privilege permissions.
- Anonymization improvements.
- Offline tests with synthetic Graph responses.
- Documentation updates when Microsoft changes the retirement timeline or Graph schemas.

## Bug reports

Include:

- Script version.
- PowerShell version (`$PSVersionTable.PSVersion`).
- Whether `-IncludeRecentUsage` or `-Anonymize` was used.
- The audit stage and script line from the diagnostic output.
- Sanitized error text.

Do **not** post user names, UPNs, object IDs, tenant IDs, group names, policy names, access tokens, or raw production exports.

## Pull requests

Keep changes focused and explain:

- What behavior changed.
- Which Graph endpoint/property is involved.
- Whether the endpoint is v1.0 or beta.
- What permissions are required.
- How null, empty, scalar, and multi-item results are handled under `Set-StrictMode`.
- How the change was validated.
