# Privacy and sharing

The audit is designed to help administrators share useful migration data without exposing employee identities, but normal output should be treated as sensitive tenant data.

## What `-Anonymize` changes

The script pseudonymizes identifying values such as:

- User display names, UPNs, and object IDs.
- Group IDs and names.
- Conditional Access policy IDs and names.
- Tenant/account identifiers in summary/console output.
- Application names associated with recent telephony use.

Authentication-method names, readiness flags, dates, counts, account enabled state, user type, and migration classifications are retained because they are required for analysis.

## Stable IDs across runs

Without `-AnonymizationKey`, a random in-memory key is created for each run. The same identity maps consistently across files from that run, but not across later runs.

With a private `-AnonymizationKey`, the same underlying identity maps to the same pseudonym in later audits. This enables longitudinal analysis without preserving an identity map in the output folder.

Never publish the anonymization key.

## Best-effort limitation

Anonymization is best-effort. Microsoft can add new Graph properties or method labels over time. Review generated files manually before posting them publicly.

The safest public bug report contains:

- Script version.
- PowerShell version.
- Audit stage and failing line.
- Sanitized exception text.
- A minimal synthetic reproduction where possible.
