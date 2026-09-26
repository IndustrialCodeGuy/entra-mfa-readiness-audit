# Microsoft Entra MFA Readiness Audit

A read-only PowerShell audit for Microsoft Entra ID environments preparing for the retirement of Microsoft-provided SMS and voice authentication.

The tool expands Authentication Methods policy scope to actual users, correlates MFA registration and passwordless readiness, reviews sign-in activity and MFA enforcement signals, and can optionally inspect recent sign-ins for actual SMS/voice usage.

> **Independent project:** This repository is not affiliated with, endorsed by, sponsored by, or distributed by Microsoft.

## Why this exists

Microsoft publishes an official [Entra SMS/Voice Policy Scanner](https://github.com/microsoft/entra-sms-voice-usage-analyzer). Its documentation describes it as a **policy-scope scanner, not a user inventory or usage report**: it does not expand group membership, calculate effective user counts after exclusions, inspect registered methods, or read sign-in activity.

This project is intended to complement that policy-level view with an operational per-user audit useful for migration planning and remediation.

No Microsoft source code is included in this project.

## Retirement context

Microsoft's current public-cloud guidance states:

- **September 1, 2026:** passkeys become the default authentication experience for users enabled for SMS or voice, with automatic passkey enablement/registration nudges beginning.
- **February 1, 2027:** Microsoft-provided SMS and voice delivery is retired for users in scope of the February retirement. Global Administrators and external users follow the later date; internal guest users remain in the February population.
- **July 1, 2027:** Microsoft-provided SMS and voice delivery is retired for Global Administrators and external users.

Always use Microsoft's current documentation as the source of truth:

- [SMS and voice retirement guidance](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement)
- [Retirement FAQ](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement-faq)
- [Passkey deployment guidance](https://aka.ms/passkeydeploymentguide)

## What the audit does

The script is read-only. It can:

- Read the tenant Authentication Methods migration state and registration campaign state.
- Read SMS and Voice authentication-method policy configuration.
- Expand included and excluded groups **transitively** and calculate effective user scope.
- Read the `userRegistrationDetails` report and correlate:
  - MFA registration and capability.
  - Passwordless capability.
  - Registered authentication methods.
  - System-preferred authentication methods.
  - User-preferred secondary authentication method.
- Read `signInActivity` to distinguish accounts with successful sign-in history from accounts with no retained successful sign-in timestamp.
- Read Security Defaults status.
- Identify Conditional Access policies requiring MFA or an MFA-satisfying authentication strength.
- Determine whether a user is in the directly evaluated user/group scope of those policies.
- Optionally analyze recent sign-ins for:
  - Successful SMS and voice authentication.
  - Raw authentication-method labels returned by Graph.
  - MFA-required sign-ins.
  - Enabled MFA Conditional Access policies observed applying to sign-ins.
- Pseudonymize identifying output while preserving analytical relationships across files.
- Produce prioritized migration and enforcement-review CSVs.

## What it does **not** claim

This is an audit and planning tool, not a certification that every sign-in is protected by MFA.

Conditional Access evaluation is contextual. A user can be in the user/group scope of a policy while application, location, device, platform, client type, sign-in risk, user risk, or other conditions determine whether the policy applies to a particular sign-in.

Role-targeted Conditional Access include/exclude assignments are intentionally reported as **indeterminate** rather than guessed. Resolving directory-role membership would require additional permissions that this tool does not request.

`signInActivity` also has retention and licensing limits. A missing timestamp should be interpreted as **no retained sign-in activity**, not absolute proof that an account has never been used.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.x.
- Microsoft Graph PowerShell Authentication module:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

The script requests these delegated scopes when it needs to establish a Graph session:

| Scope | Purpose |
| --- | --- |
| `Policy.Read.All` | Authentication Methods, Security Defaults, and Conditional Access policy reads |
| `AuditLog.Read.All` | Authentication Methods registration report, `signInActivity`, and sign-in logs |
| `User.Read.All` | User inventory |
| `Group.Read.All` | Group names and transitive membership expansion |

Microsoft Entra directory roles can also affect access to individual reports and policy resources. `signInActivity` requires Microsoft Entra ID P1 or P2 and `AuditLog.Read.All`.

## Quick start

From the repository root:

```powershell
.\Scripts\Get-EntraMfaReadinessAudit.ps1
```

The default audit uses Microsoft Graph v1.0 for its core policy, registration, user, sign-in-activity, Security Defaults, and Conditional Access analysis.

### Include recent SMS/voice usage

```powershell
.\Scripts\Get-EntraMfaReadinessAudit.ps1 `
    -IncludeRecentUsage `
    -UsageDays 30
```

The recent sign-in authentication-step analysis uses Microsoft Graph beta properties. Failure of that optional section does not invalidate the core audit.

### Run against a specific tenant

```powershell
.\Scripts\Get-EntraMfaReadinessAudit.ps1 `
    -TenantId 'contoso.onmicrosoft.com'
```

### Produce shareable anonymized output

```powershell
.\Scripts\Get-EntraMfaReadinessAudit.ps1 `
    -Anonymize `
    -IncludeRecentUsage
```

Without an anonymization key, pseudonyms are consistent only within that run.

For repeatable pseudonyms across monthly/quarterly audits:

```powershell
$key = Read-Host 'Private anonymization key'

.\Scripts\Get-EntraMfaReadinessAudit.ps1 `
    -Anonymize `
    -AnonymizationKey $key `
    -IncludeRecentUsage `
    -UsageDays 30
```

Keep the key private. It is not written to the output directory.

## Recent telephony detection

Microsoft Graph sign-in authentication details can use human-readable labels rather than the registration-report names. The audit currently recognizes successful telephony steps including:

- `SMS`
- `Text message`
- `Voice`
- `Voice call`
- `Phone call`
- `Phone call approval (Authentication phone)`

The raw values encountered are also exported to `MFA-RecentAuthMethodSummary.csv`, making unexpected/new Graph labels visible instead of silently discarding them.

## Output files

A timestamped output directory is created by default.

| File | Purpose |
| --- | --- |
| `MFA-Summary.csv` | High-level counts and audit status |
| `MFA-UserAudit.csv` | Full correlated per-user inventory |
| `MFA-MigrationCandidates.csv` | Enabled users currently in effective SMS/voice policy scope |
| `MFA-EnforcementReview.csv` | Unregistered accounts and other enforcement-review candidates |
| `MFA-PolicyTargets.csv` | Authentication Methods include/exclude targets and expanded counts |
| `MFA-ConditionalAccessMfaPolicies.csv` | MFA/authentication-strength CA policies and targeting summary |
| `MFA-RecentAuthMethodSummary.csv` | Raw recent sign-in authentication methods and step counts; generated with `-IncludeRecentUsage` |
| `MFA-AuthenticationMethodsPolicy.json` | Authentication Methods policy snapshot |
| `MFA-SMS-Policy.json` | SMS policy snapshot |
| `MFA-Voice-Policy.json` | Voice policy snapshot |

See [Docs/output-reference.md](Docs/output-reference.md) for interpretation guidance.

## Migration-priority categories

The per-user audit assigns a working migration priority:

| Priority | Meaning |
| --- | --- |
| `0A - Unregistered / no successful sign-in recorded` | No registered auth method and no retained successful sign-in timestamp |
| `0B - Unregistered / successful sign-in recorded` | Successful sign-in history but no registered auth method; investigate enforcement |
| `1 - Recent SMS/Voice use` | Successful telephony authentication observed in the requested recent period |
| `2 - Likely telephony dependent` | Phone method registered and no durable non-telephony MFA alternative detected |
| `3 - SMS/Voice preferred` | Stronger method exists but user/system preference still indicates telephony |
| `4 - Phone registered` | Phone remains registered but another MFA method is available |
| `5 - Policy scope only` | In SMS/voice policy scope without a registered phone method |

These are operational triage categories, not Microsoft-defined risk classifications.

## Privacy and sharing

Normal output can contain names, UPNs, object IDs, group names, Conditional Access policy names, tenant IDs, and application names.

Use `-Anonymize` before sharing results outside the administrative team. Stable pseudonyms allow multiple output files to be correlated without publishing the original identities.

Anonymization is best-effort. Review files before publishing or attaching them to a public issue. See [Docs/privacy-and-sharing.md](Docs/privacy-and-sharing.md).

## Repository layout

```text
entra-mfa-readiness-audit/
├── README.md
├── LICENSE
├── NOTICE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── Scripts/
│   └── Get-EntraMfaReadinessAudit.ps1
├── Docs/
│   ├── output-reference.md
│   └── privacy-and-sharing.md
└── .github/
    └── ISSUE_TEMPLATE/
        ├── bug_report.yml
        └── feature_request.yml
```

## Project status

This is an independent administrator tool developed from real-world migration auditing and tested against live Microsoft Entra data. Microsoft Graph schemas and authentication-method labels can change. Review unexpected values in the raw method summary and validate important findings against the Entra admin center before making production policy changes.

The script does not request Graph write scopes and does not change tenant configuration.

## Contributing

Issues and pull requests are welcome. Useful contributions include:

- New anonymized authentication-method labels observed in Graph sign-in details.
- Validation from different tenant sizes and Conditional Access designs.
- Safer or more complete anonymization.
- Additional read-only migration-readiness checks.
- PowerShell 5.1/7 compatibility fixes.
- Documentation corrections following Microsoft Graph/API changes.

Do not post production tenant exports containing identifiable information in public issues.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (C) 2026 Dan Michel.

Licensed under the **GNU General Public License version 3 only** (`GPL-3.0-only`). Commercial and private use are permitted. Redistribution and derivative works are subject to the GPLv3 terms, including corresponding-source requirements.

See [LICENSE](LICENSE) for the governing terms.

## Independence and trademarks

Microsoft Entra MFA Readiness Audit is an independent third-party project. It is not affiliated with, endorsed by, sponsored by, or distributed by Microsoft.

Microsoft, Microsoft Entra, Windows, and related product names are trademarks of the Microsoft group of companies. Their names are used only to identify compatible services, products, APIs, and documentation.

See [NOTICE](NOTICE).

## Disclaimer

The software is provided on an **AS IS** basis, without warranties or conditions of any kind. Authentication policy and sign-in analysis can be affected by licensing, retention, API changes, Conditional Access conditions, tenant configuration, and incomplete data. Validate findings before changing production authentication policy.
