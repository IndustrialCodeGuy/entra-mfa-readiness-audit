# Changelog

All notable changes to this project are documented here.

## [1.3.0] - 2026-09-25

First public repository release.

### Added

- Effective SMS and Voice policy-scope expansion, including transitive group membership and exclusions.
- Authentication Methods registration-report correlation.
- Passwordless, FIDO/passkey, phone, MFA-capability, and preferred-method analysis.
- `signInActivity` correlation for successful/interactive/non-interactive sign-in history.
- Security Defaults status.
- Conditional Access MFA/authentication-strength policy inventory and user/group-scope analysis.
- Optional recent sign-in authentication-step analysis.
- Recent MFA-required and applied-CA-policy observations.
- Legacy per-user MFA check for enabled in-scope users with no registered methods.
- Deterministic output pseudonymization with optional cross-run key.
- Diagnostic stage/line reporting for terminating script errors.
- Authentication Methods migration state and registration campaign state.
- Public documentation and repository packaging.

### Fixed

- Recent telephony detection now recognizes Graph sign-in labels observed in live data, including `Text message` and `Phone call approval (Authentication phone)`, in addition to `SMS` and `Voice`-style labels.
- Avoided PowerShell `$PID` automatic-variable collisions in Conditional Access loops.
- Hardened scalar/array handling under `Set-StrictMode`.
- Corrected variable interpolation before Graph query strings such as `${GroupId}?$select=...`.

### Notes

- Core audit data uses Microsoft Graph v1.0.
- Optional recent authentication-detail analysis and the legacy per-user MFA requirement endpoint use Microsoft Graph beta.
