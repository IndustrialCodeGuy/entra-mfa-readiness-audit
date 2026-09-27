# Changelog

All notable changes to this project are documented here.

## [1.5.0] - 2026-09-27

### Added

- Authentication-origin classification independent of `UserType`: `Internal Member`, `Internal Guest`, `External Guest`, and `External Member`.
- Per-user fields for identity origin, classification confidence/basis, B2B invitation state, and the SMS/voice retirement milestone associated with identity origin.
- `MFA-GuestAndExternalUsers.csv` for guest/external review.
- Summary counts for enabled internal/external members and guests, plus in-scope internal guests (February 1, 2027) and external users (July 1, 2027).
- Tenant verified-domain lookup used to distinguish host-tenant versus external sign-in identity issuers.

### Changed

- User retrieval now requests `identities` and `externalUserState`.
- Added delegated `User.Read` scope so the script can read tenant `verifiedDomains` without requesting organization-wide read/write access.

## [1.4.1] - 2026-09-26

### Fixed

- Refined Conditional Access scope uncertainty handling so a separate role-targeted MFA policy no longer marks every user as `CaMfaScopeIndeterminate=True` when another enabled MFA policy definitively covers that user through evaluated user/group scope.
- `MFA-EnforcementReview.csv` now remains focused on unregistered users, potential enforcement gaps, and users whose MFA coverage is genuinely unresolved.

## [1.4.0] - 2026-09-26

### Added

- `MFA-MigrationWaves.csv`, a mutually exclusive outreach-sequencing view of enabled users in effective SMS/voice scope.
- Migration waves for recent telephony users, likely telephony-dependent users, Authenticator-ready users, phishing-resistant users, unregistered/unused accounts, and manual-review cases.
- Per-user `AuthenticatorRegistered`, `WindowsHelloForBusinessRegistered`, `PhishingResistantRegistered`, and `RecentTelephonyAuthCount` fields.
- Summary counts for each migration wave and for unique recent SMS and voice users.

### Changed

- Expanded recent telephony label recognition while retaining the raw authentication-method summary so unknown/new Graph labels remain visible.
- `MFA-MigrationCandidates.csv` remains the full enabled in-scope population; `MFA-MigrationWaves.csv` is now the recommended outreach-sequencing file.

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
