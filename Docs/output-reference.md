# Output reference

## MFA-Summary.csv

High-level health and migration counts. Important fields include:

- Authentication Methods migration state.
- Registration campaign state.
- SMS/Voice policy state and effective user counts.
- Registration-report match count.
- Likely telephony-dependent user count.
- Passwordless-capable count.
- Unregistered users split by whether a successful sign-in timestamp is retained.
- Conditional Access MFA-policy coverage.
- Potential enforcement-gap count.
- Unique recent SMS/voice users when recent usage analysis is enabled.

## MFA-UserAudit.csv

Full per-user correlated dataset.

### Identity/status

- `DisplayName`
- `UserPrincipalName`
- `ObjectId`
- `AccountEnabled`
- `UserType`
- `IsAdmin`

`IsAdmin` indicates that the registration report considers the account an administrator; it does not identify a specific role such as Global Administrator.

### Sign-in history

- `HasAnySignInActivity`
- `HasSuccessfulSignInRecorded`
- `LastInteractiveSignInAttemptUtc`
- `LastNonInteractiveAttemptUtc`
- `LastSuccessfulSignInUtc`
- `SignInHistoryClassification`

A blank/missing sign-in timestamp is not proof that an account has never been used. Microsoft Graph retention and historical availability apply.

### Authentication Methods policy

- `SmsPolicyInScope`
- `VoicePolicyInScope`
- `SmsOrVoicePolicyInScope`

These represent calculated effective scope after expanding included groups and removing excluded targets.

### Registration/readiness

- `MethodsRegistered`
- `PhoneRegistered`
- `NonTelephonyMfaRegistered`
- `AuthenticatorRegistered`
- `PasskeyOrFidoRegistered`
- `WindowsHelloForBusinessRegistered`
- `PhishingResistantRegistered`
- `IsMfaRegistered`
- `IsMfaCapable`
- `IsPasswordlessCapable`
- `SystemPreferredMethods`
- `UserPreferredMfaMethod`
- `SmsOrVoicePreferred`
- `LikelyTelephonyDependent`
- `NoRegisteredAuthenticationMethods`

`LikelyTelephonyDependent` is an operational classification made by this project: the user is in effective SMS/voice scope, has a phone method, and no durable non-telephony MFA method was detected in `methodsRegistered`.

### Enforcement signals

- `SecurityDefaultsEnabled`
- `LegacyPerUserMfaState`
- `CaMfaEnabledPolicyUserScope`
- `CaMfaEnabledPolicyCount`
- `CaMfaEnabledPolicyNames`
- `CaMfaReportOnlyPolicyCount`
- `CaMfaScopeIndeterminate` - true only when unresolved Conditional Access role/other scope could still affect the user's overall MFA coverage; a separate role-targeted policy does not make this true when another enabled MFA policy definitively covers the user
- `MfaEnforcementAssessment`

Being in a Conditional Access policy's user/group scope does not prove that every sign-in is MFA-enforced; other policy conditions still apply.

### Recent sign-in usage

Generated/populated when `-IncludeRecentUsage` is used:

- `RecentSmsUseCount`
- `RecentVoiceUseCount`
- `RecentTelephonyAuthCount`
- `RecentSmsOrVoiceUse`
- `LastSmsOrVoiceUseUtc`
- `LastSmsOrVoiceMethod`
- `LastSmsOrVoiceApp`
- `RecentSignInCount`
- `RecentSuccessfulSignInCount`
- `RecentInteractiveSignInCount`
- `RecentMfaRequiredSignInCount`
- `RecentCaMfaAppliedSignInCount`

Counts are sign-in/authentication-step observations, not unique people. The summary reports unique users with at least one successful telephony step.


### Identity-origin and guest/external fields

- `IdentityOrigin` - `Internal` or `External`; this is independent of `UserType`.
- `UserClassification` - `Internal Member`, `Internal Guest`, `External Guest`, or `External Member`.
- `IsExternalUser` - true when authentication is determined to be homed outside the resource tenant.
- `IdentityOriginConfidence` - `High` when invitation state, identity issuer, or a B2B `#EXT#` UPN provides a direct signal; otherwise `Inferred`.
- `IdentityClassificationBasis` - non-identifying description of the signal used.
- `ExternalUserState` - B2B invitation state when Graph reports one.
- `TelephonyRetirementMilestone` - identity-origin retirement milestone. Internal guests are February 1, 2027; external users are July 1, 2027. Internal-member rows note that Global Administrators have the later July date because this audit does not currently resolve the specific Global Administrator role.

`UserType=Guest` is a relationship/permission label, not an authentication-origin indicator. The audit therefore does not assume every Guest is external.

## MFA-MigrationCandidates.csv

Subset of enabled users in effective SMS/voice policy scope. This remains the complete in-scope working population.

## MFA-MigrationWaves.csv

The same enabled in-scope population, sorted by `MigrationWaveOrder` and `DisplayName`, with mutually exclusive outreach categories.

Important fields:

- `MigrationWaveOrder`
- `MigrationWave`
- `MigrationWaveReason`
- `RecentTelephonyAuthCount`
- `AuthenticatorRegistered`
- `PhishingResistantRegistered`

Wave 1 is meaningful only when the audit is run with `-IncludeRecentUsage`; otherwise recent SMS/voice use is not observed and users can fall into later readiness-based waves instead.

## MFA-EnforcementReview.csv

Focus list containing enabled/in-scope accounts that are unregistered, have a potential enforcement-gap classification, or have indeterminate Conditional Access role/guest scope.

## MFA-RecentAuthMethodSummary.csv

Raw authentication-method labels observed in recent sign-in `authenticationDetails`, plus total and successful step counts and the project's telephony classification.

This file is intentionally useful for detecting future Graph label changes. If Microsoft starts returning a new SMS/voice label, it should appear here even before the classifier recognizes it.

## Policy files

- `MFA-PolicyTargets.csv`
- `MFA-ConditionalAccessMfaPolicies.csv`
- `MFA-AuthenticationMethodsPolicy.json`
- `MFA-SMS-Policy.json`
- `MFA-Voice-Policy.json`

When `-Anonymize` is enabled, identifying policy/group/user values are pseudonymized or reduced to non-identifying state fields where practical.

## MFA-GuestAndExternalUsers.csv

Contains enabled users where either `UserType=Guest` or `IsExternalUser=True`. It is intended for retirement-date planning and guest/external Conditional Access review. External members are included because the July 1, 2027 retirement follows external authentication origin rather than `UserType`.
