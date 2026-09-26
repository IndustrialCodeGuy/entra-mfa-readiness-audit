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
- `PasskeyOrFidoRegistered`
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
- `CaMfaScopeIndeterminate`
- `MfaEnforcementAssessment`

Being in a Conditional Access policy's user/group scope does not prove that every sign-in is MFA-enforced; other policy conditions still apply.

### Recent sign-in usage

Generated/populated when `-IncludeRecentUsage` is used:

- `RecentSmsUseCount`
- `RecentVoiceUseCount`
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

## MFA-MigrationCandidates.csv

Subset of enabled users in effective SMS/voice policy scope. Use this as the main working population for migration planning.

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
