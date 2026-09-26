# Security Policy

## Sensitive data

Audit output can contain Microsoft Entra tenant and identity information. Do not publish raw production output in a public issue.

Use `-Anonymize` before sharing diagnostic output, and review the generated files manually because no automated anonymization process can guarantee that all future Graph fields are free of identifying information.

Never share:

- Access or refresh tokens.
- Client secrets or certificates.
- Anonymization keys.
- Unredacted user/group/policy identifiers.
- Raw sign-in records.

## Reporting a security issue

If GitHub private vulnerability reporting is enabled for the repository, use it. Otherwise, open a public issue containing only a non-sensitive description and request a private channel before sharing technical details that could expose tenant information.

## Scope

This project is intended for authorized administration of Microsoft Entra tenants you own or are permitted to manage. The audit is designed to be read-only and should not request Microsoft Graph write permissions.
