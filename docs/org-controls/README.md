# Organization and account-level controls

The rotation solution in this repository (`template.yaml`) provisions the
per-solution resources. Several Public Content Security Review (PCSR)
mitigations are **account- or organization-wide** and cannot be deployed from a
per-solution stack. They are documented here and must be applied through AWS
Organizations, IAM Identity Center, or your account security baseline.

> **Sample content, non-production.** These JSON documents are reference
> drafts. Review and adapt them with your security team before applying. Replace
> every `<account-id>`, `<cicd-pipeline-role>`, and cluster placeholder.

## Files

| File | Mitigation | Apply via |
| --- | --- | --- |
| `permissions-boundary.json` | M4 | IAM (attach as the execution role's permissions boundary; referenced by the `PermissionsBoundaryArn` template parameter) |
| `scp-rotation-controls.json` | M4, M10, M19 | AWS Organizations (Service Control Policy) |

## M3 — MFA and short-session credentials

- Enforce MFA for all engineer access through **IAM Identity Center**; require
  `aws:MultiFactorAuthPresent: true` on sensitive IAM operations via SCP or
  identity policies.
- The rotation execution role is created with `MaxSessionDuration: 3600`
  (1 hour) in `template.yaml`.

## M4 — Permissions boundary + SCP

- `permissions-boundary.json` denies `iam:*`, `organizations:*`, and
  `account:*` while allowing only the rotation workload actions. Attach it to
  the execution role (the template requires its ARN).
- `scp-rotation-controls.json` denies `iam:AttachRolePolicy` /
  `iam:PutRolePolicy` (and permissions-boundary tampering) on the execution
  role for every principal except your CI/CD pipeline role.

## M10 — Restrict Lambda updates to CI/CD

- `scp-rotation-controls.json` denies `lambda:UpdateFunctionCode`,
  `lambda:UpdateFunctionConfiguration`, and `lambda:AddLayerVersionPermission`
  on the rotation function for all identities except the pipeline role.
- Require pull-request review before any Lambda deployment.

## M19 — Restrict `rds:ModifyDBCluster`

- `scp-rotation-controls.json` denies `rds:ModifyDBCluster` on the two cluster
  ARNs for every principal except the rotation role.
- `template.yaml` adds an EventBridge rule (`UnexpectedModifyDBClusterRule`)
  that alerts on any `ModifyDBCluster` call not made by the rotation role.

## Account prerequisites (enable once per account/Region)

These are intentionally **not** in `template.yaml` (they are account baselines
and would conflict with an existing setup):

- **M14 — AWS CloudTrail** in `us-east-1` and `us-east-2`: management events,
  log-file integrity validation, delivery to an S3 bucket with Object Lock
  (WORM), forwarded to a centralized security-account trail.
- **M16 — Amazon GuardDuty** (with Secrets Manager protection) and **AWS
  Security Hub**, with findings routed to your SIEM/alerting. The template's
  EventBridge rules (`UnexpectedSecretAccessRule`) complement these but do not
  replace them.
