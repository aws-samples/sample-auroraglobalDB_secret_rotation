# Failover-Aware Master User Password Rotation for Amazon Aurora Global Database

This repository contains the AWS Lambda rotation function, IAM policies, and an
AWS SAM template for rotating the master user password of an Amazon Aurora
MySQL Global Database through AWS Secrets Manager.

> **Sample code — non-production.** This is sample code, for non-production
> usage. You should work with your security and legal teams to meet your
> organizational security, regulatory, and compliance requirements before
> deployment. Deploying this content may incur AWS charges for the resources it
> creates (Lambda, Secrets Manager, KMS, VPC endpoints, and others).

The native "Manage master credentials in AWS Secrets Manager" option does not
support DB clusters that are part of an Aurora global database. This solution
closes that gap with a custom rotation Lambda that:

- Implements the standard Secrets Manager four-step rotation protocol
  (`createSecret`, `setSecret`, `testSecret`, `finishSecret`).
- Discovers the current **writer** cluster before each rotation by calling the
  Amazon RDS `DescribeGlobalClusters` API (`IsWriter = true`), so rotation is
  resilient to planned and unplanned failovers.
- Re-verifies the writer during `testSecret` to detect a failover that occurs
  mid-rotation and stop safely.

This walkthrough uses **us-east-1** as the primary Region and **us-east-2** as
the secondary (DR) Region. Adjust the parameters and ARNs if you use other
Regions.

## Repository contents

```
src/lambda_function.py              # Failover-aware rotation Lambda (Python 3.12)
template.yaml                       # AWS SAM template (hardened rotation solution)
iam_policy.json                     # IAM execution-role permissions policy
iam_trust_policy.json               # IAM role trust policy (lambda.amazonaws.com)
Requirements.txt                    # Pinned test/CI dependencies
RUNBOOK.md                          # Rotation-failure alerting and recovery runbook
docs/org-controls/                  # Account/org-level controls (SCP, permissions boundary)
```

## Deploying with AWS SAM (recommended)

`template.yaml` provisions the hardened rotation solution: the rotation Lambda
(VPC-bound and code-signed), a customer managed KMS key for the secret, the
secret with a restrictive resource policy, an explicit encrypted log group,
interface VPC endpoints, rotation-failure alarms, and security EventBridge
rules.

```bash
sam build
sam deploy --guided \
  --parameter-overrides \
    PrimaryRegion=us-east-1 \
    SecondaryRegion=us-east-2 \
    GlobalClusterId=<your-global-cluster-id> \
    PrimaryClusterId=<your-primary-cluster-id> \
    SecondaryClusterId=<your-secondary-cluster-id> \
    SecretName=aurora-global-master-cred \
    VpcId=<your-vpc-id> \
    PrivateSubnetIds=<subnet-a>,<subnet-b> \
    PermissionsBoundaryArn=arn:aws:iam::<account-id>:policy/<boundary-name> \
    [email protected]
```

Before deploying, create the permissions boundary from
`docs/org-controls/permissions-boundary.json` (see M4 below); the template
requires its ARN.

The template deploys the rotation solution only. Account-wide security
baselines — AWS CloudTrail, Amazon GuardDuty, and AWS Security Hub — are
prerequisites documented in [`docs/org-controls/`](docs/org-controls/), because
they are enabled once per account/organization.

## Configuration

- **Runtime:** Python 3.12
- **Handler:** `lambda_function.lambda_handler`
- **Timeout:** 60 seconds
- **Memory:** 128 MB
- **Environment variable:** `GLOBAL_CLUSTER_ID` — **required**. The function
  validates this at initialization against the pattern
  `^[a-zA-Z][a-zA-Z0-9-]{1,62}$` and raises `EnvironmentError` if it is missing
  or malformed. There is no default; the function fails closed rather than
  rotating an unintended cluster.

## Security hardening

This sample applies the following controls (mapped to the security review that
gated publication):

- **Least-privilege IAM** — execution-role permissions in `iam_policy.json` are
  scoped to the specific secret, cluster ARNs (both Regions), and log group.
  `rds:DescribeGlobalClusters` and `secretsmanager:GetRandomPassword` do not
  support resource-level permissions, so those statements use `Resource: "*"`.
- **Scoped trust policy** — `iam_trust_policy.json` restricts assumption with an
  `aws:SourceAccount` condition.
- **Customer managed KMS key** — the secret is encrypted with a dedicated CMK
  whose key policy limits decrypt to the execution role and the Secrets Manager
  service principal.
- **Secret resource policy** — denies `GetSecretValue`/`PutSecretValue` for all
  principals except the rotation execution role.
- **VPC-bound Lambda** — runs in private subnets with egress limited to
  interface VPC endpoints for RDS, Secrets Manager, and CloudWatch Logs.
- **Code signing** — enforced through AWS Signer.
- **Encrypted logs** — explicit log group with a CMK, 90-day retention, and a
  metric-filter alarm that fires if a log event ever contains a plaintext
  secret marker.
- **Alerting** — CloudWatch alarms and EventBridge rules for rotation failures,
  unexpected `ModifyDBCluster`, and unexpected `GetSecretValue`, routed to SNS.
- **Org-level controls** — MFA/short sessions (M3), permissions boundary and
  SCPs (M4/M10/M19) in [`docs/org-controls/`](docs/org-controls/).

## Secret structure

The rotation Lambda expects the secret to contain the following JSON:

```json
{
    "username": "admin",
    "password": "<your-current-password>",
    "engine": "mysql",
    "host": "<your-primary-cluster-endpoint>",
    "port": 3306,
    "dbClusterIdentifier": "<your-primary-cluster-id>",
    "writerRegion": "us-east-1",
    "globalClusterIdentifier": "<your-global-cluster-id>"
}
```

> **Security note:** Never store a real password in source control. When
> creating the secret from the command line, write the JSON to a temporary file
> with restrictive permissions and reference it with `file://` rather than
> passing the password inline, then delete the file. In production, create and
> rotate secrets through infrastructure-as-code or a controlled pipeline.

## Password generation

`generate_password()` produces a 30-character password guaranteed to include an
uppercase letter, a lowercase letter, a digit, and a special character, while
never emitting characters that Amazon RDS disallows in a master password
(`/`, `@`, `"`, space) or that are unsafe in shell/JSON contexts (`\`, `'`, `` ` ``).
All character pools — including the four mandatory seed characters — have these
excluded characters removed.

## Recovery

See [`RUNBOOK.md`](RUNBOOK.md) for rotation-failure alerting behavior and the
procedure to restore a known-good password from the last successful
`AWSCURRENT` version.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
