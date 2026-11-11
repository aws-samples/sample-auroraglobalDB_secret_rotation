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
- Re-verifies the writer in `setSecret` (before changing anything) and in
  `testSecret`, and confirms that RDS has applied the change before the new
  value is promoted.
- Rolls the database back to the `AWSCURRENT` value if a rotation is abandoned
  after the password was changed, so the database and `AWSCURRENT` stay
  consistent (see [Validation and failure handling](#validation-and-failure-handling)).

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

The template creates the secret **empty** and does not rotate it at creation.
After the stack is deployed, seed the secret with the cluster's current master
credentials (use `file://`, never an inline password), then start the first
rotation:

```bash
aws secretsmanager put-secret-value --secret-id <SecretArn output> \
  --secret-string file:///tmp/aurora-cred.json --region us-east-1
aws secretsmanager rotate-secret --secret-id <SecretArn output> --region us-east-1
```

**Network path to the secondary Region (PCSR M12).** The Lambda security group
allows outbound HTTPS only to interface VPC endpoints, and the template creates
those endpoints in the primary Region. Interface endpoints serve only their own
Region, and cross-Region AWS PrivateLink does not support Amazon RDS. After a
failover the writer is in the secondary Region, and the function must call
`rds.<secondary-region>.amazonaws.com` (`DescribeDBClusters`,
`ModifyDBCluster`). To keep that traffic on VPC endpoints, give the Lambda's VPC
private access to an RDS interface endpoint in the secondary Region:

1. Create a `com.amazonaws.<secondary-region>.rds` interface endpoint in a VPC in
   the secondary Region.
2. Connect that VPC to the Lambda's VPC with inter-Region VPC peering or AWS
   Transit Gateway.
3. Associate a Route 53 private hosted zone for
   `rds.<secondary-region>.amazonaws.com` (an alias to that endpoint) with the
   Lambda's VPC.
4. Add an HTTPS (443) egress rule from the Lambda security group to that
   endpoint's security group or subnet CIDRs.

Without this path, the function cannot reach the writer while it is in the
secondary Region:

- A rotation that **starts** while the writer is in the secondary Region fails
  in `createSecret`, before anything changes. The database and `AWSCURRENT`
  stay consistent, and `RotationFailed` alerts.
- If a failover happens **between `setSecret` and `testSecret`**, the function
  cannot roll back on the new writer. It logs `ROLLBACK FAILED - MANUAL RECOVERY
  REQUIRED`; follow [`RUNBOOK.md`](RUNBOOK.md).

The template deploys the rotation solution only. Account-wide security
baselines — AWS CloudTrail, Amazon GuardDuty, and AWS Security Hub — are
prerequisites documented in [`docs/org-controls/`](docs/org-controls/), because
they are enabled once per account/organization.

## Configuration

- **Runtime:** Python 3.12
- **Handler:** `lambda_function.lambda_handler`
- **Timeout:** 120 seconds (minimum recommended). `testSecret` waits for RDS to
  apply the change and keeps 40 seconds in reserve for a rollback.
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
  scoped to the specific secret, cluster ARNs (both Regions), the global cluster
  ARN, and the log group. The secret ARN ends in `-??????` (in the template, it
  is the exact ARN) so it cannot match other secrets that share the name
  prefix. Passwords are generated in the function with Python's `secrets`
  module, so `secretsmanager:GetRandomPassword` is not granted.
- **Scoped trust policy** — `iam_trust_policy.json` restricts assumption with an
  `aws:SourceAccount` condition.
- **Customer managed KMS key** — the secret is encrypted with a dedicated CMK
  whose key policy limits decrypt to the execution role and the Secrets Manager
  service principal.
- **Secret resource policy** — denies `GetSecretValue`/`PutSecretValue` for all
  principals except the rotation execution role. Add the principals that must
  read the secret (applications, break-glass administrators) to this policy's
  exception list, or they cannot retrieve it.
- **VPC-bound Lambda** — runs in private subnets with egress limited to
  interface VPC endpoints for RDS, Secrets Manager, and CloudWatch Logs. For
  rotation while the writer is in the secondary Region, see
  [Network path to the secondary Region](#deploying-with-aws-sam-recommended).
- **Code signing** — enforced through AWS Signer.
- **Encrypted logs** — explicit log group with a CMK, 90-day retention, and a
  metric-filter alarm that fires if a log event ever contains a plaintext
  secret marker.
- **Alerting** — CloudWatch alarms and EventBridge rules for rotation failures,
  unexpected `ModifyDBCluster`, and unexpected `GetSecretValue`, routed to an
  SNS topic encrypted with a customer managed key whose policy allows
  `cloudwatch.amazonaws.com` and `events.amazonaws.com`. These resources exist
  only in `template.yaml`; a manual CLI deployment must create them separately.
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

## Validation and failure handling

**What `testSecret` validates.** Before the new value is promoted to
`AWSCURRENT`, `testSecret` checks that:

1. the `AWSPENDING` secret has every required field;
2. the writer cluster is still the one the new password was applied to; and
3. RDS reports that the change is applied on that writer: the cluster status is
   `available` and no master password change is pending.

This is control-plane validation. It does **not** open a database connection
or authenticate with the new password. To add that, give the function a network
path to the writer endpoint in *both* Regions (port 3306, TLS with the RDS CA
bundle), bundle a MySQL driver such as PyMySQL, and connect with the
`AWSPENDING` value inside the `try` block of `test_secret`, so a failed
connection triggers the same rollback.

**What happens if a rotation fails.** The password is changed on the cluster in
`setSecret`, before `testSecret` runs, and Aurora replicates that change to the
secondary cluster. So a rotation abandoned after `setSecret` must not simply
stop:

| Failure point | What the function does | State afterwards |
| --- | --- | --- |
| `createSecret` | Raises. | Database unchanged; `AWSCURRENT` valid. |
| `setSecret`, writer changed since `createSecret` | Re-applies `AWSCURRENT` to the current writer, clears `AWSPENDING`, raises. | Database matches `AWSCURRENT`. |
| `setSecret`, `ModifyDBCluster` error | Raises and keeps `AWSPENDING`. | Database unchanged. The retry reuses the same version. |
| `testSecret` (failover mid-rotation, or validation failed or timed out) | Re-applies `AWSCURRENT` to the current writer, clears `AWSPENDING`, raises. | Database matches `AWSCURRENT`. |
| Rollback itself fails | Logs `ROLLBACK FAILED - MANUAL RECOVERY REQUIRED` and keeps `AWSPENDING`. | Database may hold the `AWSPENDING` value; follow [`RUNBOOK.md`](RUNBOOK.md). |
| `finishSecret` | Raises. | Database holds `AWSPENDING`; the retry of `finishSecret` promotes it. |

Retries are idempotent: when Secrets Manager reattempts a rotation with the same
token, `createSecret` reuses the existing `AWSPENDING` version instead of
generating a new value (which would make `PutSecretValue` fail). After a
rollback clears `AWSPENDING`, the next scheduled or on-demand rotation starts
fresh and discovers the writer again.

## Recovery

See [`RUNBOOK.md`](RUNBOOK.md) for rotation-failure alerting behavior and the
procedure to restore a known-good password from the last successful
`AWSCURRENT` version.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
