# Runbook: Aurora global database rotation failures

Sample content, non-production. Adapt to your operational tooling and
organizational procedures before relying on it.

## Alerting

`template.yaml` wires two failure signals to the `aurora-rotation-alerts` SNS
topic (subscribed by the `OnCallEmail` address):

- **`RotationErrorAlarm`** — CloudWatch alarm on the Lambda `Errors` metric.
- **`RotationFailedRule`** — EventBridge rule on Secrets Manager
  `RotationFailed` events.

Two security-signal rules publish to the same topic:
`UnexpectedModifyDBClusterRule` (M19) and `UnexpectedSecretAccessRule` (M16).

## Triage

1. Open the CloudWatch log group `/aws/lambda/aurora-master-password-rotation`
   and read the most recent rotation step (`createSecret`, `setSecret`,
   `testSecret`, `finishSecret`).
2. Common causes:
   - **`testSecret: FAILOVER DETECTED`** — a failover occurred mid-rotation.
     This is expected-safe: the current password (`AWSCURRENT`) is untouched.
     The next scheduled rotation discovers the new writer and completes. To
     rotate sooner, trigger an on-demand rotation once the failover settles:
     `aws secretsmanager rotate-secret --secret-id aurora-global-master-cred --region us-east-1`
   - **`EnvironmentError: GLOBAL_CLUSTER_ID ...`** — the function's
     `GLOBAL_CLUSTER_ID` env var is unset or malformed. Fix the configuration
     (via the pipeline) and redeploy.
   - **`ModifyDBCluster` AccessDenied** — verify the execution role policy and
     that the writer is one of the two permitted cluster ARNs.

## Restoring a known-good password

If a rotation left the database and secret out of sync (for example, the
password was changed on the cluster but `finishSecret` did not promote the new
version), restore the last successful `AWSCURRENT` value:

1. List the secret's versions and stages:
   ```
   aws secretsmanager list-secret-version-ids \
     --secret-id aurora-global-master-cred --region us-east-1
   ```
2. Identify the version currently staged `AWSCURRENT` (the last known-good
   password). Retrieve it **without printing it to the terminal** — write it to
   a restricted temp file if you must inspect it.
3. Re-apply that password to the current writer cluster (discover the writer
   first with `describe-global-clusters`):
   ```
   aws rds modify-db-cluster \
     --db-cluster-identifier <current-writer-cluster-id> \
     --master-user-password file:///dev/stdin \
     --apply-immediately --region <writer-region>
   ```
   Supply the password via `file://` or stdin, never inline.
4. If a stale `AWSPENDING` version is stuck, remove that staging label so the
   next rotation starts clean:
   ```
   aws secretsmanager update-secret-version-stage \
     --secret-id aurora-global-master-cred \
     --version-stage AWSPENDING \
     --remove-from-version-id <stuck-pending-version-id> \
     --region us-east-1
   ```
5. Confirm connectivity with the restored `AWSCURRENT` password, then re-enable
   / re-trigger rotation.
