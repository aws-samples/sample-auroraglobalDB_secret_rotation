# Runbook: Aurora global database rotation failures

Sample content, non-production. Adapt to your operational tooling and
organizational procedures before relying on it.

## Alerting

`template.yaml` wires two failure signals to the `aurora-rotation-alerts` SNS
topic (subscribed by the `OnCallEmail` address):

- **`RotationErrorAlarm`** — CloudWatch alarm on the Lambda `Errors` metric.
- **`RotationFailedRule`** — EventBridge rule on Secrets Manager
  `RotationFailed` events.

The topic is encrypted with a customer managed key whose policy allows
CloudWatch and EventBridge to use it. The dead-letter queue
`aurora-rotation-dlq` receives only failed *asynchronous* invocations, so treat
it as a secondary signal.

Two security-signal rules publish to the same topic:
`UnexpectedModifyDBClusterRule` (M19) and `UnexpectedSecretAccessRule` (M16).

These resources exist only in `template.yaml`. If you deployed with the AWS CLI
steps instead, create equivalent alerting before relying on this runbook.

## Triage

1. Open the CloudWatch log group `/aws/lambda/aurora-master-password-rotation`
   and read the most recent rotation step (`createSecret`, `setSecret`,
   `testSecret`, `finishSecret`).
2. Find out whether the function rolled back. Search the log for `Rollback:`.
   - **`Rollback: AWSPENDING cleared`** — the function re-applied the
     `AWSCURRENT` value to the current writer and removed `AWSPENDING`. The
     database and `AWSCURRENT` are consistent, and the next scheduled rotation
     starts fresh. To rotate sooner, wait for the cluster to be `available`, then
     run:
     `aws secretsmanager rotate-secret --secret-id aurora-global-master-cred --region us-east-1`
   - **`ROLLBACK FAILED - MANUAL RECOVERY REQUIRED`** — the database may hold the
     `AWSPENDING` value while `AWSCURRENT` holds the previous one. Go to
     [Restoring a known-good credential](#restoring-a-known-good-credential).
3. Common causes:
   - **`FAILOVER DETECTED`** (in `setSecret` or `testSecret`) — the writer moved
     during the rotation. The function rolls back automatically; check step 2.
   - **`timed out waiting for RDS to apply the credential change`** — the
     cluster did not return to `available` within the function's time budget.
     The function rolls back. If this repeats, raise the Lambda timeout (120
     seconds minimum).
   - **`setSecret: ModifyDBCluster failed`** — nothing was changed on the
     database, and `AWSPENDING` is kept so the reattempt can finish. For
     `AccessDenied`, verify the execution role policy, the permissions boundary,
     and that the writer is one of the two permitted cluster ARNs.
   - **Connect timeout to `rds.<secondary-region>.amazonaws.com`** — the writer is
     in the secondary Region and the function has no private path to that
     Region's RDS API. Set up the secondary-Region RDS endpoint path described
     in README.md ("Network path to the secondary Region"). Do not open
     internet egress; the security group must stay limited to VPC endpoints
     (PCSR M12).
   - **`EnvironmentError: GLOBAL_CLUSTER_ID ...`** — the function's
     `GLOBAL_CLUSTER_ID` env var is unset or malformed. Fix the configuration
     (via the pipeline) and redeploy.
   - **`finishSecret` failed** — the database already holds the `AWSPENDING`
     value. The reattempt promotes it. If it keeps failing, follow
     [Restoring a known-good credential](#restoring-a-known-good-credential).
4. **An on-demand `rotate-secret` returns an error about a rotation in
   progress** — `AWSPENDING` is still attached to an earlier version. Do not
   just clear it: first confirm which value the database accepts (see below),
   then remove the stale `AWSPENDING` label and run `rotate-secret` again.

## Restoring a known-good credential

Use this when a rotation left the database and the secret out of sync, for
example after `ROLLBACK FAILED - MANUAL RECOVERY REQUIRED`.

1. List the secret's versions and stages:
   ```
   aws secretsmanager list-secret-version-ids \
     --secret-id aurora-global-master-cred --region us-east-1
   ```
2. Note the version staged `AWSCURRENT` and, if present, the version staged
   `AWSPENDING`. Either one may be the value the database now accepts. Retrieve
   values **without printing them to the terminal**; write them to a restricted
   temp file if you must inspect them.
3. Find the current writer:
   ```
   aws rds describe-global-clusters \
     --global-cluster-identifier aurora-global-test-cluster \
     --query 'GlobalClusters[0].GlobalClusterMembers[?IsWriter].DBClusterArn'
   ```
4. Make the database match `AWSCURRENT` by re-applying that value to the
   writer:
   ```
   aws rds modify-db-cluster \
     --db-cluster-identifier <current-writer-cluster-id> \
     --master-user-password file:///dev/stdin \
     --apply-immediately --region <writer-region>
   ```
   Supply the value via `file://` or stdin, never inline. Wait until the cluster
   status returns to `available`.
5. Remove the stale `AWSPENDING` label so the next rotation can start:
   ```
   aws secretsmanager update-secret-version-stage \
     --secret-id aurora-global-master-cred \
     --version-stage AWSPENDING \
     --remove-from-version-id <stuck-pending-version-id> \
     --region us-east-1
   ```
6. Confirm connectivity with the `AWSCURRENT` value, then trigger rotation
   again with `aws secretsmanager rotate-secret`.
