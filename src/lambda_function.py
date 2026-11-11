"""
Aurora Global Database - Failover-Aware Secrets Manager Rotation.

This AWS Lambda function rotates the master user password for an Amazon Aurora
Global Database through AWS Secrets Manager. It implements the standard
Secrets Manager four-step rotation protocol (createSecret, setSecret,
testSecret, finishSecret) with one critical addition: before each rotation it
calls the Amazon RDS DescribeGlobalClusters API to discover which cluster
currently holds the writer role, making rotation resilient to planned and
unplanned failovers.

Failure handling
----------------
The master password is changed on the cluster in setSecret, before testSecret
runs. If the rotation is abandoned after that point, the database would hold
the AWSPENDING value while AWSCURRENT still holds the previous one. To keep the
database and AWSCURRENT consistent, any failure that abandons the rotation
(a writer change detected in setSecret or testSecret, or a failed validation)
triggers a rollback:

  1. Re-apply the AWSCURRENT credential to the *current* writer cluster.
  2. Remove the AWSPENDING staging label from this rotation's version, so the
     next rotation starts from a clean state and discovers the writer again.
  3. Raise, so Secrets Manager records the rotation as failed (RotationFailed).

If the rollback itself fails, AWSPENDING is left in place (it may hold the value
the database now uses) and the function logs MANUAL RECOVERY REQUIRED. Follow
RUNBOOK.md in that case.

Log hygiene: the deployment template alarms on any log event that contains the
term "password" (a plaintext-leak tripwire). Log and exception messages in this
module therefore say "credential" and never include secret values.

Runtime : Python 3.12
Handler : lambda_function.lambda_handler
"""

import json
import logging
import os
import re
import string
import time
import secrets as python_secrets

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Global cluster identifier is supplied entirely by configuration; there is no
# default. A missing or malformed value is a deployment error and must fail
# closed at module load rather than silently rotating the wrong cluster.
# Pattern matches the RDS global cluster identifier constraints: start with a
# letter, then letters/digits/hyphens, 2-63 characters total.
_GLOBAL_CLUSTER_ID_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9-]{1,62}$')


def _load_global_cluster_id():
    """Read and validate GLOBAL_CLUSTER_ID from the environment at import time.

    Raises:
        EnvironmentError: if the variable is unset/empty or does not match the
            expected RDS global cluster identifier pattern.
    """
    value = os.environ.get('GLOBAL_CLUSTER_ID', '').strip()
    if not value:
        raise EnvironmentError(
            'GLOBAL_CLUSTER_ID environment variable is required and was not set'
        )
    if not _GLOBAL_CLUSTER_ID_PATTERN.match(value):
        raise EnvironmentError(
            f'GLOBAL_CLUSTER_ID {value!r} is not a valid global cluster '
            f'identifier (expected pattern ^[a-zA-Z][a-zA-Z0-9-]{{1,62}}$)'
        )
    return value


GLOBAL_CLUSTER_ID = _load_global_cluster_id()

# Characters excluded from generated passwords. Amazon Aurora MySQL master
# passwords cannot contain '/', '@', '"', or a space; we also exclude the
# backslash and quotes to keep the value shell- and JSON-safe.
EXCLUDE_CHARS = '/@"\\\'`'

# Special characters allowed in generated passwords. This pool already omits
# every character in EXCLUDE_CHARS (notably '@' and '/'), so it is safe to draw
# both the mandatory seed character and the fill characters from it.
SPECIAL_CHARS = '!#$%&()*+,-.:;<=>?[]^_{|}~'

# Fail fast on unreachable endpoints (for example, a VPC without a network path
# to the secondary Region's RDS API) instead of consuming the whole Lambda
# timeout on the default 60-second connect timeout.
_AWS_CONFIG = Config(
    connect_timeout=5,
    read_timeout=15,
    retries={'max_attempts': 3, 'mode': 'standard'},
)

# testSecret waits for RDS to finish applying the credential change. Keep this
# many seconds of the invocation in reserve so a rollback can still run if the
# wait times out. Use a Lambda timeout of at least 120 seconds.
ROLLBACK_RESERVE_SECONDS = 40
POLL_INTERVAL_SECONDS = 5
# Used only when no Lambda context is available (for example, local tests).
DEFAULT_TIME_BUDGET_SECONDS = 60


class RotationAbortedError(Exception):
    """The rotation was abandoned; see the message for whether it was rolled back."""


def _client(service, region=None):
    return boto3.client(service, region_name=region, config=_AWS_CONFIG)


def lambda_handler(event, context):
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    logger.info(f"Rotation step: {step} | Secret: {arn} | Token: {token}")

    # Operate on the secret in the Lambda's own Region (Secrets Manager
    # replication keeps the secondary Region in sync).
    sm_client = _client('secretsmanager')

    metadata = sm_client.describe_secret(SecretId=arn)
    if not metadata.get('RotationEnabled'):
        raise ValueError(f"Secret {arn} is not enabled for rotation")

    versions = metadata.get('VersionIdsToStages', {})
    if token not in versions:
        raise ValueError(f"Secret version {token} has no stage for rotation")

    if "AWSCURRENT" in versions[token]:
        logger.info(f"Secret version {token} already set as AWSCURRENT. Skipping.")
        return
    elif "AWSPENDING" not in versions[token]:
        raise ValueError(f"Secret version {token} not set as AWSPENDING")

    if step == "createSecret":
        create_secret(sm_client, arn, token)
    elif step == "setSecret":
        set_secret(sm_client, arn, token, context)
    elif step == "testSecret":
        test_secret(sm_client, arn, token, context)
    elif step == "finishSecret":
        finish_secret(sm_client, arn, token)
    else:
        raise ValueError(f"Invalid step parameter: {step}")


def discover_writer_cluster():
    """
    Dynamically discover the current writer cluster in the Aurora Global
    Database. Makes rotation failover-aware - always targets the current
    primary regardless of Region.
    """
    logger.info(f"Discovering current writer for global cluster: {GLOBAL_CLUSTER_ID}")

    rds_client = _client('rds')

    response = rds_client.describe_global_clusters(GlobalClusterIdentifier=GLOBAL_CLUSTER_ID)

    global_clusters = response.get('GlobalClusters', [])
    if not global_clusters:
        raise ValueError(f"Global cluster {GLOBAL_CLUSTER_ID} not found")

    members = global_clusters[0].get('GlobalClusterMembers', [])

    writer_member = None
    for member in members:
        if member.get('IsWriter', False):
            writer_member = member
            break

    if not writer_member:
        raise ValueError(f"No writer found in global cluster {GLOBAL_CLUSTER_ID}")

    # Extract Region and cluster ID from the ARN.
    # ARN format: arn:aws:rds:<region>:<account>:cluster:<cluster-id>
    writer_arn = writer_member['DBClusterArn']
    arn_parts = writer_arn.split(':')
    writer_region = arn_parts[3]
    writer_cluster_id = arn_parts[6]

    logger.info(f"Writer discovered: {writer_cluster_id} in {writer_region}")

    # Get the endpoint from the writer's Region.
    writer_rds_client = _client('rds', writer_region)
    cluster_response = writer_rds_client.describe_db_clusters(DBClusterIdentifier=writer_cluster_id)
    cluster_info = cluster_response['DBClusters'][0]

    return {
        'cluster_arn': writer_arn,
        'cluster_id': writer_cluster_id,
        'region': writer_region,
        'endpoint': cluster_info['Endpoint'],
        'reader_endpoint': cluster_info['ReaderEndpoint'],
        'port': cluster_info['Port'],
    }


def _get_pending(sm_client, arn, token):
    response = sm_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    return json.loads(response['SecretString'])


def create_secret(sm_client, arn, token):
    logger.info("Step: createSecret - Generating new credential")

    # Idempotency: Secrets Manager reattempts an incomplete rotation with the
    # same ClientRequestToken. A version's value is immutable, so generating a
    # new value for an existing token would make PutSecretValue fail. Reuse the
    # AWSPENDING version that already exists for this token instead; setSecret
    # re-checks the writer before it changes anything.
    try:
        _get_pending(sm_client, arn, token)
        logger.info("createSecret: AWSPENDING version already exists for this token. Reusing it.")
        return
    except sm_client.exceptions.ResourceNotFoundException:
        pass

    current_secret = sm_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
    secret_dict = json.loads(current_secret['SecretString'])

    # Discover current writer - key failover-aware step.
    writer_info = discover_writer_cluster()

    new_password = generate_password(30)

    # Update secret with new password AND current writer info.
    secret_dict['password'] = new_password
    secret_dict['host'] = writer_info['endpoint']
    secret_dict['port'] = writer_info['port']
    secret_dict['dbClusterIdentifier'] = writer_info['cluster_id']
    secret_dict['writerRegion'] = writer_info['region']
    secret_dict['globalClusterIdentifier'] = GLOBAL_CLUSTER_ID

    sm_client.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(secret_dict),
        VersionStages=['AWSPENDING'],
    )

    logger.info(
        f"createSecret: Done. Writer: {writer_info['cluster_id']} in {writer_info['region']}"
    )


def set_secret(sm_client, arn, token, context=None):
    logger.info("Step: setSecret - Applying new credential to writer cluster")

    deadline = _deadline(context)
    secret_dict = _get_pending(sm_client, arn, token)
    cluster_id = secret_dict['dbClusterIdentifier']
    writer_region = secret_dict['writerRegion']

    # Check the writer BEFORE changing anything. If it moved since createSecret
    # (or since an earlier attempt of this same rotation), abandon the rotation.
    # The rollback is a no-op in effect when nothing was applied yet, and it
    # restores consistency if an earlier attempt already applied the change.
    current_writer = discover_writer_cluster()
    if current_writer['cluster_id'] != cluster_id:
        _abort_rotation(
            sm_client, arn, token,
            f"setSecret: FAILOVER DETECTED. AWSPENDING targets {cluster_id} but the "
            f"current writer is {current_writer['cluster_id']}.",
            deadline,
        )

    rds_client = _client('rds', writer_region)
    try:
        rds_client.modify_db_cluster(
            DBClusterIdentifier=cluster_id,
            MasterUserPassword=secret_dict['password'],
            ApplyImmediately=True,
        )
    except ClientError as e:
        # Nothing was applied. Leave AWSPENDING in place so the reattempt
        # (same token) can complete the rotation.
        logger.error(
            f"setSecret: ModifyDBCluster failed for {cluster_id} in {writer_region}: "
            f"{e.response.get('Error', {}).get('Code')}"
        )
        raise
    logger.info(f"setSecret: Credential change submitted for {cluster_id} in {writer_region}")


def test_secret(sm_client, arn, token, context=None):
    logger.info("Step: testSecret - Validating new credential")

    deadline = _deadline(context)
    secret_dict = _get_pending(sm_client, arn, token)

    try:
        _validate_secret_fields(secret_dict)

        # Verify the writer hasn't changed mid-rotation (failover during rotation).
        current_writer = discover_writer_cluster()
        if current_writer['cluster_id'] != secret_dict['dbClusterIdentifier']:
            raise RotationAbortedError(
                f"FAILOVER DETECTED. AWSPENDING targets {secret_dict['dbClusterIdentifier']} "
                f"but the current writer is {current_writer['cluster_id']}."
            )

        # Confirm that RDS finished applying the change on the writer: the
        # cluster is available and no master credential change is pending.
        # This is control-plane validation; it does not open a DB connection.
        _wait_for_credential_change_applied(
            secret_dict['dbClusterIdentifier'],
            secret_dict['writerRegion'],
            deadline - ROLLBACK_RESERVE_SECONDS,
        )
    except Exception as e:  # noqa: BLE001 - any failure here must roll back
        _abort_rotation(sm_client, arn, token, f"testSecret: {e}", deadline)

    logger.info(
        f"testSecret: Passed. Writer confirmed and credential change applied: "
        f"{secret_dict['dbClusterIdentifier']} in {secret_dict['writerRegion']}"
    )


def finish_secret(sm_client, arn, token):
    logger.info("Step: finishSecret - Promoting AWSPENDING to AWSCURRENT")

    metadata = sm_client.describe_secret(SecretId=arn)
    current_version = None

    for version_id, stages in metadata['VersionIdsToStages'].items():
        if 'AWSCURRENT' in stages:
            if version_id == token:
                logger.info("finishSecret: Already AWSCURRENT")
                return
            current_version = version_id
            break

    sm_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage='AWSCURRENT',
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )

    logger.info(f"finishSecret: Rotated. New AWSCURRENT: {token}")


# ---------------------------------------------------------------------------
# Validation and rollback helpers
# ---------------------------------------------------------------------------

def _deadline(context):
    """Monotonic time by which this invocation must be finished."""
    if context is not None and hasattr(context, 'get_remaining_time_in_millis'):
        remaining = context.get_remaining_time_in_millis() / 1000.0
    else:
        remaining = DEFAULT_TIME_BUDGET_SECONDS
    return time.monotonic() + remaining


def _validate_secret_fields(secret_dict):
    required_fields = [
        'username', 'password', 'host', 'port', 'engine',
        'dbClusterIdentifier', 'writerRegion', 'globalClusterIdentifier',
    ]
    missing = [f for f in required_fields if f not in secret_dict]
    if missing:
        raise ValueError(f"AWSPENDING is missing {len(missing)} required field(s)")
    if len(secret_dict['password']) < 8:
        raise ValueError("generated credential is shorter than 8 characters")


def _describe_cluster(rds_client, cluster_id):
    return rds_client.describe_db_clusters(DBClusterIdentifier=cluster_id)['DBClusters'][0]


def _wait_for_credential_change_applied(cluster_id, region, deadline):
    """Wait until the cluster is available with no pending master credential change.

    ModifyDBCluster records the change in PendingModifiedValues and moves the
    cluster through 'resetting-master-credentials'. When both have cleared,
    RDS has applied the new master credential.
    """
    rds_client = _client('rds', region)
    while True:
        cluster = _describe_cluster(rds_client, cluster_id)
        status = cluster.get('Status')
        change_pending = 'MasterUserPassword' in (cluster.get('PendingModifiedValues') or {})
        if status == 'available' and not change_pending:
            logger.info(f"testSecret: RDS reports the credential change applied on {cluster_id}")
            return
        if time.monotonic() + POLL_INTERVAL_SECONDS > deadline:
            raise RotationAbortedError(
                f"timed out waiting for RDS to apply the credential change on {cluster_id} "
                f"(status={status}, change_pending={change_pending})"
            )
        time.sleep(POLL_INTERVAL_SECONDS)


def _modify_when_ready(rds_client, cluster_id, value, deadline):
    """ModifyDBCluster, retrying while the cluster is busy (for example, still
    applying the change being rolled back, or settling after a failover)."""
    while True:
        try:
            rds_client.modify_db_cluster(
                DBClusterIdentifier=cluster_id,
                MasterUserPassword=value,
                ApplyImmediately=True,
            )
            return
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code != 'InvalidDBClusterStateFault' or time.monotonic() + POLL_INTERVAL_SECONDS > deadline:
                raise
            logger.info(f"Rollback: {cluster_id} is busy ({code}); retrying")
            time.sleep(POLL_INTERVAL_SECONDS)


def _abort_rotation(sm_client, arn, token, reason, deadline=None):
    """Roll the database back to AWSCURRENT, clear AWSPENDING, then raise."""
    if deadline is None:
        deadline = time.monotonic() + DEFAULT_TIME_BUDGET_SECONDS
    logger.error(
        f"{reason} Rolling back: re-applying the AWSCURRENT credential to the "
        f"current writer and clearing AWSPENDING."
    )
    try:
        current = json.loads(
            sm_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")['SecretString']
        )
        writer = discover_writer_cluster()
        _modify_when_ready(
            _client('rds', writer['region']), writer['cluster_id'], current['password'], deadline
        )
        logger.info(
            f"Rollback: AWSCURRENT credential re-applied to {writer['cluster_id']} "
            f"in {writer['region']}"
        )
    except Exception:  # noqa: BLE001
        # Keep AWSPENDING: it may hold the value the database now uses.
        logger.exception(
            "ROLLBACK FAILED - MANUAL RECOVERY REQUIRED. AWSPENDING was left in place. "
            "Follow 'Restoring a known-good credential' in RUNBOOK.md."
        )
        raise RotationAbortedError(f"{reason} Rollback failed; manual recovery required.")

    sm_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage='AWSPENDING',
        RemoveFromVersionId=token,
    )
    logger.info("Rollback: AWSPENDING cleared. The next rotation starts fresh.")
    raise RotationAbortedError(f"{reason} Rolled back to AWSCURRENT; AWSPENDING cleared.")


def generate_password(length=30, exclude_chars=EXCLUDE_CHARS):
    """
    Generate a random password of the given length.

    Guarantees at least one uppercase letter, one lowercase letter, one digit,
    and one special character, while never emitting any character listed in
    exclude_chars. All character pools (including the four mandatory seed
    characters) have exclude_chars removed, so RDS-forbidden characters such as
    '@' and '/' can never appear.
    """
    excluded = set(exclude_chars)

    def pool(source):
        return ''.join(c for c in source if c not in excluded)

    uppers = pool(string.ascii_uppercase)
    lowers = pool(string.ascii_lowercase)
    digits = pool(string.digits)
    specials = pool(SPECIAL_CHARS)
    all_chars = uppers + lowers + digits + specials

    if not (uppers and lowers and digits and specials):
        raise ValueError("exclude_chars removes an entire required character class")

    # Seed one mandatory character from each class (all exclusion-aware).
    chars = [
        python_secrets.choice(uppers),
        python_secrets.choice(lowers),
        python_secrets.choice(digits),
        python_secrets.choice(specials),
    ]
    chars += [python_secrets.choice(all_chars) for _ in range(length - 4)]

    python_secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)
