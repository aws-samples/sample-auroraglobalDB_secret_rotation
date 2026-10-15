"""
Aurora Global Database - Failover-Aware Secrets Manager Rotation.

This AWS Lambda function rotates the master user password for an Amazon Aurora
Global Database through AWS Secrets Manager. It implements the standard
Secrets Manager four-step rotation protocol (createSecret, setSecret,
testSecret, finishSecret) with one critical addition: before each rotation it
calls the Amazon RDS DescribeGlobalClusters API to discover which cluster
currently holds the writer role, making rotation resilient to planned and
unplanned failovers.

Runtime : Python 3.12
Handler : lambda_function.lambda_handler
"""

import json
import logging
import os
import random
import re
import string
import secrets as python_secrets

import boto3

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

# Characters excluded from generated passwords. Amazon RDS for SQL Server /
# MySQL master passwords cannot contain '/', '@', '"', or a space; we also
# exclude the backslash and quotes to keep the value shell- and JSON-safe.
EXCLUDE_CHARS = '/@"\\\'`'

# Special characters allowed in generated passwords. This pool already omits
# every character in EXCLUDE_CHARS (notably '@' and '/'), so it is safe to draw
# both the mandatory seed character and the fill characters from it.
SPECIAL_CHARS = '!#$%&()*+,-.:;<=>?[]^_{|}~'


def lambda_handler(event, context):
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    logger.info(f"Rotation step: {step} | Secret: {arn} | Token: {token}")

    # Operate on the secret in the Lambda's own Region (Secrets Manager
    # replication keeps the secondary Region in sync).
    sm_client = boto3.client('secretsmanager')

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
        set_secret(sm_client, arn, token)
    elif step == "testSecret":
        test_secret(sm_client, arn, token)
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

    rds_client = boto3.client('rds')

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
    writer_rds_client = boto3.client('rds', region_name=writer_region)
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


def create_secret(sm_client, arn, token):
    logger.info("Step: createSecret - Generating new password")

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


def set_secret(sm_client, arn, token):
    logger.info("Step: setSecret - Applying new password to writer cluster")

    pending_secret = sm_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    secret_dict = json.loads(pending_secret['SecretString'])

    new_password = secret_dict['password']
    cluster_id = secret_dict['dbClusterIdentifier']
    writer_region = secret_dict['writerRegion']

    # Connect to the writer's Region to modify the cluster.
    rds_client = boto3.client('rds', region_name=writer_region)

    try:
        rds_client.modify_db_cluster(
            DBClusterIdentifier=cluster_id,
            MasterUserPassword=new_password,
            ApplyImmediately=True,
        )
        logger.info(f"setSecret: Updated password for {cluster_id} in {writer_region}")
    except Exception as e:
        logger.error(f"setSecret: Failed: {e}")
        raise


def test_secret(sm_client, arn, token):
    logger.info("Step: testSecret - Verifying new password")

    pending_secret = sm_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    secret_dict = json.loads(pending_secret['SecretString'])

    required_fields = [
        'username', 'password', 'host', 'port', 'engine',
        'dbClusterIdentifier', 'writerRegion', 'globalClusterIdentifier',
    ]
    for field in required_fields:
        if field not in secret_dict:
            raise ValueError(f"testSecret: Missing field '{field}'")

    if len(secret_dict['password']) < 8:
        raise ValueError("testSecret: Password too short")

    # Verify the writer hasn't changed mid-rotation (detect failover during rotation).
    current_writer = discover_writer_cluster()
    if current_writer['cluster_id'] != secret_dict['dbClusterIdentifier']:
        raise ValueError(
            f"testSecret: FAILOVER DETECTED during rotation! "
            f"Secret targets {secret_dict['dbClusterIdentifier']} but current writer "
            f"is {current_writer['cluster_id']}. Rotation will be retried."
        )

    logger.info(
        f"testSecret: Passed. Writer confirmed: {secret_dict['dbClusterIdentifier']} "
        f"in {secret_dict['writerRegion']}"
    )

    # To add an actual DB connectivity test, add a pymysql layer and use:
    # import pymysql
    # conn = pymysql.connect(
    #     host=secret_dict['host'],
    #     user=secret_dict['username'],
    #     password=secret_dict['password'],
    #     port=int(secret_dict['port']),
    #     connect_timeout=5,
    # )
    # conn.close()


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
    password = [
        python_secrets.choice(uppers),
        python_secrets.choice(lowers),
        python_secrets.choice(digits),
        python_secrets.choice(specials),
    ]
    password += [python_secrets.choice(all_chars) for _ in range(length - 4)]

    random.SystemRandom().shuffle(password)
    return ''.join(password)
