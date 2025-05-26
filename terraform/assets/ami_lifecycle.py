import boto3
import json
import time
import logging
import os
from datetime import datetime, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PROTECTION_TAG_KEY = os.environ.get('AMI_PROTECTION_TAG', 'do_not_delete')

def lambda_handler(event, context):
    """
    Main Lambda function to clean up unused AMIs
    """
    ec2_client = boto3.client('ec2')
    athena_client = boto3.client('athena')
    s3_client = boto3.client('s3')
    rbin_client = boto3.client('rbin')
    
    database = os.environ.get('ATHENA_DATABASE')
    table = os.environ.get('ATHENA_TABLE')
    s3_output_bucket = os.environ.get('ATHENA_RESULTS_BUCKET')
    s3_output_prefix = 'ami-analysis/results/'
    
    if not all([database, table, s3_output_bucket]):
        raise ValueError("Missing required environment variables. Please set ATHENA_DATABASE, ATHENA_TABLE, and ATHENA_RESULTS_BUCKET")
    
    retention_period_days = 90  
    thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y%m%d')
    
    try:
        used_amis = query_used_amis(athena_client, database, table, s3_output_bucket, s3_output_prefix)
        
        owned_amis = get_owned_amis(ec2_client)
        
        unused_amis = find_unused_amis(owned_amis, used_amis, thirty_days_ago)
        
        ami_report = check_ami_sharing(ec2_client, unused_amis)
        
        ami_report = check_instance_usage(ec2_client, ami_report)
        
        cleanup_report = implement_cleanup_policy(
            ec2_client, 
            rbin_client,
            ami_report, 
            retention_period_days
        )
        
        report = generate_report(ami_report, cleanup_report)
        
        store_report_in_s3(s3_client, s3_output_bucket, s3_output_prefix + 'unused_ami_report.json', report)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully analyzed AMI usage. Found {len(unused_amis)} unused AMIs.',
                'moved_to_recycle_bin': cleanup_report['moved_to_recycle_bin_count'],
                'report_location': f's3://{s3_output_bucket}/{s3_output_prefix}unused_ami_report.json'
            })
        }
    
    except Exception as e:
        logger.error(f"Error in AMI analysis: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': f'Error analyzing AMI usage: {str(e)}'
            })
        }

def query_used_amis(athena_client, database, table, s3_output_bucket, s3_prefix):
    """
    Query Athena to find AMIs used in RunInstances events
    """
    query = f"""
    WITH used_ami_events AS (
        SELECT DISTINCT
            json_extract_scalar(requestparameters, '$.instancesSet.items[0].imageId') AS ami_id,
            eventtime
        FROM
            {database}.{table}
        WHERE
            eventname = 'RunInstances'
            AND json_extract_scalar(requestparameters, '$.instancesSet.items[0].imageId') IS NOT NULL
        
        UNION ALL
        
        SELECT DISTINCT
            json_extract_scalar(requestparameters, '$.instancesSet.items[1].imageId') AS ami_id,
            eventtime
        FROM
            {database}.{table}
        WHERE
            eventname = 'RunInstances'
            AND json_extract_scalar(requestparameters, '$.instancesSet.items[1].imageId') IS NOT NULL
    )
    
    SELECT 
        ami_id, 
        max(eventtime) as last_used
    FROM 
        used_ami_events
    WHERE 
        ami_id IS NOT NULL
    GROUP BY 
        ami_id
    ORDER BY 
        ami_id
    """
    
    query_execution = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': database},
        ResultConfiguration={'OutputLocation': f's3://{s3_output_bucket}/{s3_prefix}query-results/'}
    )
    
    query_execution_id = query_execution['QueryExecutionId']
    logger.info(f"Started Athena query with execution ID: {query_execution_id}")
    
    state = 'RUNNING'
    max_attempts = 60
    attempts = 0
    
    while state in ['RUNNING', 'QUEUED'] and attempts < max_attempts:
        attempts += 1
        response = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        state = response['QueryExecution']['Status']['State']
        
        if state in ['RUNNING', 'QUEUED']:
            time.sleep(10)
    
    if state != 'SUCCEEDED':
        error_message = response['QueryExecution']['Status'].get('StateChangeReason', 'Unknown error')
        raise Exception(f"Athena query failed with state {state}: {error_message}")
    
    results = athena_client.get_query_results(QueryExecutionId=query_execution_id)
    
    used_amis = {}
    
    for row in results['ResultSet']['Rows'][1:]:
        if len(row['Data']) >= 2:
            ami_id = row['Data'][0].get('VarCharValue')
            last_used = row['Data'][1].get('VarCharValue')
            
            if ami_id:
                used_amis[ami_id] = last_used
    
    logger.info(f"Found {len(used_amis)} unique AMIs used in CloudTrail logs")
    return used_amis

def get_owned_amis(ec2_client):
    """
    Get all AMIs owned by the current account
    """
    owned_amis = []
    paginator = ec2_client.get_paginator('describe_images')
    
    for page in paginator.paginate(Owners=['self']):
        for image in page['Images']:
            owned_amis.append({
                'ImageId': image['ImageId'],
                'Name': image.get('Name', 'N/A'),
                'CreationDate': image.get('CreationDate', 'N/A'),
                'Description': image.get('Description', 'N/A')
            })
    
    logger.info(f"Found {len(owned_amis)} AMIs owned by this account")
    return owned_amis

def find_unused_amis(owned_amis, used_amis_with_dates, thirty_days_ago):
    """
    Compare owned AMIs with used AMIs to find AMIs:
    - Not used in the last 30 days
    - Older than 30 days
    """
    unused_amis = []
    protected_new_amis = []
    
    for ami in owned_amis:
        ami_id = ami['ImageId']
        
        try:
            creation_date = datetime.strptime(ami['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        except (ValueError, TypeError):
            try:
                creation_date = datetime.strptime(ami['CreationDate'], '%Y-%m-%dT%H:%M:%SZ')
            except (ValueError, TypeError):
                logger.warning(f"Could not parse creation date for AMI {ami_id}")
                continue
        
        if creation_date > (datetime.now() - timedelta(days=30)):
            logger.info(f"Skipping new AMI {ami_id} created {creation_date}")
            protected_new_amis.append(ami)
            continue
        
        if ami_id not in used_amis_with_dates:
            unused_amis.append(ami)
        else:
            last_used_str = used_amis_with_dates[ami_id]
            try:
                last_used_date = None
                for date_format in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%fZ']:
                    try:
                        last_used_date = datetime.strptime(last_used_str, date_format)
                        break
                    except ValueError:
                        continue
                
                if not last_used_date:
                    continue
                    
                if last_used_date.strftime('%Y%m%d') <= thirty_days_ago:
                    unused_amis.append(ami)
            
            except Exception as e:
                logger.warning(f"Error parsing date {last_used_str} for AMI {ami_id}: {e}")
    
    logger.info(f"Found {len(unused_amis)} AMIs older than 30 days and unused")
    logger.info(f"Protected {len(protected_new_amis)} new AMIs less than 30 days old")
    
    return unused_amis

def check_ami_sharing(ec2_client, unused_amis):
    """
    Check if unused AMIs are shared with other accounts
    """
    ami_report = []
    
    for ami in unused_amis:
        try:
            sharing_info = ec2_client.describe_image_attribute(
                ImageId=ami['ImageId'],
                Attribute='launchPermission'
            )
            
            shared_accounts = []
            if 'LaunchPermissions' in sharing_info:
                for permission in sharing_info['LaunchPermissions']:
                    if 'UserId' in permission:
                        shared_accounts.append(permission['UserId'])
            
            if shared_accounts:
                risk_level = "SHARED"
            else:
                risk_level = "NOT_SHARED"
            
            snapshots = get_ami_snapshots(ec2_client, ami['ImageId'])
            
            ami_report.append({
                'ImageId': ami['ImageId'],
                'Name': ami['Name'],
                'CreationDate': ami['CreationDate'],
                'Description': ami['Description'],
                'SharedWithAccounts': shared_accounts,
                'IsShared': len(shared_accounts) > 0,
                'RiskLevel': risk_level,
                'Snapshots': snapshots
            })
            
        except Exception as e:
            logger.error(f"Error checking sharing for AMI {ami['ImageId']}: {e}")
            ami_report.append({
                'ImageId': ami['ImageId'],
                'Name': ami['Name'],
                'CreationDate': ami['CreationDate'],
                'Description': ami['Description'],
                'SharedWithAccounts': [],
                'IsShared': False,
                'RiskLevel': "ERROR_CHECKING",
                'Snapshots': [],
                'Error': str(e)
            })
    
    return ami_report

def check_instance_usage(ec2_client, ami_report):
    """
    Check if AMIs are currently used by running instances
    """
    running_amis = set()
    paginator = ec2_client.get_paginator('describe_instances')
    
    try:
        for page in paginator.paginate(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'pending', 'stopping']}
            ]):
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    if 'ImageId' in instance:
                        running_amis.add(instance['ImageId'])
    except Exception as e:
        logger.warning(f"Error getting running instances: {str(e)}")
    
    for ami in ami_report:
        ami['InUseByInstance'] = ami['ImageId'] in running_amis
    
    return ami_report

def check_ami_protected_status(ec2_client, image_id):
    """
    Check if the AMI has a tag indicating it should not be deleted
    """
    try:
        image_info = ec2_client.describe_images(
            ImageIds=[image_id],
            Owners=['self']
        )
        
        if not image_info['Images']:
            return False
        
        tags = image_info['Images'][0].get('Tags', [])
        
        for tag in tags:
            if tag.get('Key', '').lower() == PROTECTION_TAG_KEY.lower():
                return True
        
        return False
    
    except Exception as e:
        logger.error(f"Error checking protection status for AMI {image_id}: {e}")
        return False

def get_ami_snapshots(ec2_client, image_id):
    """
    Get snapshots associated with an AMI
    """
    try:
        image_info = ec2_client.describe_images(ImageIds=[image_id])
        
        if not image_info['Images']:
            return []
        
        snapshot_ids = []
        for bdm in image_info['Images'][0].get('BlockDeviceMappings', []):
            if 'Ebs' in bdm and 'SnapshotId' in bdm['Ebs']:
                snapshot_ids.append(bdm['Ebs']['SnapshotId'])
        
        return snapshot_ids
    
    except Exception as e:
        logger.error(f"Error getting snapshots for AMI {image_id}: {e}")
        return []

def implement_cleanup_policy(ec2_client, rbin_client, ami_report, retention_period_days):
    """
    Implement AMI cleanup policy:
    - Move AMIs and associated snapshots to Recycle Bin
    """
    cleanup_report = {
        'moved_to_recycle_bin': [],
        'protected_amis': [],
        'errors': [],
        'moved_to_recycle_bin_count': 0,
        'snapshots_moved_to_recycle_bin_count': 0,
        'protected_amis_count': 0,
        'error_count': 0
    }
    

    for ami in ami_report:
        try:
            image_id = ami['ImageId']
            
            if check_ami_protected_status(ec2_client, image_id):
                logger.info(f"Skipping protected AMI {image_id}")
                cleanup_report['protected_amis'].append({
                    'ImageId': image_id,
                    'Name': ami.get('Name', 'N/A')
                })
                cleanup_report['protected_amis_count'] += 1
                continue
            
            if ami.get('InUseByInstance', False):
                logger.info(f"Skipping AMI {image_id} as it's in use by running instances")
                continue
            
            snapshot_ids = ami.get('Snapshots', [])
            is_shared = ami.get('IsShared', False)
            
            ec2_client.create_tags(
                Resources=[image_id],
                Tags=[
                    {'Key': 'aws:recycle-bin:resource-in-bin', 'Value': 'true'},
                    {'Key': 'ParentAMI:Shared', 'Value': str(is_shared)},
                    {'Key': 'RecycleBinDate', 'Value': datetime.now().strftime('%Y-%m-%d')}
                ]
            )
            
            rbin_client.put_retention_rule(
                ResourceType='AMI',
                RetentionPeriod={
                    'RetentionPeriodValue': retention_period_days,
                    'RetentionPeriodUnit': 'DAYS'
                },
                ResourceIds=[image_id]
            )
            
            logger.info(f"Moved AMI {image_id} to Recycle Bin")
            
            for snapshot_id in snapshot_ids:
                try:
                    ec2_client.create_tags(
                        Resources=[snapshot_id],
                        Tags=[
                            {'Key': 'aws:recycle-bin:resource-in-bin', 'Value': 'true'},
                            {'Key': 'ParentAMI', 'Value': image_id},
                            {'Key': 'IsShared', 'Value': str(is_shared)},
                            {'Key': 'RecycleBinDate', 'Value': datetime.now().strftime('%Y-%m-%d')}
                        ]
                    )
                    
                    rbin_client.put_retention_rule(
                        ResourceType='EBS_SNAPSHOT',
                        RetentionPeriod={
                            'RetentionPeriodValue': retention_period_days,
                            'RetentionPeriodUnit': 'DAYS'
                        },
                        ResourceIds=[snapshot_id]
                    )
                    
                    logger.info(f"Moved snapshot {snapshot_id} to Recycle Bin")
                    cleanup_report['snapshots_moved_to_recycle_bin_count'] += 1
                
                except Exception as e:
                    logger.error(f"Error processing snapshot {snapshot_id}: {e}")
            
            cleanup_report['moved_to_recycle_bin'].append({
                'ImageId': image_id,
                'Name': ami.get('Name', 'N/A'),
                'IsShared': is_shared,
                'SnapshotCount': len(snapshot_ids)
            })
            cleanup_report['moved_to_recycle_bin_count'] += 1
        
        except Exception as e:
            logger.error(f"Error implementing cleanup policy for AMI {ami['ImageId']}: {e}")
            cleanup_report['errors'].append({
                'ImageId': ami['ImageId'],
                'Name': ami.get('Name', 'N/A'),
                'Error': str(e)
            })
            cleanup_report['error_count'] += 1
    
    return cleanup_report

def generate_report(ami_report, cleanup_report):
    """
    Generate a comprehensive report of unused AMIs and cleanup actions
    """
    sorted_report = sorted(ami_report, key=lambda x: x.get('CreationDate', ''))
    
    shared_amis = [ami for ami in sorted_report if ami['IsShared']]
    unshared_amis = [ami for ami in sorted_report if not ami['IsShared']]
    error_checking = [ami for ami in sorted_report if ami['RiskLevel'] == 'ERROR_CHECKING']
    
    report = {
        'summary': {
            'total_unused_amis': len(sorted_report),
            'shared_amis_count': len(shared_amis),
            'unshared_amis_count': len(unshared_amis),
            'error_checking_count': len(error_checking),
            'moved_to_recycle_bin_count': cleanup_report['moved_to_recycle_bin_count'],
            'error_count': cleanup_report['error_count'],
            'analysis_timestamp': datetime.now().isoformat()
        },
        'shared_amis': shared_amis,
        'unshared_amis': unshared_amis,
        'error_checking': error_checking,
        'all_unused_amis': sorted_report,
        'cleanup_actions': {
            'moved_to_recycle_bin': cleanup_report['moved_to_recycle_bin'],
            'errors': cleanup_report['errors']
        }
    }
    
    return report

def store_report_in_s3(s3_client, bucket, key, report):
    """
    Store the report in S3
    """
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(report, default=str),
        ContentType='application/json'
    )
    logger.info(f"Report stored in S3: s3://{bucket}/{key}")