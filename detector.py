import json
import gzip
import boto3
from datetime import datetime

s3 = boto3.client('s3')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')

# Update this with your SNS Topic ARN
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:058264465854:cloudtrail-alerts"
DYNAMO_TABLE = "cloudtrail-alert-log"

# Detection rules mapped to severity levels
# Each event is also mapped to MITRE ATT&CK in README
SUSPICIOUS_EVENTS = {
    "DeleteTrail":               "CRITICAL",  # T1562.001 - Impair Defenses
    "StopLogging":               "CRITICAL",  # T1562.001 - Impair Defenses
    "UpdateTrail":               "HIGH",      # T1562.001 - Impair Defenses
    "CreateUser":                "HIGH",      # T1136.003 - Create Cloud Account
    "AttachUserPolicy":          "HIGH",      # T1098 - Account Manipulation
    "PutUserPolicy":             "HIGH",      # T1098 - Account Manipulation
    "CreateAccessKey":           "HIGH",      # T1528 - Steal Application Access Token
    "DeleteBucketPolicy":        "HIGH",      # T1070 - Indicator Removal
    "PutBucketAcl":              "MEDIUM",    # T1530 - Data from Cloud Storage
    "AssumeRoleWithWebIdentity": "MEDIUM",    # T1548 - Abuse Elevation Control
    "ConsoleLogin":              "LOW",       # T1078 - Valid Accounts
}


def lambda_handler(event, context):
    """
    Triggered by S3 ObjectCreated events on the CloudTrail log bucket.
    Parses each CloudTrail log file and checks for suspicious API calls.
    Sends SNS alerts and logs to DynamoDB for every detection.
    """
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']

        print(f"Processing log file: s3://{bucket}/{key}")

        # Download and decompress CloudTrail log
        response = s3.get_object(Bucket=bucket, Key=key)
        compressed = response['Body'].read()
        log_data = json.loads(gzip.decompress(compressed))

        for ct_event in log_data.get('Records', []):
            event_name = ct_event.get('eventName', '')

            if event_name in SUSPICIOUS_EVENTS:
                severity = SUSPICIOUS_EVENTS[event_name]
                user = ct_event.get('userIdentity', {}).get('arn', 'Unknown')
                source_ip = ct_event.get('sourceIPAddress', 'Unknown')
                region = ct_event.get('awsRegion', 'Unknown')
                event_time = ct_event.get('eventTime', '')
                event_id = ct_event.get('eventID', 'unknown')

                alert = {
                    "severity": severity,
                    "event": event_name,
                    "user": user,
                    "source_ip": source_ip,
                    "region": region,
                    "time": event_time
                }

                # Send SNS email alert
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=f"[{severity}] Suspicious AWS Activity: {event_name}",
                    Message=json.dumps(alert, indent=2)
                )

                # Persist alert to DynamoDB audit log
                table = dynamodb.Table(DYNAMO_TABLE)
                table.put_item(Item={
                    "event_id":   event_id,
                    "timestamp":  event_time,
                    "severity":   severity,
                    "event_name": event_name,
                    "user_arn":   user,
                    "source_ip":  source_ip,
                    "region":     region
                })

                print(f"ALERT [{severity}]: {event_name} by {user} from {source_ip} at {event_time}")

    return {"statusCode": 200}
