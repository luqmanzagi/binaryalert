"""AWS Lambda function for testing a binary against a list of YARA rules."""
# Expects the following environment variables:
#   SQS_QUEUE_URL: URL of the queue from which messages originated (needed for message deletion).
#   YARA_MATCHES_DYNAMO_TABLE_NAME: Name of the Dynamo table which stores YARA match results.
#   YARA_ALERTS_SNS_TOPIC_ARN: ARN of the SNS topic which should be alerted on a YARA match.
# Expects a binary YARA rules file to be at './compiled_yara_rules.bin'
import json
import os
from typing import Any, Dict, List
import urllib.parse

from botocore.exceptions import ClientError as BotoError
import boto3

if __package__:
    # Imported by unit tests or other external code.
    from lambda_functions.analyzer import analyzer_aws_lib, binary_info, yara_analyzer
    from lambda_functions.analyzer.common import COMPILED_RULES_FILEPATH, LOGGER
else:
    # mypy complains about duplicate definitions
    import analyzer_aws_lib  # type: ignore
    import binary_info  # type: ignore
    from common import COMPILED_RULES_FILEPATH, LOGGER  # type: ignore
    import yara_analyzer  # type: ignore

# Build the YaraAnalyzer from the compiled rules file at import time (i.e. once per container).
# This saves 50-100+ ms per Lambda invocation, depending on the size of the rules file.
ANALYZER = yara_analyzer.YaraAnalyzer(COMPILED_RULES_FILEPATH)
# Due to a bug in yara-python, num_rules only be computed once. Thereafter, it will return 0.
# So we have to compute this here since multiple invocations may share the same analyzer.
NUM_YARA_RULES = ANALYZER.num_rules


def _iter_s3_objects(s3_records):
    if not isinstance(s3_records, list):
        raise TypeError('S3 records should be a list: %s', s3_records)

    for s3_record in s3_records:
        try:
            bucket_name = s3_record['s3']['bucket']['name']
            object_key = urllib.parse.unquote_plus(s3_record['s3']['object']['key'])
        except KeyError:
            LOGGER.exception('Skipping invalid S3 record %s', s3_record)
            continue
        yield (bucket_name, object_key)


def _parse_and_validate_event(event: List[Dict[str, Any]]):
    result = {}  # Map SQS receipt to list of (bucket_name, object_key) to analyze.

    if isinstance(event, list):
        LOGGER.info('Invoked from dispatcher with list of %d events', len(event))
        for sqs_record in event:
            # Parse SQS record.
            sqs_receipt = None
            try:
                s3_records = json.loads(sqs_record['body'])['Records']
                sqs_receipt = sqs_record['receipt']
            except (json.JSONDecodeError, KeyError):
                LOGGER.exception('Skipping invalid SQS record %s', sqs_record)
                if sqs_receipt:
                    result[sqs_receipt] = []
                continue
            result[sqs_receipt] = list(_iter_s3_objects(s3_records))

    elif isinstance(event, dict):
        LOGGER.info('Invoked with dictionary (S3 Event)')
        # Since there's only one S3 event, we let top-level KeyErrors and TypeErrors bubble up.
        s3_records = event['Records']
        result[''] = list(_iter_s3_objects(s3_records))

    else:
        raise TypeError('Unexpected event type: %s', event)

    return result


def analyze_lambda_handler(event: Any, lambda_context) -> Dict[str, Dict[str, Any]]:
    """Lambda function entry point.

    Args:
        event: List of 1-10 invocation events from dispatcher: [
            {
                'body': string JSON encoded S3 Put Event: {
                    'Records': [
                        {
                            "s3": {
                                "object": {
                                    "key": "FileName.txt"
                                },
                                "bucket": {
                                    "name": "bucket.name"
                                }
                            }
                        }
                    ]
                }
                'receipt': string SQS receipt,
                'receive_count': int number of times this message has been received
            }
        ]
            Alternatively, the event can be an S3 Put Event dictionary (with no sqs information).
            This allows the analyzer to be linked directly to an S3 bucket notification if needed.
        lambda_context: LambdaContext object (with .function_version).

    Returns:
        A dict mapping S3 object identifier to a summary of file info and matched YARA rules.
        Example: {
            'S3:bucket:key': {
                'FileInfo': { ... },
                'MatchedRules': { ... },
                'NumMatchedRules': 1
            }
        }
    """
    result = {}
    binaries = []  # List of the BinaryInfo data.

    # The Lambda version must be an integer.
    try:
        lambda_version = int(lambda_context.function_version)
    except ValueError:
        LOGGER.warning('Invoked $LATEST instead of a versioned function')
        lambda_version = -1

    receipts_to_delete = []
    for sqs_receipt, objects in _parse_and_validate_event(event).items():
        for (bucket_name, object_key) in objects:
            LOGGER.info('Analyzing "%s:%s', bucket_name, object_key)

            with binary_info.BinaryInfo(bucket_name, object_key, ANALYZER) as binary:
                result[binary.s3_identifier] = binary.summary()
                binaries.append(binary)

            if binary.yara_matches:
                LOGGER.warning('%s matched YARA rules: %s', binary, binary.matched_rule_ids)
                binary.save_matches_and_alert(
                    lambda_version, os.environ['YARA_MATCHES_DYNAMO_TABLE_NAME'],
                    os.environ['YARA_ALERTS_SNS_TOPIC_ARN'])

        if sqs_receipt:
            receipts_to_delete.append(sqs_receipt)

    # Delete all of the SQS receipts (mark them as completed).
    analyzer_aws_lib.delete_sqs_messages(os.environ['SQS_QUEUE_URL'], receipts_to_delete)

    # Publish metrics.
    try:
        analyzer_aws_lib.put_metric_data(NUM_YARA_RULES, binaries)
    except BotoError:
        LOGGER.exception('Error saving metric data')

    return result
