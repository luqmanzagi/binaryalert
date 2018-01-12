"""The dispatch Lambda function."""
# The dispatcher rotates through all of the SQS queues listed, polling a batch of up to 10 records
# and forwarding them to the Lambda function configured for that queue.
#
# Expects the following environment variables:
#   SQS_QUEUE_URLS: Comma-separated list of SQS queues to poll
#   LAMBDA_TARGETS: Comma-separated list of Lambda function:qualifier to dispatch to.
#   MAX_INVOCATIONS: Comma-separated list of the maximum number of invocations allowed per queue.
import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

CLOUDWATCH = boto3.client('cloudwatch')
LAMBDA = boto3.client('lambda')
DISPATCH_CONFIGS = [
    {
        'queue': boto3.resource('sqs').Queue(url),
        'queue_url': url,
        'lambda_name':  target.split(':')[0],
        'lambda_qualifier': target.split(':')[1],
        'max_invocations': int(max_invoke),
    }
    for (url, target, max_invoke) in zip(
        os.environ['SQS_QUEUE_URLS'].split(','),
        os.environ['LAMBDA_TARGETS'].split(','),
        os.environ['MAX_INVOCATIONS'].split(',')
    )
]

SQS_MAX_MESSAGES = 10  # Maximum number of messages to request (highest allowed by SQS).
WAIT_TIME_SECONDS = 3  # Maximum amount of time to hold a receive_message connection open.


def dispatch_lambda_handler(_, lambda_context):
    """Dispatch Lambda function entry point.

    Args:
        _: Unused invocation event.
        lambda_context: LambdaContext object with .get_remaining_time_in_millis().
    """
    # The maximum amount of time needed in the execution loop.
    # This allows us to dispatch as long as possible while still staying under the time limit.
    # We need time to wait for sqs messages as well as a few seconds (e.g. 5) to forward them.
    loop_execution_time_ms = (WAIT_TIME_SECONDS + 5) * 1000

    # Keep track of the number of invocations of each Lambda for this run.
    invocations = {config['lambda_name']: 0 for config in DISPATCH_CONFIGS}

    while lambda_context.get_remaining_time_in_millis() > loop_execution_time_ms:
        # Round-robin all queue configs, polling from each.
        # TODO: Check if they are all at the dispatch limit
        # TODO: Don't publish metrics if nothing happened
        for config in DISPATCH_CONFIGS:
            # If we've already reached our invocation limit for this queue, skip it.
            function_name = config['lambda_name']
            if invocations[function_name] == config['max_invocations']:
                continue

            # Poll a batch of messages.
            sqs_messages = config['queue'].receive_messages(
                AttributeNames=['ApproximateReceiveCount'],
                MaxNumberOfMessages=SQS_MAX_MESSAGES,
                WaitTimeSeconds=WAIT_TIME_SECONDS
            )
            if not sqs_messages:
                continue

            # Build the JSON payload.
            records = [
                {
                    'body': msg.body,
                    'receipt': msg.receipt_handle,
                    'receive_count': int(msg.attributes['ApproximateReceiveCount']),
                }
                for msg in sqs_messages
            ]

            # Invoke the target Lambda.
            qualifier = config['lambda_qualifier']
            LOGGER.info('Sending %d messages to %s:%s', len(records), function_name, qualifier)
            LAMBDA.invoke(
                FunctionName=function_name,
                InvocationType='Event',  # Asynchronous invocation
                Payload=json.dumps(records),
                Qualifier=qualifier
            )
            invocations[function_name] += 1

    # Publish metrics about invocations.
    LOGGER.info('Dispatch cycle ended - publishing invocation metrics')
    CLOUDWATCH.put_metric_data(
        Namespace='BinaryAlert', MetricData=[
            {
                'MetricName': 'DispatchInvocations',
                'Dimensions': [
                    {
                        'Name': 'FunctionName',
                        'Value': function_name
                    }
                ],
                'Value': invoke_count,
                'Unit': 'Count'
            }
            for function_name, invoke_count in invocations.items()
        ]
    )
