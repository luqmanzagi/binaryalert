"""The dispatch Lambda function."""
# The dispatcher rotates through all of the SQS queues listed, polling a batch of up to 10 records
# and forwarding them to the Lambda function configured for that queue.
#
# Expects the following environment variables:
#   SQS_QUEUE_URLS: Comma-separated list of SQS queues to poll.
#   LAMBDA_TARGETS: Comma-separated list of Lambda function:qualifier to dispatch to.
#   MAX_INVOCATIONS: Comma-separated list of the maximum number of invocations allowed per queue.
import collections
import json
import logging
import os
from typing import Any, Dict, List

import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

CLOUDWATCH = boto3.client('cloudwatch')
LAMBDA = boto3.client('lambda')

# Build a DispatchConfig tuple for each queue specified in the environment variables.
DispatchConfig = collections.namedtuple(
    'DispatchConfig', ['queue', 'lambda_name', 'lambda_qualifier', 'max_invocations'])
DISPATCH_CONFIGS = [
    DispatchConfig(
        queue=boto3.resource('sqs').Queue(url),
        lambda_name=target.split(':')[0],
        lambda_qualifier=target.split(':')[1],
        max_invocations=int(max_invoke)
    )
    for (url, target, max_invoke) in zip(
        os.environ['SQS_QUEUE_URLS'].split(','),
        os.environ['LAMBDA_TARGETS'].split(','),
        os.environ['MAX_INVOCATIONS'].split(',')
    )
]

SQS_MAX_MESSAGES = 10  # Maximum number of messages to request (highest allowed by SQS).
WAIT_TIME_SECONDS = 3  # Maximum amount of time to hold a receive_message connection open.


def _send_messages(sqs_messages: List[Any], config: DispatchConfig) -> None:
    """Invoke the target Lambda with a batch of SQS messages."""
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
    LOGGER.info('Sending %d messages to %s:%s',
                len(records), config.lambda_name, config.lambda_qualifier)
    LAMBDA.invoke(
        FunctionName=config.lambda_name,
        InvocationType='Event',  # Asynchronous invocation
        Payload=json.dumps(records),
        Qualifier=config.lambda_qualifier
    )


def _publish_metrics(batch_sizes: Dict[str, List[int]]) -> None:
    """Publish metrics about how many times each function was invoked, and with what batch sizes."""
    metric_data = []

    for function_name, batches in batch_sizes.items():
        if len(batches) == 0:
            # This function was never invoked - save money / API calls by eliding its metrics.
            continue

        dimensions = [{'Name': 'FunctionName', 'Value': function_name}]
        metric_data.append({
            'MetricName': 'DispatchInvocations',
            'Dimensions': dimensions,
            'Value': len(batches),
            'Unit': 'Count'
        })
        metric_data.append({
            'MetricName': 'DispatchBatchSize',
            'Dimensions': dimensions,
            'StatisticValues': {
                'Minimum': min(batches),
                'Maximum': max(batches),
                'SampleCount': len(batches),
                'Sum': sum(batches)
            },
            'Unit': 'Count'
        })

    if metric_data:
        LOGGER.info('Publishing invocation metrics')
        CLOUDWATCH.put_metric_data(Namespace='BinaryAlert', MetricData=metric_data)
    else:
        LOGGER.info('No messages dispatched')


def dispatch_lambda_handler(_, lambda_context):
    """Dispatch Lambda function entry point.

    Args:
        _: Unused invocation event.
        lambda_context: LambdaContext object with .get_remaining_time_in_millis().
    """
    # Keep track of the batch sizes (one element for each invocation) for each target function.
    batch_sizes = {config.lambda_name: [] for config in DISPATCH_CONFIGS}

    # The maximum amount of time needed in the execution loop.
    # This allows us to dispatch as long as possible while still staying under the time limit.
    # We need time to wait for sqs messages as well as a few seconds (e.g. 5) to forward them.
    loop_execution_time_ms = (WAIT_TIME_SECONDS + 5) * 1000

    while lambda_context.get_remaining_time_in_millis() > loop_execution_time_ms:
        # If all functions have reached their dispatch limit, stop now.
        if all(len(batch_sizes[config.lambda_name]) == config.max_invocations
               for config in DISPATCH_CONFIGS):
            LOGGER.info('Dispatch limit reached - stopping early')
            break

        for config in DISPATCH_CONFIGS:
            # If we've already reached our invocation limit for this queue, skip it.
            if len(batch_sizes[config.lambda_name]) == config.max_invocations:
                continue

            # Poll a batch of messages.
            sqs_messages = config.queue.receive_messages(
                AttributeNames=['ApproximateReceiveCount'],
                MaxNumberOfMessages=SQS_MAX_MESSAGES,
                WaitTimeSeconds=WAIT_TIME_SECONDS
            )
            if not sqs_messages:
                continue

            _send_messages(sqs_messages, config)
            batch_sizes[config.lambda_name].append(len(sqs_messages))

    _publish_metrics(batch_sizes)
