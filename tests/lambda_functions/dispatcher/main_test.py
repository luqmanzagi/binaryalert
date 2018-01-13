"""Unit tests for batcher main.py. Mocks out boto3 clients."""
import collections
import json
import os
import unittest
from unittest import mock

import boto3

from tests import common

MockSQSMessage = collections.namedtuple('MockSQSMessage', ['attributes', 'body', 'receipt_handle'])


class MainTest(unittest.TestCase):
    """Test the dispatch handler."""

    def setUp(self):
        """Set environment variables and setup the mocks."""
        mock_environ = {
            'LAMBDA_TARGETS': 'analyzer:production,downloader:staging',
            'MAX_INVOCATIONS': '2,3',
            'SQS_QUEUE_URLS': 'url1,url2'
        }

        with mock.patch.dict(os.environ, mock_environ), mock.patch.object(boto3, 'client'), \
                mock.patch.object(boto3, 'resource'):
            from lambda_functions.dispatcher import main
            self.dispatcher_main = main

        config1 = self.dispatcher_main.DISPATCH_CONFIGS[0]
        config2 = self.dispatcher_main.DISPATCH_CONFIGS[1]

        # All boto3 resources have to be explicitly assigned their own mock (not totally sure why).
        self.dispatcher_main.DISPATCH_CONFIGS = [
            self.dispatcher_main.DispatchConfig(
                mock.MagicMock(),
                config1.lambda_name, config1.lambda_qualifier, config1.max_invocations
            ),
            self.dispatcher_main.DispatchConfig(
                mock.MagicMock(),
                config2.lambda_name, config2.lambda_qualifier, config2.max_invocations
            )
        ]
        self.dispatcher_main.CLOUDWATCH = mock.MagicMock()
        self.dispatcher_main.LAMBDA = mock.MagicMock()

        self.config1 = self.dispatcher_main.DISPATCH_CONFIGS[0]
        self.config2 = self.dispatcher_main.DISPATCH_CONFIGS[1]

    def _set_sqs_messages(self, empty=False):
        """Sets sqs receive calls to return either an empty list or pre-defined mocks."""
        if empty:
            self.config1.queue.receive_messages.return_value = []
            self.config2.queue.receive_messages.return_value = []
        else:
            self.config1.queue.receive_messages.return_value = [
                MockSQSMessage({'ApproximateReceiveCount': 1}, 'queue1-message1', 'q1m1'),
                MockSQSMessage({'ApproximateReceiveCount': 2}, 'queue1-message2', 'q1m2')
            ]
            self.config2.queue.receive_messages.return_value = [
                MockSQSMessage({'ApproximateReceiveCount': 3}, 'queue2-message1', 'q2m1')
            ]

    def test_dispatch_configs(self):
        """Environment variables were parsed correctly into 2 DispatchConfig tuples."""
        self.assertIsInstance(self.config1.queue, mock.MagicMock)
        self.assertEqual('analyzer', self.config1.lambda_name)
        self.assertEqual('production', self.config1.lambda_qualifier)
        self.assertEqual(2, self.config1.max_invocations)

        self.assertIsInstance(self.config2.queue, mock.MagicMock)
        self.assertNotEqual(self.config1.queue, self.config2.queue)
        self.assertEqual('downloader', self.config2.lambda_name)
        self.assertEqual('staging', self.config2.lambda_qualifier)
        self.assertEqual(3, self.config2.max_invocations)

    def test_dispatch_no_messages(self):
        """Dispatcher doesn't do anything if there are no SQS messages."""
        self._set_sqs_messages(empty=True)

        with mock.patch.object(self.dispatcher_main, 'LOGGER') as mock_logger:
            self.dispatcher_main.dispatch_lambda_handler(None, common.MockLambdaContext())
            mock_logger.assert_has_calls([mock.call.info('No messages dispatched')])

        self.dispatcher_main.CLOUDWATCH.assert_not_called()
        self.dispatcher_main.LAMBDA.assert_not_called()

    def test_dispatch_invokes_all_targets(self):
        """Dispatcher invokes each of the Lambda targets with data from its respective queue."""
        self._set_sqs_messages(empty=False)

        # The mock lambda context causes function to poll each queue twice.
        with mock.patch.object(self.dispatcher_main, 'LOGGER') as mock_logger:
            self.dispatcher_main.dispatch_lambda_handler(None, common.MockLambdaContext())
            mock_logger.assert_has_calls([
                mock.call.info('Sending %d messages to %s:%s', 2, 'analyzer', 'production'),
                mock.call.info('Sending %d messages to %s:%s', 1, 'downloader', 'staging'),
                mock.call.info('Sending %d messages to %s:%s', 2, 'analyzer', 'production'),
                mock.call.info('Sending %d messages to %s:%s', 1, 'downloader', 'staging'),
                mock.call.info('Publishing invocation metrics')
            ])

        # Verify Lambda invocations.
        self.dispatcher_main.LAMBDA.assert_has_calls([
            mock.call.invoke(
                FunctionName='analyzer',
                InvocationType='Event',
                Payload=json.dumps([
                    {
                        'body': 'queue1-message1',
                        'receipt': 'q1m1',
                        'receive_count': 1
                    },
                    {
                        'body': 'queue1-message2',
                        'receipt': 'q1m2',
                        'receive_count': 2
                    }
                ]),
                Qualifier='production'
            ),
            mock.call.invoke(
                FunctionName='downloader',
                InvocationType='Event',
                Payload=json.dumps([
                    {
                        'body': 'queue2-message1',
                        'receipt': 'q2m1',
                        'receive_count': 3
                    }
                ]),
                Qualifier='staging'
            )
        ])

        # Verify metrics.
        self.dispatcher_main.CLOUDWATCH.assert_has_calls([
            mock.call.put_metric_data(
                Namespace='BinaryAlert',
                MetricData=[
                    {
                        'MetricName': 'DispatchInvocations',
                        'Dimensions': [{'Name': 'FunctionName', 'Value': 'analyzer'}],
                        'Value': 2,
                        'Unit': 'Count'
                    },
                    {
                        'MetricName': 'DispatchBatchSize',
                        'Dimensions': [{'Name': 'FunctionName', 'Value': 'analyzer'}],
                        'StatisticValues': {
                            'Minimum': 2,
                            'Maximum': 2,
                            'SampleCount': 2,
                            'Sum': 4
                        },
                        'Unit': 'Count'
                    },
                    {
                        'MetricName': 'DispatchInvocations',
                        'Dimensions': [{'Name': 'FunctionName', 'Value': 'downloader'}],
                        'Value': 2,
                        'Unit': 'Count'
                    },
                    {
                        'MetricName': 'DispatchBatchSize',
                        'Dimensions': [{'Name': 'FunctionName', 'Value': 'downloader'}],
                        'StatisticValues': {
                            'Minimum': 1,
                            'Maximum': 1,
                            'SampleCount': 2,
                            'Sum': 2
                        },
                        'Unit': 'Count'
                    }
                ]
            )
        ])

    def test_dispatch_limit_reached(self):
        """Dispatcher quits early when dispatch limits are reached."""
        self._set_sqs_messages(empty=False)

        with mock.patch.object(self.dispatcher_main, 'LOGGER') as mock_logger:
            # Dispatcher would run for several minutes, but should stop early.
            # analyzer should be invoked 2 times, downloader should be invoked 3 times.
            self.dispatcher_main.dispatch_lambda_handler(
                None, common.MockLambdaContext(time_limit_ms=120000, decrement_ms=5000))
            mock_logger.assert_has_calls([
                mock.call.info('Sending %d messages to %s:%s', 2, 'analyzer', 'production'),
                mock.call.info('Sending %d messages to %s:%s', 1, 'downloader', 'staging'),
                mock.call.info('Sending %d messages to %s:%s', 2, 'analyzer', 'production'),
                mock.call.info('Sending %d messages to %s:%s', 1, 'downloader', 'staging'),
                mock.call.info('Sending %d messages to %s:%s', 1, 'downloader', 'staging'),
                mock.call.info('Dispatch limit reached - stopping early'),
                mock.call.info('Publishing invocation metrics')
            ])
