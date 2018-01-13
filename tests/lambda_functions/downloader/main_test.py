"""Unit tests for the CarbonBlack downloading Lambda function."""
# pylint: disable=protected-access
import base64
import io
import os
from unittest import mock

import boto3
import cbapi
from cbapi.errors import ObjectNotFoundError
from pyfakefs import fake_filesystem_unittest


class MockBinary(object):
    """Mock for cbapi.response.models.Binary."""

    class MockVirusTotal(object):
        """Mock for cbapi.response.models.VirusTotal."""
        def __init__(self, score: int = 0) -> None:
            self.score = score

    def __init__(self, contents: bytes, **kwargs) -> None:
        self.contents = contents
        self.properties = dict(kwargs)

    def __getattr__(self, attr: str):
        if attr == 'file':
            return io.BytesIO(self.contents)
        return self.properties[attr]


class MainTest(fake_filesystem_unittest.TestCase):
    """Test each function in downloader/main.py"""

    def setUp(self):
        """Mock out CarbonBlack and boto3 before importing the module."""
        # Setup fake filesystem.
        self.setUpPyfakefs()

        # Create a mock binary.
        self._binary = MockBinary(
            b'hello world',
            group=['Production', 'Laptops'],
            host_count=2,
            last_seen='sometime-recently',
            md5='ABC123',
            observed_filenames=['/Users/name/file.txt'],
            os_type='Linux',
            virustotal=MockBinary.MockVirusTotal(),
            webui_link='example.com'
        )

        mock_environ = {
            'CARBON_BLACK_URL': 'cb-url',
            'DOWNLOAD_SQS_QUEUE_URL': 'queue-url',
            'ENCRYPTED_CARBON_BLACK_API_TOKEN': base64.b64encode(b'super-secret').decode('ascii'),
            'TARGET_S3_BUCKET': 'test-bucket'
        }

        # Mock out cbapi and import the file under test.
        with mock.patch.object(boto3, 'client'), \
                mock.patch.object(boto3, 'resource'), \
                mock.patch.object(cbapi, 'CbEnterpriseResponseAPI'), \
                mock.patch.dict(os.environ, mock_environ):
            from lambda_functions.downloader import main
            self.download_main = main

        # Reset mocks for each test.
        self.download_main.LOGGER = mock.MagicMock()
        self.download_main.CLOUDWATCH = mock.MagicMock()
        self.download_main.SQS_QUEUE = mock.MagicMock()

    def test_validate_list_with_errors(self):
        """Extract valid MD5s from a list and log errors for the rest."""
        event = [
            {
                'body': '{"md5":"ABC"}',
                'receipt': 'R1',
                'receive_count': 1
            },
            {
                'body': '{"md5":"DEF"}',
                'receipt': 'R2',
                'receive_count': 2
            },
            {'body': 'not-json'},  # JSONDecodeError
            {}  # KeyError
        ]

        with mock.patch.object(self.download_main, 'LOGGER') as mock_logger:
            result = self.download_main._validate_and_extract_md5s(event)
            mock_logger.assert_has_calls([
                mock.call.info('Invoked from dispatcher with list of %d SQS records', 4),
                mock.call.exception('Skipping invalid SQS record: %s', event[2]),
                mock.call.exception('Skipping invalid SQS record: %s', event[3])
            ])

        expected = [
            self.download_main.DownloadRecord('ABC', 'R1', 1),
            self.download_main.DownloadRecord('DEF', 'R2', 2)
        ]
        self.assertEqual(expected, result)

    def test_validate_dict(self):
        """Extract MD5 from a dictionary invocation."""
        event = {'md5': 'ABC'}

        with mock.patch.object(self.download_main, 'LOGGER') as mock_logger:
            result = self.download_main._validate_and_extract_md5s(event)
            mock_logger.assert_has_calls([mock.call.info('Invoked with dictionary event')])

        expected = [self.download_main.DownloadRecord('ABC', None, 0)]
        self.assertEqual(expected, result)

    def test_validate_dict_key_error(self):
        """Log an exception for an invalid dictionary invocation."""
        event = {'sha256': 'ABC'}

        with mock.patch.object(self.download_main, 'LOGGER') as mock_logger:
            result = self.download_main._validate_and_extract_md5s(event)
            mock_logger.assert_has_calls([
                mock.call.info('Invoked with dictionary event'),
                mock.call.exception('Invalid event: %s', event)
            ])

        self.assertEqual([], result)

    def test_validate_unknown_event_type(self):
        """An event which is not a dict nor a list logs an exception."""
        event = 123

        with mock.patch.object(self.download_main, 'LOGGER') as mock_logger:
            result = self.download_main._validate_and_extract_md5s(event)
            mock_logger.assert_has_calls([mock.call.exception('Unexpected event type: %s', event)])

        self.assertEqual([], result)

    def test_process_md5(self):
        """Test a download process for a single MD5."""
        with mock.patch.object(self.download_main.CARBON_BLACK, 'select') as mock_select, \
                mock.patch.object(self.download_main, 'LOGGER') as mock_logger, \
                mock.patch.object(self.download_main, 'subprocess') as mock_subprocess:
            mock_select.return_value = self._binary

            self.assertTrue(self.download_main._process_md5('ABC123'))

            mock_logger.assert_has_calls([
                mock.call.info('Downloading %s to %s', 'example.com', mock.ANY),
                mock.call.info('Uploading to S3 with key %s', 'carbonblack/ABC123')]
            )

            expected_metadata = {
                'carbon_black_group': 'Production,Laptops',
                'carbon_black_host_count': '2',
                'carbon_black_last_seen': 'sometime-recently',
                'carbon_black_md5': 'ABC123',
                'carbon_black_os_type': 'Linux',
                'carbon_black_virustotal_score': '0',
                'carbon_black_webui_link': 'example.com',
                'filepath': '/Users/name/file.txt'
            }

            self.download_main.S3_BUCKET.assert_has_calls([
                mock.call.put_object(
                    Body=mock.ANY, Key='carbonblack/ABC123', Metadata=expected_metadata
                )
            ])

            mock_subprocess.assert_has_calls([
                mock.call.check_call(['shred', '--remove', mock.ANY])
            ])

    def test_process_md5_not_found(self):
        """Trying to download a file which doesn't exist logs an error."""
        with mock.patch.object(self.download_main.CARBON_BLACK, 'select') as mock_select, \
                mock.patch.object(self.download_main, '_build_metadata',
                                  side_effect=ObjectNotFoundError('')), \
                mock.patch.object(self.download_main, 'LOGGER') as mock_logger, \
                mock.patch.object(self.download_main, 'subprocess') as mock_subprocess:
            mock_select.return_value = self._binary

            self.assertFalse(self.download_main._process_md5('ABC123'))

            mock_logger.assert_has_calls([mock.call.exception('Error downloading %s', 'ABC123')])
            mock_subprocess.assert_has_calls([
                mock.call.check_call(['shred', '--remove', mock.ANY])
            ])

    def test_download_lambda_handler_sqs(self):
        """Verify receipts are deleted and metrics published."""
        event = [
            {
                'body': '{"md5":"ABC"}',
                'receipt': 'R1',
                'receive_count': 1
            },
            {
                'body': '{"md5":"DEF"}',
                'receipt': 'R2',
                'receive_count': 2
            }
        ]

        with mock.patch.object(self.download_main, '_process_md5', return_value=True), \
                mock.patch.object(self.download_main, 'LOGGER') as mock_logger:
            self.download_main.download_lambda_handler(event, None)

            mock_logger.assert_has_calls([
                mock.call.info('Invoked from dispatcher with list of %d SQS records', 2),
                mock.call.info('Deleting %d SQS receipt(s)', 2),
                mock.call.info('Sending ReceiveCount metrics')
            ])

        self.download_main.SQS_QUEUE.assert_has_calls([
            mock.call.delete_messages(Entries=[
                {'Id': '0', 'ReceiptHandle': 'R1'},
                {'Id': '1', 'ReceiptHandle': 'R2'}
            ])
        ])

        self.download_main.CLOUDWATCH.assert_has_calls([
            mock.call.put_metric_data(Namespace='BinaryAlert', MetricData=[{
                'MetricName': 'DownloadQueueReceiveCount',
                'StatisticValues': {
                    'Minimum': 1,
                    'Maximum': 2,
                    'SampleCount': 2,
                    'Sum': 3
                },
                'Unit': 'Count'
            }])
        ])

    def test_download_lambda_handler_no_sqs(self):
        """An event with no SQS receipts results in no calls to CloudWatch nor SQS"""
        event = {'md5': 'ABC'}

        with mock.patch.object(self.download_main, '_process_md5', return_value=True):
            self.download_main.download_lambda_handler(event, None)

        self.download_main.SQS_QUEUE.assert_not_called()
        self.download_main.CLOUDWATCH.assert_not_called()

    def test_download_lambda_handler_empty_list(self):
        """An empty event causes downloader to exit early."""
        with mock.patch.object(self.download_main, 'LOGGER') as mock_logger:
            self.download_main.download_lambda_handler([], None)
            mock_logger.assert_has_calls([
                mock.call.warning('No MD5 records found')
            ])
