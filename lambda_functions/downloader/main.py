"""Lambda function to copy a binary from CarbonBlack into the BinaryAlert input S3 bucket."""
# Expects the following environment variables:
#   CARBON_BLACK_URL: URL of the CarbonBlack server.
#   DOWNLOAD_SQS_QUEUE_URL: URL for the downloader SQS queue.
#   ENCRYPTED_CARBON_BLACK_API_TOKEN: API token, encrypted with KMS.
#   TARGET_S3_BUCKET: Name of the S3 bucket in which to save the copied binary.
import base64
import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Dict, List
import zipfile

import backoff
import boto3
from botocore.exceptions import BotoCoreError
import cbapi
from cbapi.errors import ObjectNotFoundError
from cbapi.response.models import Binary

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('backoff').addHandler(logging.StreamHandler())  # Enable backoff logger.

ENCRYPTED_TOKEN = os.environ['ENCRYPTED_CARBON_BLACK_API_TOKEN']
DECRYPTED_TOKEN = boto3.client('kms').decrypt(
    CiphertextBlob=base64.b64decode(ENCRYPTED_TOKEN)
)['Plaintext']

# Establish boto3 and S3 clients at import time so Lambda can cache them for re-use.
CARBON_BLACK = cbapi.CbEnterpriseResponseAPI(
    url=os.environ['CARBON_BLACK_URL'], token=DECRYPTED_TOKEN)
CLOUDWATCH = boto3.client('cloudwatch')
S3_BUCKET = boto3.resource('s3').Bucket(os.environ['TARGET_S3_BUCKET'])
SQS_QUEUE = boto3.resource('sqs').Queue(os.environ['DOWNLOAD_SQS_QUEUE_URL'])

# SQS polling configuration
SQS_MAX_MESSAGES = 5  # Max number of messages to receive.
WAIT_TIME_SECONDS = 3  # Number of seconds to hold SQS connection open.


def _download_from_carbon_black(binary: Binary) -> str:
    """Download the binary from CarbonBlack into /tmp.

    WARNING: CarbonBlack truncates binaries to 25MB. The MD5 will cover the entire file, but only
    the first 25MB of the binary will be downloaded.

    Args:
        binary: CarbonBlack binary instance.

    Returns:
        Path where file was downloaded.
    """
    download_path = os.path.join(tempfile.gettempdir(), 'carbonblack_{}'.format(binary.md5))
    LOGGER.info('Downloading %s to %s', binary.webui_link, download_path)
    with binary.file as cb_file, open(download_path, 'wb') as target_file:
        shutil.copyfileobj(cb_file, target_file)
    return download_path


def _build_metadata(binary: Binary) -> Dict[str, str]:
    """Return basic metadata to make it easier to triage YARA match alerts."""
    return {
        'carbon_black_group': ','.join(binary.group),
        'carbon_black_host_count': str(binary.host_count),
        'carbon_black_last_seen': binary.last_seen,
        'carbon_black_md5': binary.md5,
        'carbon_black_os_type': binary.os_type,
        'carbon_black_virustotal_score': str(binary.virustotal.score),
        'carbon_black_webui_link': binary.webui_link,
        'filepath': (
            # Throw out any non-ascii characters (S3 metadata must be ascii).
            binary.observed_filenames[0].encode('ascii', 'ignore').decode('ascii')
        )
    }


@backoff.on_exception(backoff.expo, BotoCoreError, max_tries=3, jitter=backoff.full_jitter)
def _upload_to_s3(md5: str, local_file_path: str, metadata: Dict[str, str]) -> None:
    """Upload the binary contents to S3 along with the given object metadata.

    Args:
        md5: CarbonBlack MD5 key (used as the S3 object key).
        local_file_path: Path to the file to upload.
        metadata: Binary metadata to attach to the S3 object.

    Returns:
        The newly added S3 object key (based on CarbonBlack's MD5).
    """
    s3_object_key = 'carbonblack/{}'.format(md5)
    LOGGER.info('Uploading to S3 with key %s', s3_object_key)
    with open(local_file_path, 'rb') as target_file:
        S3_BUCKET.put_object(Body=target_file, Key=s3_object_key, Metadata=metadata)


def _process_md5(md5: str) -> bool:
    """Download the given file from CarbonBlack and upload to S3, returning True if successful."""
    download_path = ''
    try:
        binary = CARBON_BLACK.select(Binary, md5)
        download_path = _download_from_carbon_black(binary)
        metadata = _build_metadata(binary)
        _upload_to_s3(binary.md5, download_path, metadata)
        return True
    except (BotoCoreError, ObjectNotFoundError, zipfile.BadZipFile):
        LOGGER.exception('Error downloading %s, record will remain in queue.', md5)
        return False
    finally:
        if download_path:
            # Shred downloaded file before exiting.
            subprocess.check_call(['shred', '--remove', download_path])


def _delete_sqs_messages(receipts: List[str]) -> None:
    """Mark a batch of SQS receipts as completed (removing them from the queue).

    Args:
        receipts: List of SQS receipt handles.
    """
    if not receipts:
        return
    LOGGER.info('Deleting %d SQS receipt(s)', len(receipts))
    SQS_QUEUE.delete_messages(
        Entries=[
            {'Id': str(index), 'ReceiptHandle': receipt} for index, receipt in enumerate(receipts)]
    )


def download_lambda_handler(_, lambda_context) -> None:
    """Lambda function entry point - copy a binary from CarbonBlack into the BinaryAlert S3 bucket.

    Args:
        _: Unused invocation event
        lambda_context: Lambda context object with .get_remaining_time_in_millis().
    """
    # Maximum amount of time needed in the execution loop.
    # Allows us to break early instead of timing out.
    loop_execution_time_ms = (WAIT_TIME_SECONDS + 60) * 1000

    # Keep polling from SQS until we run out of time or until there are no messages.
    receive_counts = []  # Number of times message was received before processed successfully.
    while lambda_context.get_remaining_time_in_millis() > loop_execution_time_ms:
        # Long-polling: Wait up to 3 seconds and receive up to 5 messages.
        sqs_messages = SQS_QUEUE.receive_messages(
            AttributeNames=['ApproximateReceiveCount'],
            MaxNumberOfMessages=SQS_MAX_MESSAGES,
            WaitTimeSeconds=WAIT_TIME_SECONDS
        )

        if not sqs_messages:
            LOGGER.info('No SQS messages available: exiting')
            return

        delete_receipts = []  # List of SQS receipts which can be deleted
        for msg in sqs_messages:
            try:
                md5 = json.loads(msg.body)['md5']
            except (json.JSONDecodeError, KeyError):
                LOGGER.exception('Unrecognized message body %s', msg.body)
                delete_receipts.append(msg.receipt_handle)
                continue

            if _process_md5(md5):
                # File was copied successfully - the receipt can be deleted.
                # An MD5 which fails to download will simply remain on the queue and will become
                # available after the visibility timeout window to be tried again.
                delete_receipts.append(msg.receipt_handle)
                receive_counts.append(int(msg.attributes['ApproximateReceiveCount']))

        _delete_sqs_messages(delete_receipts)

    # Publish metrics about how many times messages had to be received before successful processing.
    if receive_counts:
        LOGGER.info('Sending receive count metrics')
        CLOUDWATCH.put_metric_data(
            Namespace='BinaryAlert', MetricData=[{
                'MetricName': 'DownloadQueueReceiveCount',
                'StatisticValues': {
                    'Minimum': min(receive_counts),
                    'Maximum': max(receive_counts),
                    'SampleCount': len(receive_counts),
                    'Sum': sum(receive_counts)
                },
                'Unit': 'Count'
            }]
        )
