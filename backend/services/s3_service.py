import os
import logging
import asyncio
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("s3-service")

try:
    import boto3
    from botocore.exceptions import NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    boto3 = None
    NoCredentialsError = Exception
    BOTO3_AVAILABLE = False

def _sync_upload(local_path: str, session_id: str) -> str:
    """
    Synchronously upload PCAP to S3. Used directly inside log parser or synchronous routes.
    """
    if not BOTO3_AVAILABLE:
        logger.error("boto3 is not installed. Skipping S3 upload.")
        return ""

    bucket_name = os.getenv("S3_BUCKET_NAME")
    if not bucket_name:
        logger.error("S3_BUCKET_NAME environment variable is not set. Skipping PCAP upload.")
        return ""

    if not os.path.exists(local_path):
        logger.error(f"Local PCAP file not found: {local_path}")
        return ""

    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY")
    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_KEY")
    region_name = os.getenv("AWS_REGION") or "us-east-1"

    current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    s3_key = f"pcaps/{current_date}/{session_id}.pcap"

    try:
        if aws_access_key and aws_secret_key:
            s3 = boto3.client(
                "s3",
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region_name
            )
        else:
            logger.warning("AWS credentials not fully configured. Falling back to default credentials.")
            s3 = boto3.client("s3", region_name=region_name)

        logger.info(f"Uploading {local_path} to S3 bucket {bucket_name} as {s3_key}...")
        s3.upload_file(local_path, bucket_name, s3_key)

        presigned_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": s3_key},
            ExpiresIn=604800  # 7 days in seconds
        )
        logger.info(f"S3 PCAP upload successful. Presigned URL: {presigned_url}")
        return presigned_url
    except NoCredentialsError:
        logger.error("AWS credentials were not found by boto3.")
        return ""
    except Exception as e:
        logger.error(f"Error uploading to S3: {e}")
        return ""

async def upload_pcap(local_path: str, session_id: str) -> str:
    """
    Asynchronously uploads local PCAP file to AWS S3 and returns a presigned URL valid for 7 days.
    """
    try:
        return await asyncio.to_thread(_sync_upload, local_path, session_id)
    except Exception as e:
        logger.error(f"Error in upload_pcap task wrapper: {e}")
        return ""
