import os
import boto3
import re
import requests
import logging
from pathlib import Path
from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError, NoCredentialsError
from urllib.parse import urlparse

from pdb import set_trace

from .utils import S3_PROVIDER_ENDPOINT_URLS, parse_uri
from .s3_auth import get_aws_credentials_with_provider_hint
from .s3_public import check_public_s3_object

logger = logging.getLogger(__name__) # Use module name for clarity

__all__ = ['create_s3_client']

def create_s3_client(s3_path, s3_config=None):
    """
    Constructs and returns a boto3 S3 client based on access type.

    :param s3_path: The S3 path being accessed (for logging purposes).
    :return: A boto3 S3 client instance, or None if client creation fails.
    """

    if s3_config is None:
        s3_config = {}
    endpoint_url = s3_config.get('endpoint_url')
    region = s3_config.get('region')

    # First, check if the object is public
    try:
        scheme, bucket_name, object_key, _ = parse_uri(s3_path)
    except ValueError as e:
        logger.error(f"Error parsing URI '{s3_path}': {e}")
        return False

    is_public = check_public_s3_object(s3_path, 
                                       region=region,
                                       endpoint_url=endpoint_url)
    
    if is_public:
        # Public access: initialize client without credentials.
        if endpoint_url is None:
            endpoint_url = S3_PROVIDER_ENDPOINT_URLS.get(scheme)

        # create the client
        try:
            client = boto3.client(
                's3',
                region_name=region,
                endpoint_url=endpoint_url,
                config=Config(signature_version=UNSIGNED)
            )
            return client
        except Exception as e:
            logger.error(f"Error creating anonymous S3 client for '{s3_path}': {e}", exc_info=True)
            return None
    else:
        # Private access: retrieve credentials and initialize client with them.
        creds = get_aws_credentials_with_provider_hint(scheme,
                                                       profile=s3_config.get('profile'),
                                                       endpoint_url=endpoint_url,
                                                       region=region)
        if not creds:
            logger.error(
                f"Could not retrieve AWS credentials for accessing '{s3_path}'. "
                f"Ensure profile '{profile}' is configured correctly."
            )
            return None

        # Use passed endpoint_url if provided; otherwise, try credentials or fallback.
        if endpoint_url is None:
            endpoint_url = creds.get('endpoint_url', S3_PROVIDER_ENDPOINT_URLS.get(scheme))

        # Create the client
        try:
            client = boto3.client(
                's3',
                region_name=region,
                aws_access_key_id=creds["aws_access_key_id"],
                aws_secret_access_key=creds["aws_secret_access_key"],
                aws_session_token=creds.get("aws_session_token"),
                endpoint_url=endpoint_url
            )
            return client
        except Exception as e:
            logger.error(f"Error creating authenticated S3 client for '{s3_path}': {e}", exc_info=True)
            return None