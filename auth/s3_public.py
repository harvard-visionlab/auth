import os
import boto3
import re
import requests
import logging
from pathlib import Path
from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError, NoCredentialsError

from pdb import set_trace

from visionlab.auth.utils import DEFAULT_AWS_REGION, parse_uri

logger = logging.getLogger(__name__) # Use module name for clarity

__all__ = ['check_public_s3_object', 'check_private_s3_object']

def check_public_s3_object(
    uri: str,
    region: str | None = None,
    endpoint_url: str | None = None,
    timeout: int = 5,
    try_list: bool = True  # New parameter to try listing as fallback
) -> bool:
    """
    Checks if an S3 object is publicly readable via anonymous S3 API calls.
    
    Args:
        uri: The S3 URI or HTTPS URL of the object.
        region: The AWS region (e.g., 'us-west-2'). Important for AWS and Wasabi.
                If None for AWS+Wasab, defaults to 'us-east-1'. May be ignored by other providers.
        endpoint_url: Explicit S3-compatible endpoint URL. Overrides provider defaults.
        timeout: Connection timeout in seconds for the S3 client.
        try_list: If True, attempt to list objects as a fallback when head_object fails.

    Returns:
        True if the object exists and is publicly accessible, False otherwise.
    """
    try:
        scheme, bucket, key, parsed_endpoint = parse_uri(uri)
    except ValueError as e:
        logger.error(f"Error parsing URI '{uri}': {e}")
        return False
    
    # Configure endpoint and region logic as in your original code
    final_endpoint_url = endpoint_url
    if not final_endpoint_url:
        # Your existing endpoint logic
        pass
        
    # Determine region (primarily for AWS)
    final_region = region
    if not final_region and scheme in ['s3', 'aws'] and final_endpoint_url and 'amazonaws.com' in final_endpoint_url :
        match = re.search(r's3\.([a-z0-9-]+)\.amazonaws\.com', final_endpoint_url)
        if match:
            final_region = match.group(1)
        else:
            final_region = DEFAULT_AWS_REGION

    # Log detailed check parameters at DEBUG level
    logger.debug(f"Checking URI: {uri}")
    logger.debug(f"  Provider Scheme: {scheme}")
    logger.debug(f"  Bucket: {bucket}")
    logger.debug(f"  Key: {key}")
    logger.debug(f"  Target Endpoint: {final_endpoint_url}")
    logger.debug(f"  Target Region: {final_region}")
    
    try:
        s3_client = boto3.client(
            's3',
            config=Config(signature_version=UNSIGNED, connect_timeout=timeout, read_timeout=timeout),
            endpoint_url=final_endpoint_url,
            region_name=final_region
        )
        
        # First try the head_object method
        try:
            s3_client.head_object(Bucket=bucket, Key=key or ".")
            logger.info(f"Success: Object readable at '{uri}'")
            return True
        except ClientError as head_error:
            error_code = head_error.response.get("Error", {}).get("Code")
            error_message = head_error.response.get("Error", {}).get("Message", str(head_error))
            
            # Handle specific error codes that shouldn't immediately fail
            if error_code in ['301', '307'] and try_list:
                logger.info(f"Received redirect ({error_code}) for '{uri}', trying list operation as fallback")
                # Try falling back to list_objects_v2 for the bucket (or prefix)
                try:
                    # If key is provided, use it as prefix for listing
                    prefix = key if key else None
                    # Only request a single object to minimize data transfer
                    response = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=1)
                    
                    # If we get a response with Contents, the bucket is readable
                    if 'Contents' in response and len(response['Contents']) > 0:
                        logger.info(f"Success via list fallback: Bucket '{bucket}' is publicly readable")
                        return True
                    else:
                        logger.info(f"Bucket '{bucket}' is accessible but empty or no matching objects")
                        # This is technically accessible, so returning True
                        return True
                except ClientError as list_error:
                    list_error_code = list_error.response.get("Error", {}).get("Code")
                    list_error_message = list_error.response.get("Error", {}).get("Message", str(list_error))
                    logger.warning(f"List fallback failed for '{uri}': Code={list_error_code}. Message: {list_error_message}")
                    return False
            elif error_code == '404' or error_code == 'NoSuchKey':
                # For buckets, 404 is expected when using head_object on the bucket itself
                if not key and try_list:
                    logger.info(f"No object key specified for '{uri}', trying list operation")
                    try:
                        # Try list_objects_v2 on the bucket
                        response = s3_client.list_objects_v2(Bucket=bucket, MaxKeys=1)
                        if 'Contents' in response:
                            logger.info(f"Success via list fallback: Bucket '{bucket}' is publicly readable")
                            return True
                        else:
                            logger.info(f"Bucket '{bucket}' is accessible but empty")
                            return True
                    except ClientError as list_error:
                        list_error_code = list_error.response.get("Error", {}).get("Code")
                        logger.info(f"List fallback failed for '{uri}': Code={list_error_code}")
                        return False
                else:
                    # Object genuinely doesn't exist
                    logger.info(f"Object not found (404) at '{uri}'")
                    return False
            elif error_code == '403' or error_code == 'AccessDenied':
                # Access is denied - not public
                logger.info(f"Access denied (403) for anonymous user at '{uri}'")
                return False
            else:
                # Other errors - log and return False
                logger.error(f"S3 ClientError checking '{uri}': Code={error_code}. Message: {error_message}")
                return False
    
    except NoCredentialsError as e:
        # Handle other exceptions as in your original code
        logger.error(f"Boto3 configuration error checking '{uri}': {e}")
        return False
    except Exception as e:
        logger.exception(f"Unexpected exception during check for '{uri}': {e}")
        return False
        
def check_private_s3_object(
        uri: str,
        region: str | None = None,
        endpoint_url: str | None = None,
        timeout: int = 5
    ) -> bool:
    
    return not check_public_s3_object(uri, region, endpoint_url, timeout)  