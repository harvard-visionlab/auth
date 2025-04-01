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

from .utils import S3_PROVIDER_ENDPOINT_URLS, DEFAULT_AWS_REGION, parse_uri, normalize_uri
from .s3_auth import get_aws_credentials
from .s3_public import check_public_s3_object
from .s3_client import create_s3_client

__all__ = [
    # 'create_s3_client',
    'check_s3_file_access',
    'count_objects_in_bucket_prefix',
    'list_objects_in_bucket_prefix',
    # 'is_bucket_file',
]

# Get a logger for this module
logger = logging.getLogger(__name__) # Use module name for clarity

def _log_s3_client_error(e: ClientError, s3_path: str) -> bool:
    """Logs ClientError exceptions from boto3 in a consistent format."""
    error_code = e.response.get("Error", {}).get("Code")
    error_message = e.response.get("Error", {}).get("Message", str(e))
    if error_code == '404' or error_code == 'NoSuchKey':
        logger.info(
            f"Object not found (404) at '{s3_path}'. "
            f"Message: {error_message}"
        )
        return False
    elif error_code == '403' or error_code == 'AccessDenied':
        logger.info(
            f"Access denied (403) for '{s3_path}'. "
            f"Message: {error_message}"
        )
        return False
    elif error_code == '301' and 'Endpoint' in e.response.get("Error", {}):
        wrong_region_endpoint = e.response['Error']['Endpoint']
        logger.warning(
            f"Permanent redirect (301) checking '{s3_path}', "
            f"possibly wrong region. "
            f"Suggested endpoint: {wrong_region_endpoint}. "
            f"Message: {error_message}"
        )
        return False
    else:
        logger.error(
            f"S3 ClientError checking '{s3_path}': "
            f"Code={error_code}. "
            f"Message: {error_message}",
            exc_info=True
        )
        return False

def construct_s3_url_from_s3_uri(s3_path, endpoint_url=None, region=None):
    """Convert s3://bucket-name/object-key into an endpoint_url/bucket-name/bucket-key url
        If s3_path is already an http(s) url, pass it through
    """
    try:
        scheme, bucket_name, object_key, _ = parse_uri(s3_path)
    except ValueError as e:
        raise ValueError(f"Invalid S3 path format: {e}")

    if bucket_name is None or object_key is None:
        raise ValueError(f"Invalid S3 path format: {s3_path} (bucket or key missing)")
    
    if scheme.startswith("http"):
        s3_url = s3_path
    else:
        if endpoint_url is None:
            if not scheme in S3_PROVIDER_ENDPOINT_URLS:
                raise ValueError(f"Unknown s3 provider: {scheme}. Pass in and `endpoint_url` for this provider, or modify s3_info.py to include it.")
                
            endpoint_url = S3_PROVIDER_ENDPOINT_URLS[scheme]
            
        if region is not None:
            endpoint_url = endpoint_url.replace("s3.", f"s3.{region}.")
            
        s3_url = f"{endpoint_url.rstrip('/')}/{bucket_name.rstrip('/')}/{object_key.rstrip('/')}"

    return s3_url
    
def check_public_url(url, timeout=5):
    try:
        # Perform a HEAD request to check if the object is publicly accessible
        response = requests.head(url, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException as e:
        print(f"Error checking object at URL {public_url}: {e}")
        return False
        
def check_s3_file_access(s3_path, endpoint_url=None, region=None, profile=None):

    # First, check if the object is public
    try:
        scheme, bucket_name, object_key, _ = parse_uri(s3_path)
    except ValueError as e:
        logger.error(f"Error parsing URI '{s3_path}': {e}")
        return False

    is_public = check_public_s3_object(s3_path, region=region, endpoint_url=endpoint_url)
    
    if is_public:        
        # Public access: Initialize the S3 client without credentials
        if endpoint_url is None:
            endpoint_url = S3_PROVIDER_ENDPOINT_URLS.get(scheme)            
        try:
            s3 = boto3.client('s3',
                                    region_name=region,
                                    endpoint_url=endpoint_url,
                                    config=Config(signature_version=UNSIGNED))
        except Exception as e:
            logger.error(f"Error creating anonymous S3 client for '{s3_path}': {e}", exc_info=True)
            return False
    else:
        # If private, retrieve AWS credentials using the helper
        creds = get_aws_credentials(profile)
        if not creds:
            logger.error(
                f"Could not retrieve AWS credentials for accessing '{s3_path}'. "
                f"Ensure profile '{profile}' is configured correctly."
            )
            return False

        # passed endpoint_url takes precedence
        if endpoint_url is None:
            # use endpoint_url from credentials; fallback to S3_PROVIDER_ENDPOINT_URLS[scheme]
            endpoint_url = creds.get('endpoint_url', S3_PROVIDER_ENDPOINT_URLS.get(scheme))
        
        try:
            s3 = boto3.client(
                's3',
                region_name=region,
                aws_access_key_id=creds["aws_access_key_id"],
                aws_secret_access_key=creds["aws_secret_access_key"],
                aws_session_token=creds.get("aws_session_token"),
                endpoint_url=creds.get("endpoint_url") if not endpoint_url else endpoint_url
            )
        except Exception as e:
            logger.error(f"Error creating authenticated S3 client for '{s3_path}': {e}", exc_info=True)
            return False
    

    try:
        # Attempt to retrieve the file metadata to check its existence
        # This will raise an exception if the object doesn't exist or access is denied
        response = s3.head_object(Bucket=bucket_name, Key=object_key)
        logger.info(f"Access granted for '{s3_path}'")
        return True
    except ClientError as e:
        return _log_s3_client_error(e, s3_path)
    except NoCredentialsError as e:
        logger.error(
            f"Boto3 configuration error (NoCredentialsError) checking '{s3_path}': "
            f"{e}",
            exc_info=True
        )
        return False
    except Exception as e:
        logger.exception(
            f"Unexpected exception during access check for '{s3_path}': "
            f"{e}"
        )
        return False
            
def list_objects_in_bucket_prefix(s3_client, bucket_name, prefix):
    objects = []
    while True:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    
        if 'Contents' in response:        
            for content in response['Contents']:
                if content['Size'] > 0:
                    objects.append(content['Key'])
                    
        if 'NextContinuationToken' in response:
            kwargs['ContinuationToken'] = response['NextContinuationToken']
        else:
            break
    
    return objects

def count_objects_in_bucket_prefix(s3_client, bucket_name, prefix):
    objects = list_objects_in_bucket_prefix(s3_client, bucket_name, prefix)    
    return len(objects)