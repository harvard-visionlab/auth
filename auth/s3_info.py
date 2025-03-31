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

__all__ = [
    'create_s3_client',
    'check_public_s3_object',
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

def create_s3_client(s3_path, region=None, endpoint_url=None, profile=None):
    """
    Constructs and returns a boto3 S3 client based on access type.

    :param s3_path: The S3 path being accessed (for logging purposes).
    :return: A boto3 S3 client instance, or None if client creation fails.
    """

    # First, check if the object is public
    try:
        scheme, bucket_name, object_key, _ = parse_uri(s3_path)
    except ValueError as e:
        logger.error(f"Error parsing URI '{s3_path}': {e}")
        return False

    is_public = check_public_s3_object(s3_path, region=region, endpoint_url=endpoint_url)
    
    if is_public:
        # Public access: initialize client without credentials.
        if endpoint_url is None:
            endpoint_url = S3_PROVIDER_ENDPOINT_URLS.get(scheme)
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
        creds = get_aws_credentials(profile)
        if not creds:
            logger.error(
                f"Could not retrieve AWS credentials for accessing '{s3_path}'. "
                f"Ensure profile '{profile}' is configured correctly."
            )
            return None

        # Use passed endpoint_url if provided; otherwise, try credentials or fallback.
        if endpoint_url is None:
            endpoint_url = creds.get('endpoint_url', S3_PROVIDER_ENDPOINT_URLS.get(scheme))
        try:
            client = boto3.client(
                's3',
                region_name=region,
                aws_access_key_id=creds["aws_access_key_id"],
                aws_secret_access_key=creds["aws_secret_access_key"],
                aws_session_token=creds.get("aws_session_token"),
                endpoint_url=creds.get("endpoint_url") if not endpoint_url else endpoint_url
            )
            return client
        except Exception as e:
            logger.error(f"Error creating authenticated S3 client for '{s3_path}': {e}", exc_info=True)
            return None
            

def check_private_s3_object(
        uri: str,
        region: str | None = None,
        endpoint_url: str | None = None,
        timeout: int = 5
    ) -> bool:
    
    return not check_public_s3_object(uri, region, endpoint_url, timeout)
    
def check_public_s3_object(
    uri: str,
    region: str | None = None,
    endpoint_url: str | None = None,
    timeout: int = 5
) -> bool:
    """
    Checks if an S3-like object is publicly readable via anonymous S3 API call.
    Uses standard Python logging for output. Configure logging level externally.

    Args:
        uri: The S3 URI or HTTPS URL of the object.
        region: The AWS region (e.g., 'us-west-2'). Important for AWS.
                If None for AWS, defaults to 'us-east-1'. May be ignored by other providers.
        endpoint_url: Explicit S3-compatible endpoint URL. Overrides provider defaults.
        timeout: Connection timeout in seconds for the S3 client.

    Returns:
        True if the object exists and head_object succeeds anonymously, False otherwise.

    Raises:
        ValueError: If the URI format is invalid (if not caught internally).
                     Currently, it logs error and returns False.
    """
    try:
        scheme, bucket, key, parsed_endpoint = parse_uri(uri)
    except ValueError as e:
        # Log parsing errors as ERROR
        logger.error(f"Error parsing URI '{uri}': {e}")
        return False

    # Determine endpoint URL
    final_endpoint_url = endpoint_url # User override takes precedence
    if not final_endpoint_url:
        if scheme in ['http', 'https'] and parsed_endpoint:
            final_endpoint_url = parsed_endpoint
        elif scheme in S3_PROVIDER_ENDPOINT_URLS:
            final_endpoint_url = S3_PROVIDER_ENDPOINT_URLS[scheme]
        elif scheme not in ['http', 'https']: # Unknown scheme, but provider-like
            # Log endpoint warnings as WARNING
            logger.warning(f"No endpoint configured for scheme '{scheme}' in URI '{uri}'. Attempting without specific endpoint.")
            final_endpoint_url = None # Let boto3 try default resolution

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
        s3_client.head_object(Bucket=bucket, Key=key)
        # Log success at INFO level (or DEBUG if you prefer)
        logger.info(f"Success: Object readable at '{uri}'")
        # logger.debug(f"  Success details: Object '{key}' in bucket '{bucket}' is publicly readable via S3 API.")
        return True

    except (ClientError, NoCredentialsError) as e:
        if isinstance(e, ClientError):
            error_code = e.response.get("Error", {}).get("Code")
            error_message = e.response.get("Error", {}).get("Message", str(e))
            if error_code == '404' or error_code == 'NoSuchKey':
                # Log not found as INFO or WARNING - it's a valid check result, not necessarily an error in the *checker*. Let's use INFO.
                logger.info(f"Object not found (404) at '{uri}'. Message: {error_message}")
            elif error_code == '403' or error_code == 'AccessDenied':
                # Log access denied as INFO - also a valid check result.
                logger.info(f"Access denied (403) for anonymous user at '{uri}'. Message: {error_message}")
            elif error_code == '301' and 'Endpoint' in e.response.get("Error", {}):
                wrong_region_endpoint = e.response['Error']['Endpoint']
                # Log redirects as WARNING as they indicate potential misconfiguration
                logger.warning(f"Permanent redirect (301) checking '{uri}', possibly wrong region. Suggested endpoint: {wrong_region_endpoint}. Message: {error_message}")
            else:
                # Log other S3 client errors as ERROR
                logger.error(f"S3 ClientError checking '{uri}': Code={error_code}. Message: {error_message}", exc_info=True) # exc_info adds traceback
        elif isinstance(e, NoCredentialsError):
             # This is unexpected with UNSIGNED, log as ERROR
             logger.error(f"Boto3 configuration error (NoCredentialsError) checking '{uri}': {e}", exc_info=True)
        else:
             # Log unexpected boto errors as ERROR
             logger.error(f"Unexpected Boto3/Botocore error checking '{uri}': {e}", exc_info=True)
        return False
    except Exception as e:
        # Log other unexpected exceptions as ERROR. Use logger.exception for traceback.
        logger.exception(f"Unexpected exception during check for '{uri}': {e}")
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