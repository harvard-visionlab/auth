import os
import boto3
from botocore.configloader import load_config

__all__ = [
    'get_aws_credentials', 
    'get_storage_options',
    'get_s5cmd_options'
]
            
def get_aws_credentials(profile=None, endpoint_url=None, region='us-east-1'):
    """
    Retrieve AWS credentials from a boto3 session or from a credentials file.
    
    If profile is None, returns default credentials from boto3.Session().
    
    If a profile is specified:
      - If the profile is found in the credentials file, use its values.
      - If not found and the profile name is all uppercase, then check
        environment variables:
            AWS_ACCESS_KEY_ID_{PROFILE}
            AWS_SECRET_ACCESS_KEY_{PROFILE}
            AWS_REGION_{PROFILE} (or AWS_REGION)
            AWS_ENDPOINT_URL_{PROFILE} (or AWS_ENDPOINT_URL)
    
    The returned dictionary will only include the 'region' and 'endpoint_url'
    keys if their corresponding values are not None.
    
    Returns:
        dict: Dictionary containing 'aws_access_key_id', 'aws_secret_access_key',
              and, if available, 'region' and 'endpoint_url'.
    """
    if profile is None:
        # Use boto3's default session credentials.
        session = boto3.Session()
        creds = session.get_credentials()
        frozen_creds = creds.get_frozen_credentials() if creds else None
        if not frozen_creds or not frozen_creds.access_key or not frozen_creds.secret_key:
            raise ValueError("Default AWS credentials not found in boto3 session")
            
        region = session.region_name or os.environ.get("AWS_REGION", region)        
        endpoint_url = os.environ.get("AWS_ENDPOINT_URL", endpoint_url)
        
        ret = {
            'aws_access_key_id': frozen_creds.access_key,
            'aws_secret_access_key': frozen_creds.secret_key,
            'region': region,            
        }        
        if endpoint_url is not None:
            ret['endpoint_url'] = endpoint_url
        return ret

    profile_name = profile
    # Get the credentials file path (default: ~/.aws/credentials)
    credentials_path = os.environ.get('AWS_SHARED_CREDENTIALS_FILE', os.path.expanduser('~/.aws/credentials'))
    config = load_config(credentials_path)

    if profile_name not in config:
        # If profile is all uppercase, try reading credentials from environment variables.
        if profile_name.isupper():
            aws_access_key_id = os.getenv(f"AWS_ACCESS_KEY_ID_{profile_name}", None)
            aws_secret_access_key = os.getenv(f"AWS_SECRET_ACCESS_KEY_{profile_name}", None)
            region = os.getenv(f"AWS_REGION_{profile_name}", os.environ.get("AWS_REGION", region))
            endpoint_url = os.getenv(f"AWS_ENDPOINT_URL_{profile_name}", os.environ.get("AWS_ENDPOINT_URL", endpoint_url))
            
            if not aws_access_key_id or not aws_secret_access_key:
                raise ValueError(f"Missing required credentials in environment variables for profile '{profile_name}'; AWS_ACCESS_KEY_ID_{profile.upper()} and AWS_SECRET_ACCESS_KEY_{profile.upper()}.")
            
            ret = {
                'aws_access_key_id': aws_access_key_id,
                'aws_secret_access_key': aws_secret_access_key,
                'region': region
            }            
            if endpoint_url is not None:
                ret['endpoint_url'] = endpoint_url
            return ret
        else:
            return {}
            # raise ValueError(f"Profile '{profile_name}' not found in credentials file; to specify as env variables, use all_caps AWS_ACCESS_KEY_ID_{profile.upper()} and AWS_SECRET_ACCESS_KEY_{profile.upper()}.")

    # Profile found in credentials file.
    profile_config = config[profile_name]
    aws_access_key_id = profile_config.get('aws_access_key_id')
    aws_secret_access_key = profile_config.get('aws_secret_access_key')
    region = profile_config.get('region', region)
    endpoint_url = profile_config.get('endpoint_url', endpoint_url)
    
    # Check for service-specific endpoint_url overrides (e.g., for s3)
    for service in ['s3']:
        if service in profile_config:
            service_config = profile_config[service]
            if 'region' in service_config:
                region = service_config['region']
            if 'endpoint_url' in service_config:
                endpoint_url = service_config['endpoint_url']
                break
    
    if not aws_access_key_id or not aws_secret_access_key:
        raise ValueError(f"Missing required credentials in profile '{profile_name}'")

    ret = {
        'aws_access_key_id': aws_access_key_id,
        'aws_secret_access_key': aws_secret_access_key
    }
    if region is not None:
        ret['region'] = region
    if endpoint_url is not None:
        ret['endpoint_url'] = endpoint_url

    return ret
            
def get_storage_options(profile=None):
    creds = get_aws_credentials(profile)
    ret = {
        "aws_access_key_id": creds['aws_access_key_id'],
        "aws_secret_access_key": creds['aws_secret_access_key'],
    }
    if 'endpoint_url' in creds:
        ret['endpoint_url'] = creds['endpoint_url']
    return ret

def get_s5cmd_options(profile=None):
    creds = get_aws_credentials(profile)
    env = None
    aws_access_key_id = creds.get('aws_access_key_id')
    aws_secret_access_key = creds.get('aws_secret_access_key')
    endpoint_url = creds.get('endpoint_url')
    region = creds.get('region')
    if aws_access_key_id is not None and aws_secret_access_key is not None:
        env = {
            "AWS_ACCESS_KEY_ID": aws_access_key_id,
            "AWS_SECRET_ACCESS_KEY": aws_secret_access_key
        }
        if region:
            env['AWS_REGION'] = region
    return env, endpoint_url