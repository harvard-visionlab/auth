import os
import subprocess
import logging
from pdb import set_trace

from ..s3_auth import (
    get_s5cmd_options, 
    get_s5cmd_options_with_provider_hint
)
from ..s3_public import check_public_s3_object
    
from visionlab.auth.utils import normalize_uri, parse_uri

logger = logging.getLogger(__name__) # Use module name for clarity

__all__ = ['list_bucket']

def list_bucket(uri, profile=None, storage_options=None, verbose=True,
                no_signed_option=None, endpoint_option=None,
                endpoint_url=None):

    provider, bucket_name, object_key, _ = parse_uri(uri)
    s3_uri = normalize_uri(uri)    

    # copy current env
    env = os.environ.copy()

    # profile credentials can override env variables & endpoint_url
    if profile is not None:
        # use the provided profile
        aws_env,endpoint_url = get_s5cmd_options(profile=profile)            
    else:
        # no profile provided; check default profile names
        # check for wasabi credentials in the ~/.aws/credentials file
        aws_env,endpoint_url = get_s5cmd_options_with_provider_hint(provider)

    # update env variables
    if aws_env:
        env.update(aws_env)
        
    # storage_options can override env variables & endpoint_url
    if storage_options:
        # endpoint_url and no_signed_option cannot be set via env variables
        # later we'll add them to the cmd manually:
        endpoint_url = storage_options.pop('endpoint_url', endpoint_url)
        no_signed_option = storage_options.pop('no_signed_option', no_signed_option)

        # AWS_ACCESS_KEY_ID and AWS_SECRET_KEY and AWS_REGION can be set as env
        env.update(storage_options)        

    # prepare the s5cmd command
    if no_signed_option or check_public_s3_object(s3_uri, endpoint_url=endpoint_url):
        no_signed_option = "--no-sign-request"

    if endpoint_url:
        endpoint_option = f"--endpoint-url {endpoint_url}"

    cmd_parts = ["s5cmd", 
                 no_signed_option, 
                 endpoint_option, 
                 "ls", 
                 s3_uri]
    cmd = " ".join(part for part in cmd_parts if part)
    logger.info(cmd)
    
    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    
    # Capture the output and errors
    output, errors = proc.communicate()
    
    # Print the bucket contents (stdout)
    if output and verbose:
        print(f"{s3_uri}")
        for line in output.decode('utf-8').splitlines():
            print(f"    {line.lstrip()}")
    
    # Optionally, print errors if any
    if errors and verbose:
        print(errors.decode('utf-8'))
    
    return proc.returncode==0