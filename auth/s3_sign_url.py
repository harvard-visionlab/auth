from urllib.parse import urlparse, urljoin

from .s3_client import create_s3_client
from .s3_info import check_public_s3_object
from .utils import S3_PROVIDER_ENDPOINT_URLS, parse_uri

__all__ = ['convert_to_http_url', 'sign_url_if_needed']

def convert_to_http_url(url, region=None):
    parse = urlparse(url)
    if parse.scheme.startswith('http'):
        return url
    elif parse.scheme in S3_PROVIDER_ENDPOINT_URLS:
        endpoint_url = S3_PROVIDER_ENDPOINT_URLS[parse.scheme]
        if region is not None:
            endpoint_url = endpoint_url.replace("s3.", f"s3.{region}.")
        scheme, bucket_name, object_key, _ = parse_uri(url)
        return "/".join([endpoint_url, bucket_name, object_key]) 
    else:
        raise ValueError(f"Unrecognized scheme: {parse}")

def standardize_s3_url(s3_url):
    _, bucket_name, _, _ = parse_uri(s3_url)
    parsed = urlparse(s3_url)
    if parsed.netloc.startswith(bucket_name):
        netloc = parsed.netloc.replace(f"{bucket_name}.", "")
        path = "/" + bucket_name + parsed.path
        s3_url = s3_url.replace(f"{parsed.netloc}{parsed.path}",
                                f"{netloc}{path}")
    return s3_url
    
def sign_url_if_needed(url, expires_in_seconds=3600, s3_config=None):
    
    # skip if this isn't an s3 object
    parsed = urlparse(url)
    if parsed.scheme.startswith('http') and not parsed.netloc.startswith("s3"):
        # this is not an s3 url
        return url

    # convert from s3:// to https:// if needed:
    s3_client = create_s3_client(url, s3_config=s3_config)
    s3_url = convert_to_http_url(url)
    _, bucket_name, bucket_key, _ = parse_uri(s3_url)
    signed_url = s3_client.generate_presigned_url('get_object', 
                                                  Params={'Bucket': bucket_name, 
                                                          'Key': bucket_key},
                                                  ExpiresIn=expires_in_seconds,
                                                  HttpMethod='GET')
    return signed_url