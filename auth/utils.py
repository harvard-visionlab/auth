from urllib.parse import urlparse
from pathlib import Path

S3_PROVIDER_ENDPOINT_URLS = {
    "s3": "https://s3.amazonaws.com",
    "aws": "https://s3.amazonaws.com",
    "wasabi": "https://s3.wasabisys.com",
    "wasabi-admin": "https://s3.wasabisys.com",
    "machina": "https://s3.machina.fas.harvard.edu",
    "valis": "https://s3.valis.fas.harvard.edu"
}

DEFAULT_AWS_REGION = "us-east-1"

def parse_uri(uri: str) -> tuple[str, str, str, str | None]:
    """
    Parses various URI formats to extract scheme, bucket, key, and potential endpoint.

    Args:
        uri: The input URI/URL string.

    Returns:
        tuple: (scheme, bucket, key, endpoint_hint)
        endpoint_hint is derived if URI is http/https, otherwise None.

    Raises:
        ValueError: If the URI format is invalid or essential parts are missing.
    """
    parsed = urlparse(uri)
    scheme = parsed.scheme.lower()
    endpoint_hint = None

    if not scheme:
        raise ValueError(f"Invalid URI: Missing scheme (e.g., 's3://', 'https://'): {uri}")

    if scheme in ['http', 'https']:
        endpoint_hint = f"{parsed.scheme}://{parsed.netloc}"
        # Path style: https://s3.amazonaws.com/bucket/key
        if parsed.netloc.startswith("s3.") or any(ep_url.endswith(parsed.netloc) for ep_url in S3_PROVIDER_ENDPOINT_URLS.values()):
             path_parts = parsed.path.lstrip('/').split('/', 1)
             if len(path_parts) >= 1 and path_parts[0]:
                 bucket = path_parts[0]
                 key = path_parts[1] if len(path_parts) > 1 else ""
             else:
                 raise ValueError(f"Invalid path-style URL: Cannot extract bucket: {uri}")
        # Virtual hosted style: https://bucket.s3.amazonaws.com/key
        elif ".s3." in parsed.netloc or any(f".{ep_domain}" in parsed.netloc for ep_domain in [urlparse(url).netloc for url in S3_PROVIDER_ENDPOINT_URLS.values() if url]): # Check against known endpoint domains
             # Basic assumption: bucket is the first part of the hostname
             # This might need refinement for complex endpoint structures
             potential_bucket = parsed.netloc.split('.')[0]
             # Heuristic: Check if removing bucket name matches a known endpoint more closely
             # This part is tricky and might require more sophisticated logic or provider-specific parsing
             # For now, we assume bucket is the first part before a known domain part
             bucket = potential_bucket # Simplified assumption
             key = parsed.path.lstrip('/')
             # Refine endpoint_hint to exclude the bucket part
             endpoint_hint = f"{parsed.scheme}://{parsed.netloc.replace(f'{bucket}.', '', 1)}"
        else:
            # Assume generic https URL might follow path style implicitly
            # Or treat netloc as bucket if path seems like a key? Needs clarification.
            # Let's assume path style as a fallback guess
            path_parts = parsed.path.lstrip('/').split('/', 1)
            if len(path_parts) >= 1 and path_parts[0]:
                 bucket = path_parts[0]
                 key = path_parts[1] if len(path_parts) > 1 else ""
            elif parsed.netloc: # Maybe netloc is the bucket? https://bucket/key - non-standard
                bucket = parsed.netloc
                key = parsed.path.lstrip('/')
            else:
                 raise ValueError(f"Unrecognized HTTPS URL format: {uri}")

    elif scheme in S3_PROVIDER_ENDPOINT_URLS:
        bucket = parsed.netloc
        key = parsed.path.lstrip('/')
        if not bucket:
            raise ValueError(f"Invalid S3-like URI: Bucket name missing: {uri}")
    else:
        # Fallback for unknown schemes: treat as provider://bucket/key
        bucket = parsed.netloc
        key = parsed.path.lstrip('/')
        if not bucket:
             raise ValueError(f"Invalid URI: Bucket name missing for scheme '{scheme}': {uri}")
        print(f"Warning: Unrecognized scheme '{scheme}'. Assuming format 'scheme://bucket/key'.")
        
    return scheme, bucket, key, endpoint_hint
    
def normalize_uri(uri):
    """Normalize the URI to use the s3:// prefix."""
    _, bucket, prefix, _ = parse_uri(uri)
    return f"s3://{bucket}/{prefix}"
    
def split_name(path: Path):
    """Split a path into the stem and the complete extension (all suffixes)."""
    path = Path(path)
    suffixes = path.suffixes
    if suffixes:
        ext = "".join(suffixes)
        stem = path.name[:-len(ext)]
    else:
        ext = ""
        stem = path.name
    return stem, ext