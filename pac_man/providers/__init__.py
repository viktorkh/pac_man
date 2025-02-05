from providers.aws.aws_provider import AWSProvider
from providers.gcp.gcp_provider import GCPProvider

def get_provider(provider_name, profile=None, region=None, whitelist_file=None):
    """
    Factory function to get the appropriate cloud provider instance.
    
    Args:
        provider_name: Name of the cloud provider ('aws' or 'gcp')
        profile: Cloud provider profile to use (optional)
        region: Cloud region to use (optional)
        whitelist_file: Path to custom whitelist YAML file (optional)
        
    Returns:
        Instance of the appropriate Provider class
        
    Raises:
        ValueError: If an unsupported provider is specified
    """
    if provider_name.lower() == 'aws':
        return AWSProvider(profile=profile, region=region, whitelist_file=whitelist_file)
    elif provider_name.lower() == 'gcp':
        return GCPProvider(profile=profile, region=region)
    else:
        raise ValueError(f"Unsupported provider: {provider_name}")
