# providers/gcp/gcp_provider.py

from providers.provider import Provider

class GCPProvider(Provider):
    """GCP-specific implementation of the Provider class."""

    def __init__(self, region=None):
        """
        Initialize the GCP provider with the specific GCP region.
        If no region is provided, use a default region.
        :param region: GCP region (e.g., 'us-central1')
        """
        default_region = 'us-central1'  # Define the default GCP region
        region = region if region else default_region
        super().__init__(name='gcp', region=region)

    def authenticate(self):
        """Authenticate to GCP."""
        print(f"Authenticating to GCP in region {self.region}")

    def load_checks(self):
        """Load GCP-specific security checks."""
        print("Loading GCP security checks")

    def execute_checks(self):
        """Execute GCP-specific security checks."""
        print("Executing GCP security checks")

