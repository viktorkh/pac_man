class Provider:
    """Base class for cloud providers."""

    def __init__(self, name, region=None):
        """
        Initialize the provider with a name and optional region.
        :param name: Name of the cloud provider (e.g., 'aws', 'gcp')
        :param region: Cloud region (optional)
        """
        self.name = name
        self.region = region

    def authenticate(self):
        """
        Authenticate the provider. Should be implemented by subclasses.
        """
        raise NotImplementedError("This method should be implemented by a cloud provider subclass")

    def load_checks(self):
        """
        Load security checks specific to the provider. Should be implemented by subclasses.
        """
        raise NotImplementedError("This method should be implemented by a cloud provider subclass")

    def execute_checks(self):
        """
        Execute security checks. Should be implemented by subclasses.
        """
        raise NotImplementedError("This method should be implemented by a cloud provider subclass")
    
    def execute_fixers(self, findings, logger):
        """
        Execute fixers for failed checks. Should be implemented by subclasses.
        :param findings: List of CheckResult objects
        :param logger: Logger object for logging messages
        """
        raise NotImplementedError("This method should be implemented by a cloud provider subclass")

    def __str__(self):
        return f"{self.name} provider in region {self.region}"
