from .base import AWSServiceBase

class RDSService(AWSServiceBase):
    def describe_db_instances(self):
        client = self.session.client('rds')
        response = client.describe_db_instances()
        return response['DBInstances']
    
    def modify_db_instance(self, instance_id, publicly_accessible, apply_immediately):
        client = self.session.client('rds')
        response = client.modify_db_instance(
            DBInstanceIdentifier=instance_id,
            PubliclyAccessible=publicly_accessible,
            ApplyImmediately=apply_immediately
        )
        return response