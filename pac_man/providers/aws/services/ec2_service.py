"""EC2 service abstraction."""

from typing import Any, Dict, List
from .base import AWSServiceBase

class EC2Service(AWSServiceBase):
    """Service class for AWS EC2 operations."""

    def __init__(self, session, region_name=None):
        """
        Initialize EC2 service.

        Args:
            session: Boto3 session
            region_name: Optional region name override
        """
        super().__init__(session, region_name)
        self.client = self._get_client('ec2')

    def revoke_security_group_ingress(self, **kwargs) -> Dict[str, Any]:
        """
        Revoke ingress rules from a security group.

        Args:
            **kwargs: Arguments to pass to the revoke_security_group_ingress API call.

        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            self.client.revoke_security_group_ingress(**kwargs)
            return {'success': True}
        except Exception as e:
            return self._handle_error(e, 'revoke_security_group_ingress')

    def revoke_security_group_egress(self, **kwargs) -> Dict[str, Any]:
        """
        Revoke egress rules from a security group.

        Args:
            **kwargs: Arguments to pass to the revoke_security_group_egress API call.

        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            self.client.revoke_security_group_egress(**kwargs)
            return {'success': True}
        except Exception as e:
            return self._handle_error(e, 'revoke_security_group_egress')

    def authorize_security_group_ingress(self, **kwargs) -> Dict[str, Any]:
        """
        Authorize ingress rules for a security group.

        Args:
            **kwargs: Arguments to pass to the authorize_security_group_ingress API call.

        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            self.client.authorize_security_group_ingress(**kwargs)
            return {'success': True}
        except Exception as e:
            return self._handle_error(e, 'authorize_security_group_ingress')

    def authorize_security_group_egress(self, **kwargs) -> Dict[str, Any]:
        """
        Authorize egress rules for a security group.

        Args:
            **kwargs: Arguments to pass to the authorize_security_group_egress API call.

        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            self.client.authorize_security_group_egress(**kwargs)
            return {'success': True}
        except Exception as e:
            return self._handle_error(e, 'authorize_security_group_egress')
    
    def list_active_regions(self) -> Dict[str, Any]:
        """
        List all active AWS regions.
        
        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - regions (List[str]): List of active region names if successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            # Get all regions including opt-in regions
            response = self.client.describe_regions(AllRegions=True)
            
            # Filter for active regions (opt-in-not-required or opted-in)
            active_regions = [
                region['RegionName']
                for region in response['Regions']
                if region['OptInStatus'] in ['opt-in-not-required', 'opted-in']
            ]
            
            # Sort regions for consistent ordering
            active_regions.sort()
            
            return {
                'success': True,
                'regions': active_regions
            }
            
        except Exception as e:
            return self._handle_error(e, 'list_active_regions')
        
    def describe_flow_logs(self, **kwargs) -> Dict[str, Any]:
        """
        Describe VPC flow logs.

        Args:
            **kwargs: Arbitrary keyword arguments to pass to the describe_flow_logs API call.

        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - FlowLogs (List[Dict]): List of flow log configurations if successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            response = self.client.describe_flow_logs(**kwargs)

            return {
                'success': True,
                'FlowLogs': response.get('FlowLogs', [])
            }
        except Exception as e:
            return self._handle_error(e, 'describe_flow_logs')


    def describe_vpcs(self) -> Dict[str, Any]:
        """
        Describe VPCs in the current region.

        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - Vpcs (List[Dict]): List of VPC configurations if successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            response = self.client.describe_vpcs()
            
            return {
                'success': True,
                'Vpcs': response.get('Vpcs', [])
            }
        except Exception as e:
            return self._handle_error(e, 'describe_vpcs')
        
    def create_flow_logs(self, ResourceIds: List[str], ResourceType: str, TrafficType: str, 
                         LogDestinationType: str, DeliverLogsPermissionArn: str, LogGroupName: str) -> Dict[str, Any]:
        try:
            response = self.client.create_flow_logs(
                ResourceIds=ResourceIds,
                ResourceType=ResourceType,
                TrafficType=TrafficType,
                LogDestinationType=LogDestinationType,
                DeliverLogsPermissionArn=DeliverLogsPermissionArn,
                LogGroupName=LogGroupName
            )
            return {
                'success': True,
                'FlowLogIds': response.get('FlowLogIds', [])
            }
        except Exception as e:
            return self._handle_error(e, 'create_flow_logs')

    def is_subnet_public(self, subnet_id, vpc_id):
        client = self.session.client('ec2')
        
        # Check subnet route table
        response = client.describe_route_tables(
            Filters=[
                {'Name': 'association.subnet-id', 'Values': [subnet_id]}
            ]
        )
        
        if response['RouteTables']:
            route_table = response['RouteTables'][0]
        else:
            # If no specific route table, check the main route table of the VPC
            response = client.describe_route_tables(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'association.main', 'Values': ['true']}
                ]
            )
            if response['RouteTables']:
                route_table = response['RouteTables'][0]
            else:
                return False  # No route table found, assume private
        
        # Check if there's a route to an Internet Gateway
        for route in route_table['Routes']:
            if route.get('GatewayId', '').startswith('igw-'):
                return True
        
        return False
    
    def describe_security_groups(self, **kwargs) -> Dict[str, Any]:
        """
        Describe EC2 security groups.

        Args:
            **kwargs: Additional arguments to pass to the describe_security_groups API call.

        Returns:
            Dict[str, Any]: A dictionary containing the API response.
        """
        try:
            response = self.client.describe_security_groups(**kwargs)
            return {'success': True, 'SecurityGroups': response['SecurityGroups']}
        except Exception as e:
            return self._handle_error(e, 'describe_security_groups')
        
    def update_security_group_rules(self, group_id, ip_permissions, rule_type='egress'):
        """
        Update the rules of a security group.

        :param group_id: The ID of the security group to update
        :param ip_permissions: The new set of IP permissions
        :param rule_type: The type of rules to update ('ingress' or 'egress')
        """
        try:
            # Handle different types of rule_type input
            if isinstance(rule_type, list):
                rule_type = rule_type[0] if rule_type else 'egress'
            elif isinstance(rule_type, bool):
                rule_type = 'ingress' if rule_type else 'egress'

            rule_type = str(rule_type).lower()

            if rule_type == 'ingress':
                self.client.revoke_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=ip_permissions
                )
                self.client.authorize_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=ip_permissions
                )
            elif rule_type == 'egress':
                self.client.revoke_security_group_egress(
                    GroupId=group_id,
                    IpPermissions=ip_permissions
                )
                self.client.authorize_security_group_egress(
                    GroupId=group_id,
                    IpPermissions=ip_permissions
                )
            else:
                raise ValueError("Invalid rule_type. Must be 'ingress' or 'egress'.")
            return True
        except self.client.exceptions.ClientError as e:
            self.logger.error(f"Error updating security group rules: {e}")
            return False


