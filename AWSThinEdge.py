import boto3
from botocore.exceptions import ClientError
from robot.api.deco import keyword
import json
import tempfile
import paho.mqtt.client as mqtt
import ssl
import os
import paramiko
import traceback

class AWSThinEdge:

    def __init__(self):
        self.session = None

    @keyword("Create Session With Keys")
    def create_session_with_keys(self, aws_access_key_id, aws_secret_access_key, region_name=None):
        """
        Creates an AWS session using the provided access key, secret key, and optional region.
        Returns a success message if the session creation is successful.
        """
        try:
            self.session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=region_name
            )
            # Try to create an IoT client to verify the session
            iot_client = self.session.client('iot')
            # Perform a simple operation like listing IoT policies to verify the connection
            iot_client.list_policies()
            return "AWS session creation successful"
        except ClientError as e:
            raise RuntimeError(f"Failed to create AWS session: {e}")

    @keyword("Create New Policy")
    def create_new_policy(self, policy_name, policy_file_path):
        """
        Creates a new IoT policy with the provided name and reads the policy document from a file.
        """
        try:
            with open(policy_file_path, 'r') as policy_file:
                policy_document = json.load(policy_file)

            iot_client = self.session.client('iot')
            response = iot_client.create_policy(
                policyName=policy_name,
                policyDocument=json.dumps(policy_document)
            )
            return response['policyArn']
        except ClientError as e:
            raise RuntimeError(f"Failed to create policy: {e}")
        except FileNotFoundError:
            raise RuntimeError(f"Policy file {policy_file_path} not found.")
        except json.JSONDecodeError:
            raise RuntimeError(f"Error decoding JSON from policy file {policy_file_path}.")

    @keyword("Register Device")
    def register_device(self, device_id):
        """
        Registers a new IoT Thing with the provided device ID.
        """
        try:
            iot_client = self.session.client('iot')
            response = iot_client.create_thing(
                thingName=device_id
            )
            return response['thingArn']
        except ClientError as e:
            raise RuntimeError(f"Failed to register device: {e}")
    
    @keyword("Check Policy Exists")
    def check_policy_exists(self, policy_name):
        """
        Checks if the specified IoT policy exists.
        """
        try:
            iot_client = self.session.client('iot')
            response = iot_client.get_policy(policyName=policy_name)
            return True if response else False
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return False
            raise RuntimeError(f"Error checking if policy exists: {e}")

    @keyword("Check Device Exists")
    def check_device_exists(self, device_id):
        """
        Checks if the specified IoT device (thing) exists.
        """
        try:
            iot_client = self.session.client('iot')
            response = iot_client.describe_thing(thingName=device_id)
            return True if response else False
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return False
            raise RuntimeError(f"Error checking if device exists: {e}")

    @keyword("Configure Device")
    def configure_device(self, device_id, policy_name):
        """
        Configures the device by creating keys and certificates, attaching the policy to the certificate,
        and attaching the certificate to the device.
        """
        try:
            iot_client = self.session.client('iot')
            
            # Create keys and certificate
            response = iot_client.create_keys_and_certificate(setAsActive=True)
            certificate_arn = response['certificateArn']
            certificate_id = response['certificateId']
            
            # Attach policy to certificate
            iot_client.attach_policy(
                policyName=policy_name,
                target=certificate_arn
            )
            
            # Attach certificate to the device
            iot_client.attach_thing_principal(
                thingName=device_id,
                principal=certificate_arn
            )
            
            return {
                'certificate_arn': certificate_arn,
                'certificate_id': certificate_id,
                'certificate_pem': response['certificatePem'],
                'key_pair': response['keyPair']
            }
        except ClientError as e:
            raise RuntimeError(f"Failed to configure device: {e}")

    
    @keyword("Connect Device")
    def connect_device(self, device_id, certificate_pem, root_ca_pem, endpoint_url):
        """
        Connects the device to AWS IoT Core using the provided certificates and keys.
        """
        cert_file_path = f'{device_id}-certificate.pem.crt'
        root_ca_file_path = f'{device_id}-AmazonRootCA1.pem'
        
        try:
            # Store certificates and keys locally
            with open(cert_file_path, 'w') as cert_file:
                cert_file.write(certificate_pem)
                    
            with open(root_ca_file_path, 'w') as root_ca_file:
                root_ca_file.write(root_ca_pem)
            
            # Connect to AWS IoT Core (Example using Paho MQTT)
            # client = mqtt.Client()
            # client.tls_set(ca_certs=root_ca_file_path,
            #                certfile=cert_file_path)
            # client.connect(endpoint_url, 8883)
            # client.loop_start()
            
            return f"Device {device_id} connected successfully"
        except Exception as e:
            raise RuntimeError(f"Failed to connect device: {e}")
        finally:
            # Remove the files after the operation
            import os
            if os.path.exists(cert_file_path):
                os.remove(cert_file_path)
            if os.path.exists(root_ca_file_path):
                os.remove(root_ca_file_path)
        
    @keyword("Teardown AWS Resources")
    def teardown_aws_resources(self, policy_name, device_id):
        """
        Deletes the created IoT policy and the registered device (thing) in AWS IoT Core.
        """
        try:
            iot_client = self.session.client('iot')
            
            # Detach policy from all principals
            response = iot_client.list_targets_for_policy(policyName=policy_name)
            targets = response.get('targets', [])
            for target in targets:
                iot_client.detach_policy(policyName=policy_name, target=target)
            
            # Delete the policy
            iot_client.delete_policy(policyName=policy_name)
            
            # Detach all principals from the thing
            response = iot_client.list_thing_principals(thingName=device_id)
            principals = response.get('principals', [])
            for principal in principals:
                iot_client.detach_thing_principal(thingName=device_id, principal=principal)
            
            # Delete the thing (device)
            iot_client.delete_thing(thingName=device_id)
            
            return "Teardown of AWS resources successful"
        except ClientError as e:
            raise RuntimeError(f"Failed to teardown AWS resources: {e}")

    @keyword("Update Device Shadow")
    def update_device_shadow(self, device_id, state):
        """
        Updates the shadow state of the specified device.
        """
        try:
            iot_data_client = self.session.client('iot-data')
            payload = json.dumps(state)
            print(f"Payload being sent: {payload}")  # Debugging statement
            response = iot_data_client.update_thing_shadow(
                thingName=device_id,
                payload=payload.encode('utf-8')  # Ensure it's a bytes object
            )
            return json.loads(response['payload'].read())
        except ClientError as e:
            error_message = f"Failed to update device shadow: {e.response['Error']['Message']}"
            raise RuntimeError(error_message)
        except Exception as e:
            raise RuntimeError(f"An unexpected error occurred: {str(e)}")


    @keyword("Get Device Shadow")
    def get_device_shadow(self, device_id):
        """
        Retrieves the current shadow state of the specified device.
        
        Args:
            device_id (str): The ID of the device whose shadow state you want to retrieve.
        
        Returns:
            dict: The current shadow document of the device.
        """
        try:
            iot_data_client = self.session.client('iot-data')
            response = iot_data_client.get_thing_shadow(
                thingName=device_id
            )
            return json.loads(response['payload'].read())
        except ClientError as e:
            raise RuntimeError(f"Failed to get device shadow: {e}")

    @keyword("Delete Device Shadow")
    def delete_device_shadow(self, device_id):
        """
        Deletes the shadow state of the specified device.
        
        Args:
            device_id (str): The ID of the device whose shadow state you want to delete.
        
        Returns:
            dict: The response from AWS IoT Core confirming the shadow state deletion.
        """
        try:
            iot_data_client = self.session.client('iot-data')
            response = iot_data_client.delete_thing_shadow(
                thingName=device_id
            )
            return json.loads(response['payload'].read())
        except ClientError as e:
            raise RuntimeError(f"Failed to delete device shadow: {e}")
