from flask import Flask, request, jsonify
import logging
import boto3
from botocore.config import Config
from botocore.session import Session
import os
import re
admission_controller = Flask(__name__)

if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    admission_controller.logger.handlers = gunicorn_logger.handlers
    admission_controller.logger.setLevel(gunicorn_logger.level)

## For testing only - from the Pod, curl https://localhost/validate/configmaps to see a "Method Not Allowed" response. Can replace "localhost" with the svc name
@admission_controller.route('/validate/configmaps', methods=['POST'])

def deployment_webhook():
    request_info = request.get_json()
    admission_controller.logger.info("Processing event..")
    # Log the full request for testing
    # admission_controller.logger.info(str(request_info))

    # Get configMap operation, UUID and name
    try:
        operation = str(request_info["request"]["operation"])
        namespace = str(request_info["request"]["namespace"])
        name = str(request_info["request"]["name"])
        username = str(request_info["request"]["userInfo"]["username"])
    except (KeyError, TypeError) as e:
        admission_controller.logger.error(f"Error while trying to fetch request information from the response: {e}")
        operation=namespace=name=username=None
    if None in (operation, username, namespace, name):
        admission_controller.logger.error("Error while trying to fetch request information from the response")
        return admission_response(False, "Error while trying to fetch request information from the response")

    # If TESTING is set to True, webhook will intercept configMaps with any name as long as it has label name=aws-auth and perform validation. This is useful if testing with kube-system namespace but you don't want to test on actual aws-auth configMap
    # If TESTING is set to False, webhook will intercept configMaps with name aws-auth as long as it has label name=aws-auth and perform validation. Other configMaps that have a different name but have label name=aws-aut will be allowed to pass through without performing any validation
    if os.getenv("TESTING") is not None:
        TESTING = eval(os.environ['TESTING'].capitalize())
    else:
        TESTING = True

    if TESTING is False and name != "aws-auth":
        admission_controller.logger.error(f"configMap name is {name} but has the label name=aws-auth. If this is for testing, set the TESTING env variable to 'TRUE'. If not, remove the label name=aws-auth from the {name} configMap...Request will be allowed to pass through and will not be validated by the webhook")
        return admission_response(True, "configMap name not 'aws-auth' but has the label name=aws-auth. If this is for testing, set the TESTING env variable to 'TRUE'. If not, remove the label name=aws-auth from the configMap...Request will be allowed to pass through and will not be validated by the webhook") 

    admission_controller.logger.info(f"Intercepted {operation} operation on {name} configMap resource in the {namespace} namespace by {username} user")
    

    # Get configMap Data
    if operation in ("CREATE","UPDATE"):

        # Get the ENV values
        MANDATORY_ENV_VARS = ["CLUSTER_NAME", "CLUSTER_REGION"]
        for var in MANDATORY_ENV_VARS:
            if var not in os.environ:
                admission_controller.logger.error("CLUSTER_NAME and/or CLUSTER_REGION environment variables were not set in the deployment...")
                return admission_response(False, "CLUSTER_NAME and/or CLUSTER_REGION environment variables were not set in the deployment")

        CLUSTER_NAME = (os.environ['CLUSTER_NAME'])
        CLUSTER_REGION = (os.environ['CLUSTER_REGION'])

        # These roles should be present in aws-auth
        if os.getenv("ADDITIONAL_ROLES") is not None:
            ADDITIONAL_ROLES = (os.environ['ADDITIONAL_ROLES'])
            ADDITIONAL_ROLES = ADDITIONAL_ROLES.split(",")
        else:
            ADDITIONAL_ROLES = []

        # These roles should not be present in aws-auth
        if os.getenv("REJECT_ROLES") is not None:
            REJECT_ROLES = (os.environ['REJECT_ROLES'])
            REJECT_ROLES = REJECT_ROLES.split(",")
        else:
            REJECT_ROLES = []            

        try:
            data = str(request_info["request"]["object"]["data"]).replace('\\n', '\n').replace('\\t', '\t')
        except (KeyError, TypeError) as e:
            data = None
            # admission_controller.logger.error(f"Error while trying to fetch configMap data block from the response: {e}")
            # return admission_response(False, "Error while trying to fetch configMap data block from the response")

        # Empty Data not allowed   
        if not data:
            admission_controller.logger.error("Request Denied - Not allowed without any data in configMap")
            return admission_response(False, "Not allowed with empty data in configMap")
        # Check if the workerNodeIAMRoles and the additional roles passed in via environment variables exist in the mapRoles section of the aws-auth configMap
        else:
            admission_controller.logger.info(f"\nData from the aws-auth configMap:\n {data} \n")

            # Extract ARNs from the configMap
            aws_auth_arns = re.findall(r'(?:^|\s)(arn:aws:iam::\S*)',data)
            aws_auth_arns = set(aws_auth_arns)

            # If roles defined in the REJECT_ROLES are present in the Data section, reject the request
            reject_roles = list(filter(None, REJECT_ROLES))     
            for r in reject_roles:
                if r in aws_auth_arns:
                    admission_controller.logger.info(f"\nRole: {r} found in configMap data mapRoles and this role cannot be used as specified in REJECT_ROLES environment variable\n")             
                    return admission_response(False, "Role: {} Not allowed in the configMap".format(r))

            ############################## AWS API Calls Section Begin ##############################

            # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html
            config=Config(connect_timeout=5, read_timeout=60, retries={'max_attempts': 3})
            
            # Get the instances associated with a Cluster and query for IAM Instance Profile
            # Get the instances which have the Tag key - kubernetes.io/cluster/<cluster_name> with value "owned"
            # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/collections.html
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Instance.iam_instance_profile
            ec2_client = boto3.resource('ec2', CLUSTER_REGION)
            filters = [{
                'Name': 'tag:kubernetes.io/cluster/{}'.format(CLUSTER_NAME),
                'Values': ['owned']
            }]            
            instanceProfilesList=[]
            try:
                ec2_response = ec2_client.instances.filter(Filters=filters)
                for i in ec2_response:
                    instanceProfileName = str(i.iam_instance_profile['Arn']).split("/")[-1]
                    instanceProfilesList.append(str(instanceProfileName))
            except Exception as ec2_error:
                admission_controller.logger.error(f"Error while trying to get the EC2 Instance profile(s) associated with the worker node(s): {ec2_error}")
                return admission_response(False, "Error while trying to get the EC2 Instance profile(s) associated with the worker node(s): {}".format(ec2_error))

            instanceProfiles = list(set(instanceProfilesList))
            admission_controller.logger.info(f"IAM Instance profiles associated with the worker nodes are: {instanceProfiles}")

            # Get the IAM Roles associated with the IAM Instance Profiles
            # Sources:
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_instance_profile
            # https://docs.aws.amazon.com/cli/latest/reference/iam/get-instance-profile.html
            iam_client = boto3.client('iam', config=config)
            iamRolesList=[]
            try:
                for iam in instanceProfiles:
                  iam_response = iam_client.get_instance_profile(
                      InstanceProfileName = iam
                  )
                  for k in iam_response['InstanceProfile']['Roles']:
                    iamRole = str(k['Arn'])
                    iamRolesList.append(iamRole)
            except Exception as iam_error:
               admission_controller.logger.error(f"Error while trying to get the IAM Role of the EC2 Instance profile(s): {iam_error}")
               return admission_response(False, "Error while trying to get the IAM Role of the EC2 Instance profile(s): {}".format(iam_error))

            # Do not fail if there are no Roles - Accounting for Fargate nodes
            iamRoles = list(set(iamRolesList))
            admission_controller.logger.info(f"IAM roles associated with the worker nodes are: {iamRoles}")    

            # Logic to list Fargate profile
            fargate_client = boto3.client('eks', CLUSTER_REGION, config=config)
            fargateProfilesList=[]
            try:
                fargate_response = fargate_client.list_fargate_profiles(
                    clusterName = CLUSTER_NAME,
                )
                if fargate_response['fargateProfileNames'] is not None:
                    for i in fargate_response['fargateProfileNames']:
                        fargateProfilesList.append(i)

            except Exception as fargate_list_error:
               admission_controller.logger.error(f"Error while trying to get the list of fargate profiles: {fargate_list_error}")
               return admission_response(False, "Error while trying to get the list of fargate profiles: {}".format(fargate_list_error))                 

            fargateProfilesList = list(filter(None, fargateProfilesList))
            fargateProfiles = set(fargateProfilesList)
            admission_controller.logger.info(f"Fargate profiles associated with the cluster are: {fargateProfiles}")

            # Logic to describe Fargate profile
            fargateRolesList=[]
            if fargateProfiles is not None:
                try:
                    for profile in fargateProfiles:                    
                      fargate_describe_response = fargate_client.describe_fargate_profile(
                          clusterName = CLUSTER_NAME,
                          fargateProfileName = profile
                      )
                      fargateRolesList.append(str(fargate_describe_response['fargateProfile']['podExecutionRoleArn']))
                except Exception as fargate_describe_error:
                    admission_controller.logger.error(f"Error while trying to describe the fargate profiles: {fargate_describe_error}")
                    return admission_response(False, "Error while trying to describe the fargate profiles: {}".format(fargate_describe_error))   

            fargateRoles = list(set(fargateRolesList))
            admission_controller.logger.info(f"Fargate profiles associated with the cluster are: {fargateRoles}")

            ############################## AWS API Calls Section End ##############################

            final_roles = iamRoles + ADDITIONAL_ROLES + fargateRoles
            final_roles = list(filter(None, final_roles))
            admission_controller.logger.info(f"Extracted ARNs from the aws-auth configMap Data section: {aws_auth_arns}")           
            for role in final_roles:
                if role in aws_auth_arns:
                    admission_controller.logger.info(f"\n{role} entry found in configMap data mapRoles \n") 
                else:
                    admission_controller.logger.error(f"\n{role} entry not found in configMap data mapRoles section \n")
                    admission_controller.logger.info(f"\nMake sure that {final_roles} entry/entries are added in configMap data mapRoles section \n")
                    return admission_response(False, "\n\nAll the roles not found in the aws-auth configMap.Make sure to add {} entry/entries are added in configMap data mapRoles section".format(final_roles))
            return admission_response(True, data)
    
    # Delete operation not allowed on aws-auth
    elif str(operation) in ("DELETE"):
        if name == "aws-auth":
            admission_controller.logger.error(f"Delete operation on {name} configMap resource in the {namespace} namespace is not allowed")
            return admission_response(False, "Delete operation not allowed on aws-auth configMap")        
            # For testing - comment the above 2 lines and uncomment the below one
            # return admission_response(True, "It's a delete operation")
        else:
           return admission_response(True, "All Good") 
    else:
       return admission_response(True, "All Good") 

def admission_response(allowed, message):
    return jsonify({"response": {"allowed": allowed, "status": {"message": str(message)}}})

## For testing only - from the Pod, curl https://localhost/ to see a response. Can replace "localhost" with the svc name
@admission_controller.route("/")
def hello():
    return "<h1 style='color:blue'>Hello There!</h1>"    

if __name__ == '__main__':
    admission_controller.run(host='0.0.0.0')
    #admission_controller.run(host='0.0.0.0', port=443, ssl_context=("/etc/webhook/certs/cert.pem", "/etc/webhook/certs/key.pem"))
