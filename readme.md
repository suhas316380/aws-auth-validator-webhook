# aws-auth-validator

### Summary
This project will help you setup a validation webhook to validate aws-auth configMap in the kube-system namespace

### Pre-reqs
- kubectl and aws-cli
- Required permissions to run 'kubectl' and 'aws' commands
- EKS 1.15+

### Highlights
##### What can the webhook do:
- configMap with empty data is not allowed. This applies for CREATE and UPDATE operation
- At a minimum, IAM roles associated with the IAM Instance profiles attached to the worker nodes should be present in the aws-auth in addition to any IAM roles/users specified as a comma saperated string via the ADDITIONAL_ROLES environment variable in the deployment. This applies for CREATE and UPDATE operation. Fargate roles are also accounted for and checks are performed to make sure that they are present in aws-auth
- Has an option to reject roles based on the values specified to REJECT_ROLES environment. This is useful in cases where a specific user/Role should be denied access. This is particularyly useful in cases where cluster creator should not be defined in aws-auth as best practice. REJECT_ROLES env variable accepts comma-separated values. 
- DELETE operation is not allowed on aws-auth configMap 
- When a request is denied, the reason should be displayed on the terminal.
- More verbose logging should be available in the Pod logs

##### What the webhook doesn't do:
- Will not perform lint and syntax checks on aws-auth. 
- Malformed aws-auth configMap can get through.

##### Why is this useful:
- Prevents accidental deletion/modification of the aws-auth and thus avoiding Nodes leaving the cluster or users getting locked out of the cluster
- Ensures that workerNode, Fargate profile IAM roles and any additional IAM roles/users specified as a comma saperated string via the ADDITIONAL_ROLES environment variable in the deployment are always present in the aws-auth configMap. Else, request is not allowed to go through.
- Ensures that pre-specified unwanted roles don't make their way into the aws-auth which can potentially grant access to someone to the cluster or in some cases, locking out all the users
- All the events are logged within the logs. The webhook is written in Python and all the events can be logged to a file/CW but this is TODO. 

### Explaination

1. The **ValidatingWebhookConfiguration** has the following namespace and Object selectors and hence namespace with label `name=kube-system` and objects with label `name=kube-system` are processed by the webhook.:
```
  namespaceSelector:
    matchExpressions:
    - key: name
      operator: In
      values:
      - kube-system
  objectSelector:
    matchLabels:
      name: aws-auth      
```
2. `generatecerts.sh` generates a selfSiigned certificate associated with the name of the Kubernetes service that is requried by the webhook. Then a CSR is created and approved and a secret: `aws-auth-validator-certs` is created in the kube-system Namespace.
    - Syntax: `bash generatecerts.sh --service aws-auth-validator-svc --secret aws-auth-validator-certs --namespace kube-system`
3. IAM Roles for Service Accounts (IRSA) is required. `setup_irsa.sh` performs the following things:
    - Enables OIDC for your cluster.
    - Creates an IAM Policy using policy.json: `aws-auth-validator`
    - Creates IAM Service Account and attaches the IAM policy.
4. The webhook can intercept **CREATE**, **UPDATE** and **DELETE** operations. Additional configuration for webhook are passed via the environment variables.
5. **CREATE** or **UPDATE** operation:
    - IAM Roles defined via REJECT_ROLES environment variable in the Deployment will not be allowed in the aws-auth. This is particularyly useful in cases where cluster creator should not be defined in aws-auth as best practice. REJECT_ROLES env variable accepts comma-separated values. 
    - When a CREATE or UPDATE operation is made on the aws-auth CM, the Pod makes "describe_instances" AWS API calls to get a list of Worker nodes (if there are large number of worker nodes, pagination is accounted for when making "describe_instances". Also consider increasing timeout value in the webhook config manifest.yaml) and their IAM Instance profiles. The instances are filtered based on the tags. Name=kubernetes.io/cluster/<cluster_name> ; Value: owned. The CLUSTER_NAME and CLUSTER_REGION variables are passed to the deployment and  these values are used to make the API calls.
    - Then a "get_instance_profile" AWS API call is made to get the IAM roles associated with the instance profile
    - Then a "list_fargate_profiles" call is made to get any fargate profiles associated with the cluster. If there are any Fargate profiles associated with the cluster, "describe_fargate_profile" API call is made to get the PodExecutionRoleArn and is stored in the list A. This ensures that Fargate Roles are also accounted for
    - Any additional comma saperated IAM Roles/Users specified via ADDITIONAL_ROLES environment variables are stored into a list (list A) along with the worker node IAM roles
    - The intercepted request is checked for the Data section of the configMap and mapRoles section is parsed and the ARNs are extracted to another list (List B)
    - Checks to make sure that all the elements in List A are present in List B. Otherwise, the request is rejected.
    - "TESTING" environment varialbe can be set via the deployment. Possible values: "True or False". Default value: True
    - If TESTING is set to True, webhook will intercept configMaps with any name as long as it has label name=aws-auth and perform validation. This is useful if testing within kube-system     namespace but you don't want to test on actual aws-auth configMap  
    - If TESTING is set to False, webhook will intercept configMaps with name aws-auth as long as it has label name=aws-auth and perform validation. Other configMaps that have a different name but have label name=aws-aut will be allowed to pass through without performing any validation
6. **DELETE** operation:
    - DELETE operation is not allowed on aws-auth configMap even when TESTING is set to True

### Steps to setup/test:
1. Label the namespace:
- `kubectl label ns kube-system name=kube-system`
2. Create Docker image from the Dockerfile
    ```
    - $(aws ecr get-login --no-include-email --region us-east-1)
    - docker build --network=host -t webhook .
    - docker tag webhook:latest 1234567.dkr.ecr.us-east-1.amazonaws.com/webhook:latest
    - docker push 1234567.dkr.ecr.us-east-1.amazonaws.com/webhook:latest
    - docker build --network=host -t webhook:latest . && docker tag webhook:latest 1234567.dkr.ecr.us-east-1.amazonaws.com/webhook:latest && docker push 1234567.dkr.ecr. us-east-1.amazonaws.com/webhook:latest
    ```
3. Generate certificates using the bash script
    - `bash generatecerts.sh --service aws-auth-validator-svc --secret aws-auth-validator-certs --namespace kube-system`
4. Enable OIDC provider, create IAM Policy and create IAM service account:
    - `bash setup_irsa.sh <region> <cluster_name> <namespace>`
    - eg: `cd irsa && bash setup_irsa.sh us-east-1 training kube-system`
4. Update the "caBundle" field in the manifest.yaml and deploy it.
    - `kubectl get secret -n kube-system aws-auth-validator-certs -o json | jq '.data."cert.pem"' | tr -d '"'`
5. **TESTING** - Apply cm.yaml. Change values and observe the output in the Pod logs
    - **Test case 1**: configMap with empty data is not allowed. This applies for CREATE and UPDATE operation
    - **Test case 2**: At a minimum, configMap should have IAM roles associated with the IAM Instance profiles attached to the worker nodes should be present in the aws-auth in addition to    any IAM roles/users specified as a comma saperated string via the ADDITIONAL_ROLES environment variable in the deployment. This applies for CREATE and UPDATE operation
    - **Test case 3**: DELETE operation is not allowed on aws-auth configMap 
    - **Test case 4**: When a request is denied, the reason should be displayed on the terminal.
    - **Test case 5**: More verbose logging should be available in the Pod logs: `kubectl logs -n kube-system -l app=aws-auth-validator -f`
6. **PRODUCTION** - Apply the label to the aws-auth to make sure that it's detected by the webhook
    - `kubectl -n kube-system label cm aws-auth name=aws-auth`


References: 
1. https://dev.to/ineedale/writing-a-very-basic-kubernetes-mutating-admission-webhook-5b1
2. https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
3. https://godoc.org/k8s.io/api/admission/v1beta1
4. https://github.com/kubernetes/kubernetes/blob/v1.13.0/test/images/webhook/configmap.go
5. https://github.com/isaaguilar/admissions-webhook-flask-server
6. https://medium.com/analytics-vidhya/how-to-write-validating-and-mutating-admission-controller-webhooks-in-python-for-kubernetes-1e27862cb798


