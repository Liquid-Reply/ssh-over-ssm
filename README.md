# Use-Case: Check the viablity of SSH over SSM into a pod/container running on a EKS Cluster

* Short answer: Yes, it is possible to use SSH over SSM agent running into a container in a EKS cluster. It's needed the AWS Systems Manager Agent (SSM Agent) on the target container in the Amazon EKS cluster. 
* Long Answer: Please follow me through this through documentation. 

1. **AWS CLI and Session Manager Plugin**
   * You need to have the latest AWS CLI and [Session Manager Plugin installed](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) on your local machine.
   * We have opted for [AWS CLI using AWS SSO](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html).  

2. **VPC Endpoints**:
   * Since the nodes are running in Private Subnet, there will not be any Internet Gateway attached the to VPC. So it is necessary to add Endpoints to the VPC where EC2 nodes are running. 3 Endpoints are necessary for this and the are:
      * com.amazonaws.<region>.ssm
      * com.amazonaws.<region>.ssmmessages
      * com.amazonaws.<region>.ec2messages 
   * All the Endpoinds to should be attached the respective private subnet where the nodes are running. Create/ add existing Security group and it is very important that, the security group must allow inbound HTTPS (port 443) traffic from the resources in your VPC that communicate with the service.


3. **Create an IAM service role for a hybrid and multicloud environment**
   * `Create an IAM service role for a hybrid and multicloud environment`:
      ```bash
      $ cat << EOF > ssm-role.json 
      {
        "Version":"2012-10-17",
        "Statement":[
            {
              "Sid":"",
              "Effect":"Allow",
              "Principal":{
                  "Service":"ssm.amazonaws.com"
              },
              "Action":"sts:AssumeRole",
              "Condition":{
                  "StringEquals":{
                    "aws:SourceAccount":"123456789012"
                  },
                  "ArnEquals":{
                    "aws:SourceArn":"arn:aws:ssm:us-east-2:123456789012:*"
                  }
              }
            }
        ]
      }
      EOF

      $ aws iam create-role \
      --role-name SSMServiceRole \
      --assume-role-policy-document smm-role.json 
      ```
    * This procedure uses the AmazonSSMManagedInstanceCore policy for Systems Manager core functionality. Depending on your use case, you might need to add additional policies to your service role for your on-premises machines to be able to access other capabilities or AWS services.
      ```bash
      aws iam attach-role-policy \
      --role-name SSMServiceRole \
      --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore  
      ``` 

4. **SSM Agent in container on EKS cluster**
   * You need to install the [AWS Systems Manager Agent (SSM Agent) on the target container on EKS cluster](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-managedinstances.html). This allows you to establish an SSH session with the target container. AWS provides this possiblity to manage non-ec2 instances as well. These instances are called `managed` instances shown as `mi-`.  We exploits the same approach to install and configure a ssm agent on a K8s pod/container. Here are the steps that we followed: 
      * `Create a hybrid activation for a hybrid and multicloud environment`:
        * To set up machines other than Amazon Elastic Compute Cloud (EC2) instances as managed nodes for a hybrid and multicloud environment, you create and apply a hybrid activation. After you successfully complete the activation, you immediately receive an Activation Code and Activation ID at the top of the console page. You specify this Code and ID combination when you install AWS Systems Manager SSM Agent on non-EC2 machines for your hybrid and multicloud environment. The Code and ID provide secure access to the Systems Manager service from your managed nodes.
        * Here is an AWS CLI sample command to run on a local Linux machine:
          ```bash
          aws ssm create-activation \
          --default-instance-name MyWebServers \
          --description "Activation for EKS containers" \
          --iam-role service-role/SSMServiceRole \
          --registration-limit 10 \
          --region us-east-2 \
          --tags ""
          ```
      * `Install SSM Agent for a hybrid and multicloud environment`: We start a ubuntu container in our EKS cluster:
        ```bash
        kubectl run ubuntu --image=ubuntu -- sleep infinity
        kubectl exec -it ubuntu -- bash
        apt update
        mkdir /tmp/ssm
        curl
        https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/am
        azon-ssm-agent.deb -o /tmp/ssm/amazon-ssm-agent.deb
        sudo dpkg -i /tmp/ssm/amazon-ssm-agent.deb
        sudo service amazon-ssm-agent stop
        sudo amazon-ssm-agent -register -code "activation-code" -id "activation-id"
        -region "region" 
        sudo service amazon-ssm-agent start 
        ```

      * Install and start SSH server on the container: 
         * Currently Visual Studio Code IDE [only supports a SSH tunnel over AWS SSM](https://github.com/aws/aws-toolkit-vscode/issues/941), so we need to install and confire a ssh deamon on our container as follows:
            ```bash
            apt install openssh-server
            /etc/init.d/ssh start
            ```
      * `Turning on the advanced-instances tier`: AWS Systems Manager offers a standard-instances tier and an advanced-instances tier for non-EC2 machines in a hybrid and multicloud environment. The standard-instances tier lets you register a maximum of 1,000 hybrid-activated machines per AWS account per AWS Region. The advanced-instances tier is also required to use Patch Manager to patch Microsoft-released applications on non-EC2 nodes, and to connect to non-EC2 nodes using Session Manager. 
      Please the given instruction [here](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-managedinstances-advanced.html#systems-manager-managedinstances-advanced-permissions) to configuring permissions to turn on the advanced-instances tier. 
        * Turning on the advanced-instances tier:
          ```bash
          aws ssm update-service-setting \
          --setting-id arn:aws:ssm:<region>:<aws-account-id>:servicesetting/ssm/managed-instance/activation-tier \
          --setting-value advanced
          
          # Run the following command to view the current service settings for managed nodes in the current AWS account and AWS Region.
          aws ssm get-service-setting \
          --setting-id arn:aws:ssm:<region>:<aws-account-id>:servicesetting/ssm/managed-instance/activation-tier

          # The command returns information like the following.
          {
            "ServiceSetting": {
                "SettingId": "/ssm/managed-instance/activation-tier",
                "SettingValue": "advanced",
                "LastModifiedDate": 1555603376.138,
                "LastModifiedUser": "arn:aws:sts::123456789012:assumed-role/Administrator/User_1",
                "ARN": "arn:aws:ssm:us-east-2:123456789012:servicesetting/ssm/managed-instance/activation-tier",
                "Status": "PendingUpdate"
            }
          }
          ```
      * Now we can test our access to the container as shown:
        ```bash
        # list managed instances 
        aws ssm describe-instance-information --filters Key=ResourceType,Values=ManagedInstance --query "InstanceInformationList[].InstanceId" --output table
        -----------------------------
        |DescribeInstanceInformation|
        +---------------------------+
        |  mi-092f811ce86a506dc     |
        +---------------------------+
        # start a ssm session by connecting to the container. 
        aws ssm start-session --target mi-092f811ce86a506dc
        # Starting session with SessionId: liquid-0b25c3d8328b7426f
        $ bash
        ssm-user@ssm-agent-69c699d6f6-mjv9l:/root$ cd
        ssm-user@ssm-agent-69c699d6f6-mjv9l:~$ whoami
        ssm-user
        ssm-user@ssm-agent-69c699d6f6-mjv9l:~$ hostname -f
        ssm-agent-69c699d6f6-mjv9l
        ```
        We can verify that our setup works and we are able to connect to our managed instance via ssm. 
      *  **SSH Key Pair**: The public key should be in the `~/.ssh/authorized_keys` file on our container to allow SSH access.

5. **Client Configuration**: You need to properly configure your local `~/.ssh/config` file to include the necessary configuration for SSM. 
   * As next step, you to update your .ssh/config as shown:
     ```bash
     Host mi-092f811ce86a506dc
     User ssm-user
     IdentityFile ~/.ssh/ssm-key.pem
     ProxyCommand bash -c "aws sso login --profile sso; export AWS_PROFILE=sso; export AWS_REGION=eu-central-1; aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'"
     ```
   * Then create a shell script called `ssm-private-ec2-proxy.sh`
     ```bash
     cat << EOF > ssm-private-ec2-proxy.sh
     #!/bin/bash

     AWS_PROFILE=''
     AWS_REGION=''
     MAX_ITERATION=5
     SLEEP_DURATION=5

     # Arguments passed from SSH client
     HOST=$1
     PORT=$2

     echo $HOST

     # Start ssm session
     aws ssm start-session --target $HOST \
       --document-name AWS-StartSSHSession \
       --parameters portNumber=${PORT} \
       --profile ${AWS_PROFILE} \
      --region ${AWS_REGION}
     EOF
     ```
  * And the last touch:
    ```bash
    chmod +x ssm-private-ec2-proxy.sh
    mv ssm-private-ec2-proxy.sh ~/.ssh/
    ```
  * Now we can try to connect to managed instance via SSH:
    ```bash
    ssh mi-092f811ce86a506dc
    Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.10.201-191.748.amzn2.x86_64 x86_64)

    * Documentation:  https://help.ubuntu.com
    * Management:     https://landscape.canonical.com
    * Support:        https://ubuntu.com/advantage

    This system has been minimized by removing packages and content that are
    not required on a system that users do not log into.

    To restore this content, you can run the 'unminimize' command.
    Last login: Wed Jan 10 10:16:47 2024 from ::1
    $ bash
    ssm-user@ssm-agent-69c699d6f6-mjv9l:~$
    ```
    This opens your default browser and begins the login process for your AWS SSO account, the typical way when using AWS CLI with SSO. Follow the steps on your browser to Allow the Authorize request.
    You should now be connected to the maanged instance.  

## Can I connect VSCode via [Remote - SSH](https://code.visualstudio.com/docs/remote/ssh-tutorial) using SSH over SSM?

Connecting VS Code using the SSH remote plugin through SSH over SSM from AWS. On VS Code, "Open a Remote Window" as shown in the following images.

<p align="center">
  <img width="700" height="500" src=./images/image-1.png>
</p>
<p align="center">
  <img width="700" height="500" src=./images/image-2.png>
</p>
<p align="center">
  <img width="700" height="500" src=./images/image-3.png>
</p>