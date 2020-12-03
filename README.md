# WSC2

A modular Command and Control using AWS Lambda and Websockets.

![Communication schema](https://raw.githubusercontent.com/aramburu/WSC2/media/communication.png)

## AWS Cost
AWS have a Free tier plan that covers all the needs for this tool by far. 


# Usage

## Install dependencies

    pip3 install -r requirements.txt

## Deploy WSC2 to AWS

Get your (free) AWS account and generate a pair of AWS Keys:
https://console.aws.amazon.com/iam/home?#/security_credentials

Deploy a new environment in AWS. 

    python3 wsc2.py --deploy --env-name some_name


## Connect to WSC2
Connect with a previously created deployment:

    python3 wsc2.py --connect --env-name some_name

When you are connected to AWS, you can execute the "help" command to see all the available commands.



## Sync local aws_config.json file

If you want to sync the WSC2 AWS account with your local file because you have created the environments from another place:

    python3 wsc2.py --sync 

## Undeploy WSC2 from AWS

If you want to remove all Lambdas, API Gateways, roles, permissions and DynamoDB tables created for a environment:

    python3 wsc2.py --remove --env-name some_name 



# Architecture

## Infrastructure

WSC2 uses the Cloud Amazon Web Services (AWS) platform. AWS Lambda has been used, which is the serverless service of AWS, which allows functions to be executed without the need to have a server running. In this way, you only pay for the number of times the function is executed. To persist some data as the clients that are connected we have made use of DynamoDB which is a NoSQL database engine from AWS. On the other hand API Gateway has been used so that the clients can connect to the Lambda functions. As a result we have the following infrastructure:

![Communication schema](https://raw.githubusercontent.com/aramburu/WSC2/media/communication.png)

# Modules


## Remote Powershell shell

Module to execute Powershell code from clients:

	ps_shell <client>

![enter image description here](https://raw.githubusercontent.com/aramburu/WSC2/media/ps_shell.gif)

Inside the shell you can execute a command and parse it with your local shell with the ">>>" operator. For example:

	dir >>> grep "c2"
This command executes a "dir" command in the client and the result is piped to the local shell with ">>>" and then grep "c2" will be executed over the "dir" output.
Another example could be:

	ipconfig >>> > ifconfig.txt
This command executes "ipconfig" command in the client and the result is piped to the local shell with ">>>" and then is saved to a file called "ifconfig.txt"

## Socks5

Module to create Socks5 Proxy through the clients
Create a Socks5 Proxy in the local host and port indicated. Tunnelizes all the TCP traffic sent to the Proxy through selected client. Proxy user and password are optional parameters, if not indicated, would be "username" and "password" by default:

	socks5_create <client> <host> <port> <username>? <password>?

Now you can connect with this Proxy with proxychains for example.

![](https://raw.githubusercontent.com/aramburu/WSC2/media/socks5_create.png)

![](https://raw.githubusercontent.com/aramburu/WSC2/media/socks5.png)

To list all the created Proxies you can use:

	socks5_list

It will show all the running proxies.

To remove a Proxy you can execute:

	socks_remove <proxy_id>

Where <proxy_id> is the id in the list of socks5_list.

![](https://raw.githubusercontent.com/aramburu/WSC2/media/socks5_remove.png)

To remove all the Proxy Socks5 running:

	socks5_remove_all
	
## Screen capture
To take a screen capture of a client, indicate the name of the client and the path. Path would be "./" if not indicated:

	screen_capture <client> <path>?


![Screen capture module](https://raw.githubusercontent.com/aramburu/WSC2/media/show_the_screen_hide_the_pain.gif)



