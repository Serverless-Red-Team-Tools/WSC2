# Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.


import json
import logging
import os
import boto3
from botocore.exceptions import ClientError


# Set up logging
# logging.basicConfig(format='%(levelname)s: %(asctime)s: %(message)s')
# logger = logging.getLogger()
# logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Example WebSocket $connect Lambda function

    :param event: Dict (usually) of parameters passed to the function
    :param context: LambdaContext object of runtime data
    :return: Dict of key:value pairs
    """

    # Log the values received in the event and context arguments
    # logger.info('$connect event: ' + json.dumps(event, indent=2))
    # logger.info(f'$connect event["requestContext"]["connectionId"]: {event["requestContext"]["connectionId"]}')

    # Retrieve the name of the DynamoDB table to store connection IDs
    table_name = os.environ['TableName']
    master_password = os.environ['MasterPassword']

    # Was a user name specified in a query parameter?
    user_name = 'Anon'
    userType = 'client'
    whoami = '-'
    hostname = '-'
    ip = '-'
    domain_name = '-'
    master_password_input = None
    if 'queryStringParameters' in event:
        if 'name' in event['queryStringParameters']:
            user_name = event['queryStringParameters']['name']
        if 'masterPassword' in event['queryStringParameters']:
            master_password_input = event['queryStringParameters']['masterPassword']
        if 'userType' in event['queryStringParameters'] and event['queryStringParameters']['userType'] != 'master':
            userType = event['queryStringParameters']['userType']
        if 'w' in event['queryStringParameters']:
            whoami = event['queryStringParameters']['w']
        if 'h' in event['queryStringParameters']:
            hostname = event['queryStringParameters']['h']
        if 'i' in event['queryStringParameters']:
            ip = event['queryStringParameters']['i']
        if 'd' in event['queryStringParameters']:
            domain_name = event['queryStringParameters']['d']

    # Store the connection ID and user name in the table
    if master_password_input == master_password:
        item = {'connectionId': {'S': event['requestContext']['connectionId']}, 'userName': {'S': user_name}, 'userType': {'S': 'master'}, 'whoami': {'S': whoami}, 'hostname': {'S': hostname}, 'ip': {'S': ip}, 'domain_name': {'S': domain_name}}
    else:
        item = {'connectionId': {'S': event['requestContext']['connectionId']}, 'userName': {'S': user_name}, 'userType': {'S': userType}, 'whoami': {'S': whoami}, 'hostname': {'S': hostname}, 'ip': {'S': ip}, 'domain_name': {'S': domain_name}}
    dynamodb_client = boto3.client('dynamodb')
    try:
        dynamodb_client.put_item(TableName=table_name, Item=item)
        # api_client = boto3.client('apigatewaymanagementapi', endpoint_url='https://{}/{}'.format(event['requestContext']['domainName'], event['requestContext']['stage']))
        # api_client.post_to_connection(Data=json.dumps({"service": "whoami", "message": event['requestContext']['connectionId']}), ConnectionId=event['requestContext']['connectionId'])
    except ClientError as e:
        # logger.error(e)
        raise ConnectionAbortedError(e)

    # Construct response
    response = {'statusCode': 200}
    return response
