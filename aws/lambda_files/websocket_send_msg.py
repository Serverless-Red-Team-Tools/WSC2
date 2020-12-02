import json
import logging
import os
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

# logging.basicConfig(format='%(levelname)s: %(asctime)s: %(message)s')
# logger = logging.getLogger()
# logger.setLevel(logging.INFO)

ERROR_FORBIDDEN = 1
ERROR_CONNECTION_NOT_FOUND = 2


def lambda_handler(event, context):
    # logger.info('message event: ' + json.dumps(event, indent=2))
    # logger.info(f'message event["requestContext"]["connectionId"]: {connectionId}')

    connectionId = event['requestContext']['connectionId']
    table_name = os.environ['TableName']

    dynamodb_client = boto3.client('dynamodb')

    try:
        user_from_query = dynamodb_client.get_item(
            TableName=table_name,
            Key={'connectionId': {'S': connectionId}},
            ProjectionExpression='userName,userType'
        )
    except ClientError as e:
        # logger.error(e)
        pass
    else:
        user_from_id = connectionId
        user_from_name = user_from_query['Item']['userName']['S']
        user_from_role = user_from_query['Item']['userType']['S']

    event_body = json.loads(event['body'])

    # logger.info('message event: ' + json.dumps(event_body, indent=2))

    try:
        user_to_query = dynamodb_client.get_item(
            TableName=table_name,
            Key={'connectionId': {'S': event_body['to']}},
            ProjectionExpression='userName,userType,connectionId'
        )
        if 'Item' in user_to_query:
            user_to_id = user_to_query['Item']['connectionId']['S']
            user_to_name = user_to_query['Item']['userName']['S']
            user_to_role = user_to_query['Item']['userType']['S']
        else:
            all_users = dynamodb_client.scan(
                TableName=table_name,
                ProjectionExpression='userName,userType,connectionId'
            )
            user_to_query = None
            for user in all_users['Items']:
                if user['userName']['S'] == event_body['to']:
                    user_to_query = user
            if user_to_query is not None:
                user_to_id = user_to_query['connectionId']['S']
                user_to_name = user_to_query['userName']['S']
                user_to_role = user_to_query['userType']['S']
                # logger.info('FOUND: ' + json.dumps(user, indent=2))
            else:
                event_body['payload'] = {'error': ERROR_CONNECTION_NOT_FOUND, 'message': 'User/Connection "{}" not found'.format(event_body['to'])}
                user_to_id = user_from_id
                user_to_name = user_from_name
                user_to_role = None

    except ClientError as e:
        # logger.error(e)
        raise ValueError(e)

    try:

        api_client = boto3.client('apigatewaymanagementapi', endpoint_url='https://{}/{}'.format(event['requestContext']['domainName'], event['requestContext']['stage']))

        if (user_from_role == 'client' and user_to_role == 'client'):
            event_body['payload'] = {"error": ERROR_FORBIDDEN, "message": "A {} cannot send message to a {}.".format(user_from_role, user_to_role)}
            user_to_id = user_from_id
            user_to_name = user_from_name
            user_to_role = user_from_role

        response = {"action": "sendmsg", "from": user_from_id, "payload": event_body['payload']}
        api_client.post_to_connection(Data=json.dumps(response), ConnectionId=user_to_id)
        return {"statusCode": 200}

    except KeyError:
        return {"statusCode": 500}

    return {"statusCode": 200}