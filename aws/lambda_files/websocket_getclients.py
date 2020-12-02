import json
import logging
import os
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr

logging.basicConfig(format='%(levelname)s: %(asctime)s: %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info('message event: ' + json.dumps(event, indent=2))
    connectionId = event['requestContext']['connectionId']
    logger.info(f'message event["requestContext"]["connectionId"]: {connectionId}')

    table_name = os.environ['TableName']

    dynamodb_client = boto3.client('dynamodb')

    try:
        response = dynamodb_client.scan(
            TableName=table_name,
            ProjectionExpression='connectionId,userName,userType,whoami,hostname,ip,domain_name'
        )
    except ClientError as e:
        logger.error(e)
        raise ValueError(e)

    try:
        body = json.loads(event['body'])
        api_client = boto3.client('apigatewaymanagementapi', endpoint_url='https://{}/{}'.format(event['requestContext']['domainName'], event['requestContext']['stage']))

        try:
            response = {"action": "getclients", "from": event["requestContext"]["connectionId"], "payload": list(filter(lambda user: user['userType']['S'] == 'client', response['Items']))}
            api_client.post_to_connection(Data=json.dumps(response), ConnectionId=connectionId)
        except ClientError as e:
            logger.error(e)


    except KeyError:
        return {
            'statusCode': 404,
            'body': json.dumps({'success': 'ko', 'message': 'KeyError'})
        }

    response = {'statusCode': 200}
    return response