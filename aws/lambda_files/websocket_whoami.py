import json
import logging
import boto3

logging.basicConfig(format='%(levelname)s: %(asctime)s: %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):

    api_client = boto3.client('apigatewaymanagementapi', endpoint_url='https://{}/{}'.format(event['requestContext']['domainName'], event['requestContext']['stage']))
    api_client.post_to_connection(Data=json.dumps({"service": "whoami", "message": event["requestContext"]["connectionId"]}), ConnectionId=event["requestContext"]["connectionId"])
    return {'statusCode': 200}