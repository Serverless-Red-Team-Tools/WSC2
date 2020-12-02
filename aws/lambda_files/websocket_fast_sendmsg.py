import json
import boto3


def lambda_handler(event, context):
    event_body = json.loads(event['body'])
    api_client = boto3.client('apigatewaymanagementapi', endpoint_url='https://{}/{}'.format(event['requestContext']['domainName'], event['requestContext']['stage']))
    api_client.post_to_connection(Data=json.dumps({"action": "fast_sendmsg", "from": event['requestContext']['connectionId'], "payload": event_body["payload"]}), ConnectionId=event_body['to'])

    return {"statusCode": 200}