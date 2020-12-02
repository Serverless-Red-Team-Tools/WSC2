import json
import logging
import boto3
import os
from botocore.exceptions import ClientError
import time

from aws.lambda_util import create_lambda_function, delete_iam_role

AWSC2_MASTER_TABLE = 'awsc2_master_table'


class AwsDeplpyment:

    def create_websockets_table(self, aws_session, table_name, region):

        attributes = [
            {
                'AttributeName': 'connectionId',
                'AttributeType': 'S'
            },
        ]
        key_schema = [
            {
                'AttributeName': 'connectionId',
                'KeyType': 'HASH'
            },
        ]
        provisioned_thruput = {
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }

        dynamodb_resource = aws_session.client('dynamodb', region_name=region)
        try:
            dynamodb_resource.create_table(TableName=table_name, AttributeDefinitions=attributes, KeySchema=key_schema, ProvisionedThroughput=provisioned_thruput)
        except ClientError as e:
            return False

        print('[+] DynamoDB "{}" table created'.format(table_name))
        return True

    def delete_websockets_table(self, aws_session, table_name, region):

        dynamodb_client = aws_session.client('dynamodb', region_name=region)
        try:
            dynamodb_client.delete_table(TableName=table_name)
        except ClientError as e:
            return False
        return True

    def attach_role_policy(self, aws_session, role_name, policy_name, api_arn, websocket_table_name, region):

        policy_arn = self.get_role_policy_arn(aws_session, role_name, policy_name)
        if policy_arn is not None:
            return policy_arn

        dynamodb_resource = aws_session.resource('dynamodb', region_name=region)
        table = dynamodb_resource.Table(websocket_table_name)
        websocket_policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': [
                        'dynamodb:DeleteItem',
                        'dynamodb:GetItem',
                        'dynamodb:PutItem',
                        'dynamodb:Scan',
                    ],
                    'Resource': table.table_arn,
                },
                {
                    'Effect': 'Allow',
                    'Action': [
                        'execute-api:ManageConnections',
                    ],
                    'Resource': api_arn,
                },
            ]
        }

        iam_client = aws_session.client('iam')
        try:
            response = iam_client.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(websocket_policy))
        except ClientError as e:
            return None
        policy_arn = response['Policy']['Arn']

        try:
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as e:
            return None
        return policy_arn

    def create_route_and_integration(self, aws_session, lambda_role_name, websocket_lambda_policy, api_id, route_name, lambda_function_name, lambda_handler_name, lambda_srcfile, websocket_table_name, master_password, region):

        env_vars = {
            'Variables': {
                'TableName': websocket_table_name,
                'MasterPassword': master_password
            }
        }

        lambda_arn = create_lambda_function(aws_session, lambda_function_name, lambda_srcfile, lambda_handler_name, lambda_role_name, region, env_vars)
        if lambda_arn is None:
            return None

        sections = lambda_arn.split(':')
        account_id = sections[4]

        api_arn = f'arn:aws:execute-api:{region}:{account_id}:{api_id}/*'
        source_arn = f'{api_arn}/{route_name}'
        lambda_client = aws_session.client('lambda', region_name=region)
        try:
            lambda_client.add_permission(FunctionName=lambda_function_name, StatementId=f'{lambda_function_name}-invoke', Action='lambda:InvokeFunction', Principal='apigateway.amazonaws.com', SourceArn=source_arn)
        except ClientError as e:
            return None

        policy_arn = self.attach_role_policy(aws_session, lambda_role_name, websocket_lambda_policy, api_arn, websocket_table_name, region)
        if policy_arn is None:
            return None

        integration_uri = f'arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations'
        api_client = aws_session.client('apigatewayv2', region_name=region)
        try:
            response = api_client.create_integration(ApiId=api_id, IntegrationType='AWS_PROXY', IntegrationMethod='POST', IntegrationUri=integration_uri)
        except ClientError as e:
            return None
        integration_id = response['IntegrationId']

        target = f'integrations/{integration_id}'
        try:
            response = api_client.create_route(ApiId=api_id, RouteKey=route_name, Target=target)
        except ClientError as e:
            return None
        return response['RouteId']

    def get_role_policy_arn(self, aws_session, role_name, policy_name):
        iam_client = aws_session.client('iam')
        try:
            response = iam_client.list_attached_role_policies(RoleName=role_name)
        except ClientError as e:
            return None

        while True:
            for policy in response['AttachedPolicies']:
                if policy['PolicyName'] == policy_name:
                    return policy['PolicyArn']

            if response['IsTruncated']:
                try:
                    response = iam_client.list_attached_role_policies(Marker=response['Marker'])
                except ClientError as e:
                    return None
            else:
                return None

    def delete_lambda_functions(self, aws_session, region, lambdas, lambda_role_name, websocket_lambda_policy):

        lambda_client = aws_session.client('lambda', region_name=region)

        for lambda_function in lambdas:
            try:
                lambda_client.delete_function(FunctionName=lambda_function['name'])
            except ClientError as e:
                pass
            else:
                print(f'[+] Deleted Lambda function: {lambda_function["name"]}')

        iam_client = aws_session.client('iam')
        policy_arn = self.get_role_policy_arn(aws_session, lambda_role_name, websocket_lambda_policy)
        if policy_arn is not None:
            try:
                iam_client.detach_role_policy(RoleName=lambda_role_name, PolicyArn=policy_arn)
                iam_client.delete_policy(PolicyArn=policy_arn)
            except ClientError as e:
                pass
            else:
                print(f'[+] Deleted IAM policy: {websocket_lambda_policy}')

        delete_iam_role(aws_session, lambda_role_name)

    def create_websocket_api(self, aws_session, lambda_role_name, websocket_lambda_policy, api_name, region, lambdas, websocket_table_name, master_password, path_name):

        selection_expression = '$request.body.action'

        api_client = aws_session.client('apigatewayv2', region_name=region)
        try:
            response = api_client.create_api(Name=api_name, ProtocolType='WEBSOCKET', RouteSelectionExpression=selection_expression)
        except ClientError as e:
            return None

        api_id = response['ApiId']
        api_endpoint = response['ApiEndpoint']

        print('[+] API Gateway created "{}"'.format(api_name))

        for lambda_function in lambdas:
            route_id = self.create_route_and_integration(aws_session, lambda_role_name, websocket_lambda_policy, api_id, lambda_function['route'], lambda_function['name'], lambda_function['lambda_handler'], lambda_function['file'], websocket_table_name, master_password, region)
            if route_id is None:
                return None
            filename, ext = os.path.splitext(lambda_function['file'])
            deployment_package = f'{filename}.zip'
            if os.path.exists(deployment_package):
                os.remove(deployment_package)
            else:
                pass
            print('[+] "{}" lambda function and "{}" route created'.format(lambda_function['name'], lambda_function['route']))

        try:
            response = api_client.create_deployment(ApiId=api_id)
        except ClientError as e:
            return None
        deployment_id = response['DeploymentId']
        if response['DeploymentStatus'] == 'FAILED':
            logging.error('[!] WebSocket deployment failed')
            return None

        try:
            api_client.create_stage(ApiId=api_id, DeploymentId=deployment_id, StageName=path_name)
        except ClientError as e:
            return None

        return f'{api_endpoint}/{path_name}'

    def get_websocket_api_id(self, aws_session, api_name, region):

        api_client = aws_session.client('apigatewayv2', region_name=region)
        try:
            apis = api_client.get_apis()
        except ClientError as e:
            return None

        # Search the batch
        while True:
            for api in apis['Items']:
                if api['Name'] == api_name:
                    return api['ApiId']
            if 'NextToken' in apis:
                try:
                    apis = api_client.get_apis(NextToken=apis['NextToken'])
                except ClientError as e:
                    return None
            else:
                return None

    def delete_websocket_api(self, aws_session, api_name, region):

        print(api_name)
        api_id = self.get_websocket_api_id(aws_session, api_name, region)
        if api_id is None:
            return False

        api_client = aws_session.client('apigatewayv2', region_name=region)
        try:
            api_client.delete_api(ApiId=api_id)
        except ClientError as e:
            print(e)
            return False
        return True

    def delete_websocket_resources(self, aws_session, region, lambdas, api_name, websocket_table_name, lambda_role_name, websocket_lambda_policy):

        if self.delete_websocket_api(aws_session, api_name, region):
            print(f'[+] Deleted WebSocketAPI: {api_name}')
        if self.delete_websockets_table(aws_session, websocket_table_name, region):
            print(f'[+] Deleted Websockets table: {websocket_table_name}')
        self.delete_lambda_functions(aws_session, region, lambdas, lambda_role_name, websocket_lambda_policy)

    def deploy(self, aws_access_key_id, aws_secret_access_key, stage, master_password, delete_resources=False, region='eu-west-3', path_name='dev'):

        ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

        lambdas = [
            {
                "name": "WebSocketConnect_{}".format(stage),
                "route": "$connect",
                "file": "{}/lambda_files/websocket_connect.py".format(ROOT_DIR),
                "lambda_handler": "lambda_handler"
            },
            {
                "name": "WebSocketDisonnect_{}".format(stage),
                "route": "$disconnect",
                "file": "{}/lambda_files/websocket_disconnect.py".format(ROOT_DIR),
                "lambda_handler": "lambda_handler"
            },
            {
                "name": "WebSocketGetClients_{}".format(stage),
                "route": "getclients",
                "file": "{}/lambda_files/websocket_getclients.py".format(ROOT_DIR),
                "lambda_handler": "lambda_handler"
            },
            {
                "name": "WebSocketSendMessage_{}".format(stage),
                "route": "sendmsg",
                "file": "{}/lambda_files/websocket_send_msg.py".format(ROOT_DIR),
                "lambda_handler": "lambda_handler"
            },
            {
                "name": "WebSocketWhoami_{}".format(stage),
                "route": "whoami",
                "file": "{}/lambda_files/websocket_whoami.py".format(ROOT_DIR),
                "lambda_handler": "lambda_handler"
            },
            {
                "name": "WebSocketFastSendmsg_{}".format(stage),
                "route": "fast_sendmsg",
                "file": "{}/lambda_files/websocket_fast_sendmsg.py".format(ROOT_DIR),
                "lambda_handler": "lambda_handler"
            },
        ]

        api_name = 'websocket-lambda-api-{}'.format(stage)
        websocket_table_name = 'websocket-lambda-table-{}'.format(stage)
        lambda_role_name = 'websocket-lambda-role-{}'.format(stage)
        websocket_lambda_policy = 'websocket-lambda-policy-{}'.format(stage)

        aws_session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )

        if delete_resources:
            self.delete_websocket_resources(aws_session, region, lambdas, api_name, websocket_table_name, lambda_role_name, websocket_lambda_policy)
            self.delete_environment_item_from_db(aws_session, stage, region)
            print('[+] Deleted resources')
            return

        if not self.create_websockets_table(aws_session, websocket_table_name, region):
            pass

        api_endpoint = self.create_websocket_api(aws_session, lambda_role_name, websocket_lambda_policy, api_name, region, lambdas, websocket_table_name, master_password, path_name)

        if api_endpoint is None:
            exit(1)

        self.create_environment_db_record(aws_session, stage, api_endpoint, master_password, region)

        print(f'[+] Created C2 infra at {api_endpoint}')
        return api_endpoint

    def load_environments(self, aws_id, aws_secret):
        aws_session = boto3.Session(
            aws_access_key_id=aws_id,
            aws_secret_access_key=aws_secret,
        )
        if self.table_exists(aws_session, AWSC2_MASTER_TABLE):
            pass

    def table_exists(self, aws_session, tabe_name, region):
        client = aws_session.client('dynamodb', region_name=region)
        response = client.list_tables()
        return tabe_name in response['TableNames']

    def create_awsc2_master_table(self, aws_session, table_name, region):
        try:
            dynamodb = aws_session.resource('dynamodb', region_name=region)
            dynamodb.create_table(
                TableName=table_name,
                KeySchema=
                [
                    {
                        'AttributeName': 'environment',
                        'KeyType': 'HASH'
                    }
                ],
                AttributeDefinitions=
                [
                    {
                        'AttributeName': 'environment',
                        'AttributeType': 'S'
                    }
                ],
                ProvisionedThroughput=
                {
                    'ReadCapacityUnits': 1,
                    'WriteCapacityUnits': 1
                }
            )
            print('[+] Created master table "{}" in this AWS account'.format(AWSC2_MASTER_TABLE))
            return True
        except ClientError as e:
            print('[!] Error creating master table "{}" in this AWS account'.format(AWSC2_MASTER_TABLE))
            return False

    def create_environment_db_record(self, aws_session, environment_name, url, master_password, region):

        environment = {
            'environment': environment_name,
            'url': url,
            'master_password': master_password
        }

        dynamodb = aws_session.resource('dynamodb', region_name=region)
        table = dynamodb.Table(AWSC2_MASTER_TABLE)

        try:
            table.put_item(Item=environment)
        except ClientError as e:
            self.create_awsc2_master_table(aws_session, AWSC2_MASTER_TABLE, region)
            counter = 0
            while counter < 60:
                try:
                    counter += 1
                    table = dynamodb.Table(AWSC2_MASTER_TABLE)
                    table.put_item(Item=environment)
                except ClientError as e:
                    time.sleep(1)
                    pass

    def get_all_environments(self, aws_id, aws_secret, region='eu-west-3'):
        aws_session = boto3.Session(
            aws_access_key_id=aws_id,
            aws_secret_access_key=aws_secret,
        )
        try:
            dynamodb = aws_session.resource('dynamodb', region_name=region)
            table = dynamodb.Table(AWSC2_MASTER_TABLE)
        except ClientError:
            return []
        return table.scan()['Items']

    def delete_environment_item_from_db(self, aws_session, environment_name, region='eu-west-3'):
        try:
            dynamodb = aws_session.resource('dynamodb', region_name=region)
            table = dynamodb.Table(AWSC2_MASTER_TABLE)
        except ClientError as e:
            return False
        return table.delete_item(Key={'environment': environment_name})
