import json
import logging
import os
import time
import zipfile
import zlib
import boto3
import string
import random
from botocore.exceptions import ClientError


def get_iam_role_arn(aws_session, iam_role_name):
    iam_client = aws_session.client('iam')
    try:
        result = iam_client.get_role(RoleName=iam_role_name)
    except ClientError as e:
        return None
    return result['Role']['Arn']


def iam_role_exists(aws_session, iam_role_name):
    if get_iam_role_arn(aws_session, iam_role_name) is None:
        return False
    return True


def create_iam_role_for_lambda(aws_session, iam_role_name):
    lambda_assume_role = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': '',
                'Effect': 'Allow',
                'Principal': {
                    'Service': 'lambda.amazonaws.com'
                },
                'Action': 'sts:AssumeRole'
            }
        ]
    }
    iam_client = aws_session.client('iam')
    try:
        result = iam_client.create_role(RoleName=iam_role_name, AssumeRolePolicyDocument=json.dumps(lambda_assume_role))
    except ClientError as e:
        return None
    lambda_role_arn = result['Role']['Arn']

    lambda_policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    try:
        iam_client.attach_role_policy(RoleName=iam_role_name, PolicyArn=lambda_policy_arn)
    except ClientError as e:
        return None

    return lambda_role_arn


def delete_iam_role(aws_session, role_name):
    iam_client = aws_session.client('iam')
    try:
        response = iam_client.list_attached_role_policies(RoleName=role_name)
    except ClientError as e:
        return

    while True:
        for policy in response['AttachedPolicies']:
            try:
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
            except ClientError as e:
                pass

        if response['IsTruncated']:
            try:
                response = iam_client.list_attached_role_policies(Marker=response['Marker'])
            except ClientError as e:
                break
        else:
            print(f'[+] Detached all policies from IAM role {role_name}')
            break

    try:
        iam_client.delete_role(RoleName=role_name)
    except ClientError as e:
        pass
    else:
        print(f'[+] Deleted IAM role: {role_name}')


def create_lambda_deployment_package(srcfile, deployment_package):
    with zipfile.ZipFile(deployment_package, mode='w', compression=zipfile.ZIP_DEFLATED, compresslevel=zlib.Z_DEFAULT_COMPRESSION) as deploy_pkg:
        try:
            head, tail = os.path.split(srcfile)
            deploy_pkg.write(srcfile, f'lambda_files/{tail}')
        except Exception as e:
            return False
    return True


def deploy_lambda_function(aws_session, name, iam_role, handler, deployment_package, runtime, env_vars, region):
    with open(deployment_package, mode='rb') as pkg:
        deploy_pkg = pkg.read()

    # Create the Lambda function
    # Note: create_function() raises an InvalidParameterValueException if its
    # newly-created IAM role has not been replicated to the appropriate region
    # yet. To resolve this situation, the operation is retried several times.
    lambda_client = aws_session.client('lambda', region_name=region)
    retry_time = 1
    max_retry_time = 32
    while retry_time <= max_retry_time:
        try:
            result = lambda_client.create_function(FunctionName=name, Runtime=runtime, Role=iam_role, Handler=handler, Environment=env_vars, Code={'ZipFile': deploy_pkg})
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidParameterValueException':
                time.sleep(retry_time)
                retry_time *= 2
            else:
                return None
        else:
            return result
    return None


def create_lambda_function(aws_session, function_name, srcfile, handler_name, role_name, region, env_vars={}):
    filename, ext = os.path.splitext(srcfile)
    deployment_package = f'{filename}.zip'
    if not create_lambda_deployment_package(srcfile, deployment_package):
        return None
    if iam_role_exists(aws_session, role_name):
        iam_role_arn = get_iam_role_arn(aws_session, role_name)
    else:
        iam_role_arn = create_iam_role_for_lambda(aws_session, role_name)
        if iam_role_arn is None:
            return None

    runtime = 'python3.7'

    head, tail = os.path.split(filename)
    microservice = deploy_lambda_function(aws_session, function_name, iam_role_arn, f'lambda_files/{tail}.{handler_name}', deployment_package, runtime, env_vars, region)

    if microservice is None:
        return None
    lambda_arn = microservice['FunctionArn']
    return lambda_arn


def random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def delete_lambda_function(aws_session, function_name, iam_role_name, region):
    lambda_client = aws_session.client('lambda', region_name=region)
    try:
        lambda_client.delete_function(FunctionName=function_name)
    except ClientError as e:
        return False

    delete_iam_role(aws_session, iam_role_name)
    return True


def invoke_lambda_function_synchronous(aws_session, name, parameters, region):
    params_bytes = json.dumps(parameters).encode()
    lambda_client = aws_session.client('lambda', region_name=region)
    try:
        response = lambda_client.invoke(FunctionName=name, InvocationType='RequestResponse', LogType='Tail', Payload=params_bytes)
    except ClientError as e:
        return None
    return response


def get_lambda_arn(aws_session, lambda_name, region):
    lambda_client = aws_session.client('lambda', region_name=region)
    try:
        response = lambda_client.get_function(FunctionName=lambda_name)
    except ClientError as e:
        return None
    return response['Configuration']['FunctionArn']
