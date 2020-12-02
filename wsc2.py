import argparse
import sys

import boto3
import logging
import botocore
import time
from getpass import getpass

from aws.aws_deployment import AwsDeplpyment
from config.config import load_config, add_environment_to_config, create_config_file, config_exists, environment_exists, DEFAULT_CONFIG_FILE_NAME, remove_environment_from_config, save_config
from aws.lambda_util import random_string
from core.connection.connection_factory import Factory, PROVIDER_AWS_WEBSOCKETS
from core.manager import C2Manager
from core.master import Master

aws_id = None
aws_secret = None


def check_aws_credentials(aws_id, aws_secret):
    try:
        print('[*] Checking AWS credentials')

        aws_session = boto3.Session(
            aws_access_key_id=aws_id,
            aws_secret_access_key=aws_secret,
        )
        sts = aws_session.client('sts')
        sts.get_caller_identity()
        return True
    except botocore.exceptions.NoCredentialsError:
        print('[-] Invalid AWS credentials')
        return False
    except botocore.exceptions.ClientError:
        print('[-] Invalid AWS credentials')
        return False
    except:
        print('[-] Error checking credentials.')
        return False


def show_aws_key_steps():
    print('\t1) To get it you need an AWS account and go to:')
    print('\t   https://console.aws.amazon.com/iam/home?#/security_credentials')
    print('\t2) Click on the "Access keys (access key ID and secret access key)" dropdown')
    print('\t3) If you don\'t have the AWS key or don\'t remember it, create a new')
    print('\t4) Keep this key safe, it is needed to every deploy or remove of a environment.\n\t   The key is not needed to connect to an environment that has already been deployed previously.')


def request_aws_credentials(file_name):
    global aws_id
    global aws_secret
    if aws_id is not None and aws_secret is not None:
        return aws_id, aws_secret

    aws_steps_shown = False
    config = load_config(file_name)
    if 'aws_id' not in config or config['aws_id'] == '':
        print('[*] AWS ID not found in the "{}" configuration file.'.format(file_name))
        print('[*] Access Key ID needed')
        show_aws_key_steps()
        aws_steps_shown = True
        access_key_id = input('[*] Access Key ID: ')
        aws_id = access_key_id
    else:
        aws_id = config['aws_id']
        print('[*] Access Key ID: {}'.format(aws_id))

    if not aws_steps_shown:
        print('[*] Secret key needed')
        show_aws_key_steps()
    aws_secret = getpass('[*] Insert your Secret Key: ')

    if not check_aws_credentials(aws_id, aws_secret):
        exit(1)
    else:
        print('[+] Credentials OK.')

    return aws_id, aws_secret


def sync_environments(file_name):
    global aws_id, aws_secret

    config = load_config(file_name)
    aws_id, aws_secret = request_aws_credentials(file_name)

    if aws_id not in config:
        config['aws_id'] = aws_id

    aws_environments = AwsDeplpyment().get_all_environments(aws_id, aws_secret)
    environments = []
    for item in aws_environments:
        environments.append({
            'name': item['environment'],
            'url': item['url'],
            'master-password': item['master_password']
        })
    config['environments'] = environments
    save_config(config, file_name)
    print('[+] Configuration file synchronized with AWS')
    list_environments(file_name)


def deploy(file_name, environment_name):
    global aws_id, aws_secret

    if not config_exists(file_name):
        print('[*] Configuration file "{}" not found, creating one.'.format(file_name))
        create_config_file(file_name)
    else:
        print('[*] Loading configuration file "{}"'.format(file_name))

    config = load_config(file_name)
    if environment_exists(environment_name, file_name):
        print('[-] The "{}" environment was created before as indicated in the "{}" configuration file. Indicate another name with the -n (--env-name) option or delete it from the configuration file.'.format(environment_name, file_name))
        exit(1)

    aws_id, aws_secret = request_aws_credentials(file_name)

    print('[+] Creating infrastructure in AWS')

    master_password = random_string(16)
    url = AwsDeplpyment().deploy(aws_id, aws_secret, environment_name, master_password)

    if 'environments' not in config:
        config['environments'] = []

    print('[+] Saving "{}" configuration file'.format(file_name))
    add_environment_to_config({
        'name': environment_name,
        'url': url,
        'master-password': master_password
    }, file_name)

    print('[+] Now you can connect to your new environment:')
    connection_command = '\n\tpython3 wsc2.py -c -n {}'.format(environment_name)
    if file_name != DEFAULT_CONFIG_FILE_NAME:
        connection_command = '\n\tpython3 wsc2.py -c -n {} -f {}'.format(environment_name, file_name)

    print(connection_command)
    print()


def remove(file_name, environment_name):
    global aws_id, aws_secret

    print('[!] Are you sure you want to delete "{}" environment? y/N'.format(environment_name))
    user_input = input()

    if user_input.lower() != 'y' and user_input == '':
        exit()

    aws_id, aws_secret = request_aws_credentials(file_name)

    config = load_config(file_name)
    if 'environments' not in config:
        config['environments'] = []
    environment_to_delete = None
    for environment in config['environments']:
        if environment['name'] == environment_name:
            environment_to_delete = environment
            break
    if environment_to_delete is None:
        print('[!] There is no "{}" environment in your local "{}" configuration file. Do you want to sync the config file with AWS? Y/n'.format(environment_name, file_name))
        user_input = input()
        if user_input.lower() == 'y' or user_input == '':
            sync_environments(file_name)
            time.sleep(1)

    config = load_config(file_name)
    environment_to_delete = None
    for environment in config['environments']:
        if environment['name'] == environment_name:
            environment_to_delete = environment
            break
    if environment_to_delete is None:
        print('[!] Environment not found. Do you want to try to delete it anyway? y/N'.format(environment_name))
        user_input = input()
        if user_input.lower() == 'n' or user_input == '':
            return

    print('[+] Removing "{}" environment from AWS'.format(environment_name))
    AwsDeplpyment().deploy(aws_id, aws_secret, environment_name, None, True)
    remove_environment_from_config(environment_name, file_name)


def connect(file_name, environment_name):
    config = load_config(file_name)
    environment_websocket = None
    for environment in config['environments']:
        if environment['name'] == environment_name:
            master = Master(
                environment_name,
                C2Manager(
                    Factory(PROVIDER_AWS_WEBSOCKETS, {'url': environment['url']}),
                    environment['master-password'],
                    environment_name
                )
            )
            master.show_c2_menu()
    if environment_websocket is None:
        print('[-] "{}" environment not found in the "{}" configuration file. Do you want to sync "{}" configuration file from AWS? Y/n'.format(environment_name, file_name, file_name))
        user_input = input()
        if user_input.lower() == 'y' or user_input == '':
            sync_environments(file_name)
    config = load_config(file_name)
    for environment in config['environments']:
        if environment['name'] == environment_name:
            master = Master(
                environment_name,
                C2Manager(
                    Factory(PROVIDER_AWS_WEBSOCKETS, {'url': environment['url']}),
                    environment['master-password'],
                    environment_name
                )
            )
            master.show_c2_menu()

    print('[-] {} environment not found in the {} configuration file. Add it manually to config file or create a new environment with -d (--deploy) option'.format(environment_name, file_name))


def list_environments(file_name):
    if not config_exists(file_name):
        print('[-] Configuration file "{}" not found'.format(file_name))
        exit(1)
    else:
        config = load_config(file_name)
        if 'environments' not in config or len(config['environments']) == 0:
            print('[!] No environments found in the {} configuration file'.format(file_name))
        else:
            print('\nEnvironments from {} configuration file:\n'.format(file_name))
            for environment in config['environments']:
                print('- {} ({}) | {}'.format(environment['name'], environment['url'], environment['master-password']))
            print()


if __name__ == '__main__':

    logging.getLogger('boto3').setLevel(logging.INFO)
    logging.getLogger('botocore').setLevel(logging.INFO)
    logging.getLogger('s3transfer').setLevel(logging.INFO)
    logging.getLogger('urllib3').setLevel(logging.CRITICAL)
    logging.getLogger('root').setLevel(logging.CRITICAL)
    logging.getLogger('asyncio').setLevel(logging.CRITICAL)

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-d', '--deploy', help='Option to deploy a new C2 to AWS. You must include the option -n or --env-name.', default=False, action='store_true')
    group.add_argument('-r', '--remove', help='Option to remove a C2 from AWS. You must include the option -n or --env-name.', default=False, action='store_true')
    group.add_argument('-c', '--connect', help='Connect to a C2 deploy. You must include the option -n or --env-name.', default=False, action='store_true')
    group.add_argument('-l', '--list', help='List environments from the config file.', default=False, action='store_true')

    parser.add_argument('-s', '--sync', help='Sync your config file with the AWS deployments', default=False, action='store_true')
    parser.add_argument('-n', '--env-name', help='The deployment environment name to create or connect to it.', default="default")
    parser.add_argument('-f', '--file-name', help='The deployment environment file name to create or connect to it. In case of deployment must include the AWS keys, see aws_config.json example file.', default="aws_config.json")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.sync:
        sync_environments(args.file_name)

    if args.deploy:
        deploy(args.file_name, args.env_name)

    elif args.remove:
        remove(args.file_name, args.env_name)

    elif args.connect:
        connect(args.file_name, args.env_name)

    elif args.list:
        list_environments(args.file_name)
