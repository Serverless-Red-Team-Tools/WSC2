import json
import os

DEFAULT_CONFIG_FILE_NAME = 'aws_config.json'


def environment_exists(environment_name, file_name):
    config = load_config(file_name)
    if 'environments' in config:
        for env in config['environments']:
            if env['name'] == environment_name:
                return True
    return False


def config_exists(file_name):
    return os.path.isfile(file_name)


def create_config_file(file_name):
    save_config({'environments': []}, file_name)


def load_config(file_name):
    config = {'environments': []}
    try:
        with open(file_name, 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        pass
    return config


def save_config(config, file_name):
    with open(file_name, 'w') as config_file:
        config_file.write(json.dumps(config, indent=2))


def add_environment_to_config(environment, file_name):
    config_file = load_config(file_name)
    config_file['environments'].append(environment)
    json_config = json.dumps(config_file, indent=2)
    with open(file_name, 'w') as config:
        config.write(json_config)


def remove_environment_from_config(environment_name, file_name):
    config = load_config(file_name)
    if 'environments' in config:
        remove = None
        for env in config['environments']:
            if env['name'] == environment_name:
                remove = env
        if remove is not None:
            config['environments'].remove(remove)
        json_config = json.dumps(config, indent=2)
        with open(file_name, 'w') as config:
            config.write(json_config)
