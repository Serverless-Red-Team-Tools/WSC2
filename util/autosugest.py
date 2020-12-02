from prompt_toolkit.auto_suggest import Suggestion, AutoSuggest
import shlex


def get_prompt_completer(c2_manager):
    def get_suggestion_from_list(user_input, list):
        for item in list:
            if item.lower().startswith(user_input.lower()):
                return item

    def get_client_suggestion(user_input):
        return get_suggestion_from_list(user_input, [client['userName']['S'] for client in c2_manager.get_cached_clients()])

    def get_mode_suggestion(user_input):
        return get_suggestion_from_list(user_input, ['direct', 'relay'])

    def get_command_suggestion(user_input):
        return get_suggestion_from_list(user_input, ['ls', 'cat', 'pwd', 'echo', 'base64', 'ls -l', 'ls -la', 'ls -lah', 'curl', 'nslookup', 'dig'])

    def get_local_host_suggestion(user_input):
        return get_suggestion_from_list(user_input, ['0.0.0.0', '127.0.0.1', '192.168.', '172.', '10.'])

    commands = [
        'clients',
        'clear',
        'help',
        'kill <client>',
        '! {}'.format('<command> ' * 100),
        'genclient <client>',
        'loadmodule <client> <module_name>',
        'exit'
    ]

    for module in c2_manager.get_loaded_modules():
        for command in module.get_commands():
            commands.append('{} {}'.format(command[0], command[1]))

    substitution_tokens = {
        '<client>': get_client_suggestion,
        '<mode>': get_mode_suggestion,
        '<command>': get_command_suggestion,
        '<local_host>': get_local_host_suggestion,
        '<remote_host>': None,
        '<module>': None,
    }

    return C2MenuAutoSuggest(c2_manager.get_loaded_modules(), commands, substitution_tokens)


class C2MenuAutoSuggest(AutoSuggest):

    def __init__(self, loaded_modules, commands=[], substitution_tokens={}):
        self.loaded_modules = loaded_modules
        self.substitution_tokens = substitution_tokens
        self.commands = commands

    def write_file(self, text):
        with open('test', 'a+') as f:
            f.write('{}\n'.format(text))

    def get_suggestion(self, buffer, document):
        text = document.text.rsplit('\n', 1)[-1]
        text_parsed = shlex.split(text)
        if text != '':
            for test_command in self.commands:
                test_command_replaced = test_command
                for token in self.substitution_tokens:
                    test_command_replaced = test_command.replace(token, '')
                if len(shlex.split(text)) < 1:
                    text_replaced = text
                else:
                    text_replaced = shlex.split(text)[0]
                # self.write_file(str(text_replaced))
                if test_command_replaced.startswith(text_replaced):
                    test_command_parsed = shlex.split(test_command)
                    if len(text_parsed) <= len(test_command_parsed):
                        to_test = test_command_parsed[len(text_parsed) - 1]
                        # self.write_file('{} -> {}'.format(to_test, text_parsed[len(text_parsed)-1]))
                        if to_test in self.substitution_tokens and self.substitution_tokens[to_test] is not None:
                            part_input = text_parsed[len(text_parsed) - 1]
                            part_suggested = self.substitution_tokens[to_test](part_input)
                            if part_suggested is None:
                                return Suggestion('')
                            return Suggestion(part_suggested[len(part_input):])
                        return Suggestion(to_test[len(text):])
                    return Suggestion(test_command[len(text):])
        else:
            return Suggestion('help')
