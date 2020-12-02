from core.connection.websockets import C2Websocket

PROVIDER_AWS_WEBSOCKETS = 0

PROVIDER_AWS_WEBSOCKETS_PARAM_URL = 'url'
PROVIDER_AWS_WEBSOCKETS_PARAM_MASTER_PASSWORD = 'master_password'

CONNECTION_TYPE_CLIENT = 'client'
CONNECTION_TYPE_MASTER = 'master'


class Factory:

    def __init__(self, provider, connection_params):
        self.provider = provider
        self.connection_params = connection_params

    def create(self, connection_name, connection_type, connection_master_password=None):
        if self.provider == PROVIDER_AWS_WEBSOCKETS:
            return C2Websocket(
                self.connection_params[PROVIDER_AWS_WEBSOCKETS_PARAM_URL],
                connection_name,
                connection_type,
                connection_master_password
            )
