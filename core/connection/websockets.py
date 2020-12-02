import json
import time

import websocket
import threading

from queue import SimpleQueue, Empty

from core.connection.actions import ACTION_SEND_MESSAGE
from core.connection.service_keys import KEY_PAYLOAD, KEY_ACTION, KEY_SERVICE, KEY_SEND_MESSAGE_TO, KEY_FROM


class C2Websocket:

    def __init__(self, url, user_name, connection_type, master_password=None):
        self.url = url
        self.user_name = user_name
        self.connection_type = connection_type
        self.master_password = master_password
        self.recv_queues = {}
        self.send_queue = SimpleQueue()
        self.connection_string = self.connect_to_websocket()

    def get_url_connection(self):
        return '{}?name={}&masterPassword={}&userType={}'.format(self.url, self.user_name, self.master_password, self.connection_type)

    def connect_to_websocket(self):
        ws = websocket.create_connection(self.get_url_connection())
        ws.settimeout(0.05)
        websocket_thread = threading.Thread(target=self._listen_websocket_messages, args=(ws,))
        websocket_thread.start()
        return self.get_url_connection()

    def send_action(self, action, payload=None, drop_queued_action_responses=False, action_options=None):
        if drop_queued_action_responses:
            self.drop_queued_action_responses(action)
        action_to_send = {KEY_ACTION: action, KEY_PAYLOAD: payload}
        if action_options:
            for action_key, action_value in action_options.items():
                action_to_send[action_key] = action_value
        self.send_queue.put_nowait(json.dumps(action_to_send))

    def send_service(self, client_id, service, payload, drop_queued_service_responses=False):
        if drop_queued_service_responses:
            self.drop_queued_service_responses(ACTION_SEND_MESSAGE, client_id, service)
        payload[KEY_SERVICE] = service
        self.send_action(ACTION_SEND_MESSAGE, payload, action_options={KEY_SEND_MESSAGE_TO: client_id})

    def recv_action_response(self, action, block=True, timeout=None):
        try:
            return self.recv_queues[action].get(block=block, timeout=timeout)
        except KeyError:
            if block:
                self.recv_queues[action] = SimpleQueue()
                self.recv_action_response(action, block)
        except KeyboardInterrupt:
            return

    def recv_service_response(self, client_id, service, block=True, timeout=None):
        try:
            return self.recv_queues[(ACTION_SEND_MESSAGE, client_id, service)].get(block=block, timeout=timeout)
        except KeyError:
            if block:
                self.recv_queues[(ACTION_SEND_MESSAGE, client_id, service)] = SimpleQueue()
                return self.recv_service_response(client_id, service, block)
        except KeyboardInterrupt:
            return

    def drop_queued_action_responses(self, action):
        self.recv_queues[action] = SimpleQueue()

    def drop_queued_service_responses(self, action, client_id, service):
        self.recv_queues[(action, client_id, service)] = SimpleQueue()

    def _add_service_message_to_recv_queue(self, action, client_id, service, payload):
        if (action, client_id, service) not in self.recv_queues:
            self.recv_queues[(action, client_id, service)] = SimpleQueue()
        self.recv_queues[(action, client_id, service)].put(payload)

    def _add_action_message_to_recv_queue(self, action, payload):
        if action not in self.recv_queues:
            self.recv_queues[action] = SimpleQueue()
        self.recv_queues[action].put(payload)

    def _listen_websocket_messages(self, ws):
        self.keep_listening = True
        try:
            while self.keep_listening:
                try:
                    message = ws.recv()
                    # print('Recv {} -> {}'.format(self.user_name, message))

                except websocket._exceptions.WebSocketTimeoutException:
                    if not self.send_queue.empty():
                        to_send = self.send_queue.get()
                        ws.send(to_send)
                        # print('Sent {} -> {}'.format(self.user_name, to_send))
                    continue

                try:
                    json_message = json.loads(message)
                except json.decoder.JSONDecodeError as e:
                    continue

                if KEY_ACTION not in json_message:
                    continue
                action = json_message[KEY_ACTION]

                if KEY_PAYLOAD in json_message and KEY_FROM in json_message and KEY_SERVICE in json_message[KEY_PAYLOAD]:
                    self._add_service_message_to_recv_queue(action, json_message[KEY_FROM], json_message[KEY_PAYLOAD][KEY_SERVICE], json_message[KEY_PAYLOAD])
                else:
                    self._add_action_message_to_recv_queue(action, json_message[KEY_PAYLOAD])
            time.sleep(1)
            ws.close()
        except websocket._exceptions.WebSocketConnectionClosedException:
            self.connect_to_websocket()

    def stop(self):
        self.keep_listening = False
