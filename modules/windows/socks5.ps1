


$socksCode = {


    $server = $args[0]
    $ip = $args[1]
    $port = $args[2]
    $to = $args[3]
    #
    $logfile = "tunnel-$($ip)-$($port).log"


    Function Write-Log
    {
    Param ([string]$text)

    if($logfile){
        $text = (Get-Date -Format "[HH:mm K dd/MM/yyyy] ").toString() + $text
        Add-content $logfile -value $text
        }

        # Show message in verbose mode
        Write-Verbose $text
    }

    Function Connect-Websocket{
        Param(
        [Parameter(Mandatory = $true)]
        [string]$server
        )

        try{
            $ws = New-Object System.Net.WebSockets.ClientWebSocket
            $ct = New-Object System.Threading.CancellationToken

            Write-Log "Connecting to $($server)"

            $Conn = $ws.ConnectAsync($server, $ct)

            # Wait until the connection is established
            while(!$Conn.IsCompleted) {
                Start-Sleep -Milliseconds 100
            }

            if($Conn.Status -eq "Faulted"){
                # Connection failed
                $status = 400
                Write-Log "Error establishing connection to $($server)"
            }

            if($ws.State -eq "Open"){
                # We are connected
                $status = 200
                Write-Log "Connection established"
            }

        }catch{
            $ws = $null
            $ct = $null
            # Something is bad
            $status = 400

            Write-Log "Error establishing connection. $($PSItem.Exception.Message)"
        }

        return @{"status" = $status;
            "ws" = $ws;
            "ct" = $ct
        };
    }

    Function Send-Message {
        Param(
        [Parameter(Mandatory = $true)]
        [hashtable]$msg,

        [Parameter(Mandatory = $true)]
        $to,

        $Timeout = 30
        )

        if($ws.State -eq "Open"){
            try{
                # Prepare data

                $data = @{"action" = "fast_sendmsg"; # Change to proper route in lambda
                    "to" =  $to;
                    "payload" = $msg
                    }

                $dataJSON = (New-Object -TypeName PSObject -Prop $data) | ConvertTo-Json -Depth 6

                $sendArray = @()
                $Encoding = [System.Text.Encoding]::UTF8
                $sendArray = $Encoding.GetBytes($dataJSON)

                $dataBytes = New-Object System.ArraySegment[byte] -ArgumentList @(,$sendArray)

                $ConnSend = $ws.SendAsync($dataBytes, [System.Net.WebSockets.WebSocketMessageType]::Text, [System.Boolean]::TrueString, $ct)
        }catch{
        Write-Log "Failed to send message. $($PSItem.Exception.Message)"
        }


        }else{
            Write-Log "Tried to send message but the connection is closed: $($msg)"
        }
    }


    ## Create websockets connection and try to connect to destination
    $Websockets = Connect-Websocket -server "wss://vghdsxu3hg.execute-api.eu-west-3.amazonaws.com/dev?name=PruebasTunel&userType=tunnel"

    if($Websockets.status -eq 200){
        $ws = $Websockets.ws
        $ct = $Websockets.ct
    }else{
        exit # For now exit
    }

    # Try to connect to destination
    Try{
        # Create the connection
        $conn = New-Object  System.Net.Sockets.TcpClient($ip, $port)
    }catch{
        # Connection failed KO message
        Send-Message -msg @{"service" =  "socks5"; "result" = "KO"; "reason" = $PSItem.Exception.Message} -to $to
        Write-Log "Failed to connect to $($ip):$($port).  $($PSItem.Exception.Message)"
        exit # Nothing to do here
    }
    #

    # If we are here everything works. Notify master
    Send-Message -msg @{"service" =  "socks5"; "result" = "OK"} -to $to
    Write-Log "Connected to $($ip):$($port)"

    # Create buffer for Websockets
    $array_size = 8192
    $array = [byte[]] @(,0) * $array_size
    $data = New-Object System.ArraySegment[byte] -ArgumentList @(,$Array)


    # Objects to interact with the TCP stream
    $stream = $conn.GetStream()
    $streamWriter = New-Object System.IO.BinaryWriter($stream)
    $streamReader = New-Object System.IO.BinaryReader($stream)

    # Buffer for TCPClient
    $buffer = New-Object System.Byte[] 8192
    $receiveWS = $true

    try{
        while($conn.Connected -or $ws.State -eq "Open"){
            # If websockets or TCP connection opened try to read/write

            # Get new data from websockets
            $message = ""

            if($receiveWS){
                $ConnWS = $ws.ReceiveAsync($data, $ct) # Read data async
                $receiveWS = $false
            }

            if($ConnWS.IsCompleted){
                # Read data
                $data.Array[0..($ConnWS.Result.Count - 1)] | ForEach-Object { $message += [char]$_}
                $receiveWS = $true # Call again ReceiveAsync

                if($ConnWS.Result.Count -lt $array_size){
                    Write-Log "Received message $($message)"
                    # Data to JSON
                    $message = ($message | convertfrom-json)
                    # Write data to TCP
                    $streamWriter.Write([System.Convert]::FromBase64String($message.payload.content))
                }
            }

            # Read data from TCP stream
            while($stream.DataAvailable){
                # There is info to read
                $readLength = $streamReader.Read($buffer, 0, 8192) # Check if buffer overflow
                # Do something with the data
                $dataEncoded = [Convert]::ToBase64String($buffer, 0, $readLength)

                Send-Message -msg @{"service" = "socks5"; "action" = "send"; "content" = $dataEncoded} -to $to

                $lengthString = [string] $readLength
                Write-Log "Read $($lengthString) bytes from TCP stream."

            }

            Start-Sleep -Milliseconds 100 # This may cause packet lost
        }
    }catch{
        Write-Log "$($PSItem.Exception.Message)"
    }finally{
        if($ws){
            Write-Log "Closing Websockets"
            $ws.Dispose()
        }
    }
}
        Start-Job -ScriptBlock $socksCode -ArgumentList $args[1], $args[0].host, $args[0].port, $args[2]