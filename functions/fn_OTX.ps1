Function Get-ippulse {
    [cmdletbinding()]
    [OutputType("ippulse")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an IPV4 address to lookup with OTX Pulse",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")]
        $ipaddress
    )
    begin {
        write-log "Function: $($MyInvocation.Mycommand)"
        $apiname = 'OTX'
    }
    Process {
        if ($ipaddress) {
            Try {
                $url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/' + $ipaddress + '/general'
                $response = Invoke-WebRequest -Method Get -Uri "$url" -ContentType 'application/json'
            }
            Catch {
                Write-log "$($_.Exception.Message)" 
            }
            if ($response) {
                $t = $response.Content | ConvertFrom-Json
                $apiname | Trace-word -words 'OTX'
                if ([switch]$raw) {
                    $res
                }
                Else {
                    If ($t.reputation) {
                        write "Reputation: $($t.reputation)"
                    }
                    $p = $t.pulse_info
                    if ($p.count) {
                        write "Pulse Count: $($p.count)"
                    }
                    [hashtable]$table = @{
                        PSTypeName = "OTX"
                    }
                    $pulses = $p.pulses 

                    ForEach ($pulse in $pulses) {
                        
                        $n = $($pulse.description) + " on date " + $($pulse.created)
                        if (!$table."$($pulse.name)") {
                            $table.Add($($pulse.name), $n)
                        }
                        Write-log " [OTX] $n"
                    }
                }
            }
        }
    }
    End {
        if ($table) {
            $htable = New-Object -TypeName psobject -Property $table
            $htable
        }
        Write-log "Exiting $($MyInvocation.Mycommand)"
    }
}

Function Get-fqdnpulse {
    [cmdletbinding()]
    [OutputType("fqdnpulse")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an FQDN address to lookup with OTX Pulse",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        $fqdn
    )
    begin {
        write-log "Function: $($MyInvocation.Mycommand)"
        $apiname = 'OTX'
    }
    Process {
        if ($fqdn) {
            Try {
                $url = 'https://otx.alienvault.com/api/v1/indicators/domain/' + $fqdn + '/general'
                $response = Invoke-WebRequest -Method Get -Uri "$url" -ContentType 'application/json'
            }
            Catch {
                Write-log "$($_.Exception.Message)" 
            }
            if ($response) {
                $t = $response.Content | ConvertFrom-Json
                $apiname | Trace-word -words 'OTX'
                if ([switch]$raw) {
                    $res
                }
                Else {
                    # If ($t.reputation) {
                    #     write "Reputation: $($t.reputation)"
                    # }
                    $p = $t.pulse_info
                    write "Pulse Count: $($p.count)"
                    [hashtable]$table = @{
                        PSTypeName = "OTX"
                    }
                    $pulses = $p.pulses 

                    ForEach ($pulse in $pulses) {
                        
                        $n = $($pulse.description) + " on date " + $($pulse.created)
                        if (!$table."$($pulse.name)") {
                            $table.Add($($pulse.name), $n)
                        }
                        Write-log " [OTX] $n"
                    }
                }
            }
        }
    }
    End {
        if ($table) {
            $htable = New-Object -TypeName psobject -Property $table
            $htable
        }
        Write-log "Exiting $($MyInvocation.Mycommand)"
    }
}