Function Get-ipstack {
    [cmdletbinding()]
    [OutputType("iplookup")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an IPV4 address to lookup with IPStack",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")]
        $ipaddress
    )
    begin {
        write-log "Function: $($MyInvocation.Mycommand)"
    }
    Process {
        if ($ipaddress) {
            if ($ipstackkey) {
                Try {
                    $url = 'http://api.ipstack.com/' + $ipaddress + '?access_key=' + $ipstackkey + '&hostname=1'
                    $response = Invoke-WebRequest -Method Post -Uri "$url" -ContentType 'application/json'
                }
                Catch {
                    Write-log "$($_.Exception.Message)" 
                    return
                }
                if ($response) {
                    $t = $response.Content | ConvertFrom-Json
                    $name = 'IPStack' | Trace-word -words 'IPStack'
                    if ([switch]$raw) {
                        $res
                    }
                    Else {
                        $properties = ($t | Get-Member -MemberType Properties).Name
                        [hashtable]$table = @{
                            PSTypeName = "IPStack"
                        }
                        ForEach ($property in $properties) {
                            If ($t."$property" -ne $t.location) {
                                If ($t."$property") {
                                    $n = $property + ": " + $t."$property" 
                                    $table.Add($property, $t."$property")
                                    Write-log " [IPStack] $n"
                                }
                            }
                        }
                    }
                }
            }
            Else {
                Write-Warning "Requires IPstack API Key" -InformationAction Continue
                return
            }
        }
    }
    End {
        if ($table) {
            $htable = New-Object -TypeName psobject -Property $table
            $htable | Format-List
        }
        if ($t.location) {
            Write-host "location: "
            $t.location | % {
                $_
            }
        }
        Write-log "Exiting $($MyInvocation.Mycommand)"
    }
}