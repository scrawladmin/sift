Function Get-fraudguardiprep {
    [cmdletbinding()]
    [OutputType("iprep")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an IPV4 address to lookup with Fraudguard",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")]
        $ipaddress
    )
    Begin {
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
        $apiname = 'FRAUDGUARD'
        if ($Fraudguardkey) {
            if ($fraudguarduserid) {
                $pair = "$($fraudguarduserid):$($Fraudguardkey)"
                $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
                $basicAuthValue = "Basic $encodedCreds"
                $Headers = @{
                    Authorization = $basicAuthValue
                }  
            }
            Else {
                write-warning "Requires Fraudguard User" -InformationAction Continue
                return
            } 
        }
        Else {
            write-warning "Requires Fraudguard Pass" -InformationAction Continue
            return
        }
    }
    Process {
        Try {
            if ($ipaddress -and $Headers) {
                $response = Invoke-WebRequest -Uri "https://api.fraudguard.io/ip/$ipaddress" -Headers $Headers
                # https://api.fraudguard.io/ip/$ipaddress
                # Paid plan URL https://api.fraudguard.io/v2/ip/<IP>
            }
        }
        Catch {
            write-warning "$($_.Exception.Message)"
            return
        }
        if ($response) {
            $apiname | Select-ColorString "FRAUDGUARD" -CaseSensitive -BackgroundColor $(Get-Random 'Gray','Blue','Green','Cyan','Red','Magenta','Yellow','White')
            # $apiname | Trace-word -words 'FRAUDGUARD'
            $t = $response.Content | ConvertFrom-Json
            if ([switch]$raw) {
                $t
            }
            Else {
                $properties = ($t | Get-Member -MemberType Properties).Name
                [hashtable]$table = @{
                    PSTypeName = "FRAUDGUARD"
                }
                ForEach ($property in $properties) {
                    If ($t."$property" -ne $t.location) {
                        If ($t."$property") {
                            $n = $property + ": " + $t."$property" 
                            $table.Add($property, $t."$property")
                            Write-log " [FRAUDGUARD] $n"
                        }
                    }
                }
            }
        }
    }
    End {
        if ($table) {
            $htable = New-Object -TypeName psobject -Property $table
            $htable | Format-List
        }
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}
Function Get-fraudguardhostnamerep {
    [cmdletbinding()]
    [OutputType("hostnamerep")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an Hostanme to lookup with Fraudguard",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        # [ValidatePattern("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")]
        $hostname
    )
    Begin {
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
        $apiname = 'FRAUDGUARD'
        if ($Fraudguardkey) {
            if ($fraudguarduserid) {
                $pair = "$($fraudguarduserid):$($Fraudguardkey)"
                $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
                $basicAuthValue = "Basic $encodedCreds"
                $Headers = @{
                    Authorization = $basicAuthValue
                }  
            }
            Else {
                write-warning "Requires Fraudguard User" -InformationAction Continue
                return
            } 
        }
        Else {
            write-warning "Requires Fraudguard Pass" -InformationAction Continue
            return
        }
    }
    Process {
        Try {
            if ($hostname -and $Headers) {
                $response = Invoke-WebRequest -Uri "https://api.fraudguard.io/v2/hostname/$hostname" -Headers $Headers
                # Paid plan URL 
                # https://api.fraudguard.io/v2/hostname/<hostname>
            }
        }
        Catch {
            write-warning "$($_.Exception.Message)"
            return
        }
        if ($response) {
            $apiname | Select-ColorString "FRAUDGUARD" -CaseSensitive -BackgroundColor $(Get-Random 'Gray','Blue','Green','Cyan','Red','Magenta','Yellow','White')
            #$apiname | Trace-word -words 'FRAUDGUARD'
            $t = $response.Content | ConvertFrom-Json
            if ([switch]$raw) {
                $t
            }
            Else {
                $properties = ($t | Get-Member -MemberType Properties).Name
                [hashtable]$table = @{
                    PSTypeName = "FRAUDGUARD"
                }
                ForEach ($property in $properties) {
                    If ($t."$property" -ne $t.location) {
                        If ($t."$property") {
                            $n = $property + ": " + $t."$property" 
                            $table.Add($property, $t."$property")
                            Write-log " [FRAUDGUARD] $n"
                        }
                    }
                }
            }
        }
    }
    End {
        if ($table) {
            $htable = New-Object -TypeName psobject -Property $table
            $htable | Format-List
        }
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}