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
            }
        }
        Catch {
            Write-warning "$($_.Exception.Message)"
            return
        }
        if ($response) {
            $t = $response.Content | ConvertFrom-Json
            $apiname | Trace-word -words 'FRAUDGUARD'
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
