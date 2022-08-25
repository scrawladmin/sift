Function Get-hetrixIPblacklist {
    [cmdletbinding()]
    [OutputType("ipblacklist")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an IPV4 address to lookup with Hetrix IP Blacklist",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")]
        $ipaddress
    )
    Begin {
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
    }
    Process {
        if ($Hetrixtoolskey) {
            if ($ipaddress) {
                Try {
                    $url = 'https://api.hetrixtools.com/v2/' + $Hetrixtoolskey + '/blacklist-check/ipv4/' + $ipaddress + '/'
                    Write-Verbose $url
                    $response = Invoke-WebRequest -Method GET -Uri "$url"
                }
                Catch {
                    write-warning "$($_.Exception.Message)" 
                    return
                }
                if ($response) {
                    $t = $response.Content | ConvertFrom-Json
                    $name = 'HETRIXTOOLS' | Trace-word -words 'HETRIXTOOLS'
                    if ([switch]$raw) {
                        $t
                    }
                    Else {
                        $properties = ($t | Get-Member -MemberType Properties).Name
                        [hashtable]$table = @{
                            PSTypeName = "HETRIXTOOLS"
                        }
                        ForEach ($property in $properties) {
                            If ("$property" -ne "blacklisted_on") {
                                If ($t."$property") {
                                    $n = $property + ": " + $t."$property" 
                                    $table.Add($property, $t."$property")
                                    Write-log " [HETRIXTOOLS] $n"
                                }
                            }
                        }
                    }
                }
            }
        }
        Else {
            write-warning "Requires Hetrix API Key" -InformationAction Continue
            return
        }
    }
    End {
        if ($table) {
            $htable = New-Object -TypeName psobject -Property $table
            $htable | Format-List
            if ($($t.blacklisted_on)) {
                Write-host "BLACKLISTED: "
                $t.blacklisted_on
            }
        }
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}

Function Get-hetrixDomainblacklist {
    [cmdletbinding()]
    [OutputType("fqdnblacklist")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an Domian name to lookup with Hetrix Domain Blacklist",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]    
        $fqdn
    )
    begin {
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
        $apiname = 'HETRIXTOOLS'
    }
    Process {
        if ($Hetrixtoolskey) {
            if ($fqdn) {
                Try {
                    $url = 'https://api.hetrixtools.com/v2/' + $Hetrixtoolskey + '/blacklist-check/domain/' + $fqdn + '/'
                    $response = Invoke-WebRequest -Method GET -Uri "$url"
                }
                Catch {
                    write-warning "$($_.Exception.Message)" 
                    return
                }
                if ($response) {
                    $t = $response.Content | ConvertFrom-Json
                    $apiname | Trace-word -words 'HETRIXTOOLS'
                    if ([switch]$raw) {
                        $t
                    }
                    Else {
                        $properties = ($t | Get-Member -MemberType Properties).Name
                        [hashtable]$table = @{}
                        ForEach ($property in $properties) {
                            If ("$property" -ne 'links') {
                                $n = $property + ": " + $t."$property" 
                                $table.Add($property, $t."$property")
                                Write-log " [HETRIXTOOLS] $n"
                            }
                        }
                    }
                }
            }
        }
        Else {
            write-warning "Requires Hetrix API Key" -InformationAction Continue
            return
        }
    }
    End {
        if ($table) {
            $htable = New-Object -TypeName psobject -Property $table
            $htable
        }
        if ($t.blacklisted_on) {
            Write-host "BLACKLISTED: "
            $t.blacklisted_on
        }
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}