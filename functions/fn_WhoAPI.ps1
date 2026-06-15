Function Get-domainscore {
    [cmdletbinding()]
    [OutputType("domainscore")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an FQDN address to lookup with domainscore",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        $fqdn
    )
    begin {
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
        $apiname = 'WHOAPI'
        $domain = $fqdn
        $r = "domainscore"
    }
    Process {
        if ($fqdn) {
            Try {
                
                $apikey = "$whoapikey"
                # https://api.whoapi.com/?apikey=YOUR_API_KEY&r=domainscore&domain=whoapi.com
                $url = "https://api.whoapi.com/?apikey=$apikey&r=$r&domain=$domain"
                #$url = "https://api.whoapi.com/?domain=$domain&r=$r&apikey=$apikey"
                $response = Invoke-WebRequest -Method Get -Uri "$url" -ContentType 'application/json'
            }
            Catch {
                Write-error "$($_.Exception.Message)" 
            }
            if ($response) {
                $t = $response.Content | ConvertFrom-Json
                $script:tx = $t.results
                $apiname | Trace-word -words 'WHOAPI'
                if ([switch]$raw) {
                    $t
                }
                Else {
                    $properties = ($t | Get-Member -MemberType Properties).Name
                    [hashtable]$table = @{
                        PSTypeName = "WHOAPI"
                    }
                    ForEach ($property in $properties) {
                       #If ($t."$property" -eq $t.results) {
                            If ($t."$property") {
                                $n = $property + ": " + $t."$property" 
                                $table.Add($property, $t."$property")
                                Write-log " [WHOAPI] $n"
                            }
                       #}
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
        $tx
        Write-log " [WHOAPI] $($tx)"
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}
Function Get-domainscorecheck {
    [cmdletbinding()]
    [OutputType("domainscorecheck")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an FQDN address to lookup with domainscore",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        $fqdn
    )
    begin {
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
        $apiname = 'WHOAPI'
        $domain = $fqdn
        $r = "domainscore-check"
    }
    Process {
        if ($fqdn) {
            Try {
                
                $apikey = "$whoapikey"
                # https://api.whoapi.com/?apikey=YOUR_API_KEY&r=domainscore&domain=whoapi.com
                $url = "https://api.whoapi.com/?apikey=$apikey&r=$r&domain=$domain"
                #$url = "https://api.whoapi.com/?domain=$domain&r=$r&apikey=$apikey"
                $response = Invoke-WebRequest -Method Get -Uri "$url" -ContentType 'application/json'
            }
            Catch {
                Write-error "$($_.Exception.Message)" 
            }
            if ($response) {
                $t = $response.Content | ConvertFrom-Json
                $script:tx = $t.results
                $apiname | Trace-word -words 'WHOAPI'
                if ([switch]$raw) {
                    $t
                }
                Else {
                    $properties = ($t | Get-Member -MemberType Properties).Name
                    [hashtable]$table = @{
                        PSTypeName = "WHOAPI"
                    }
                    ForEach ($property in $properties) {
                       #If ($t."$property" -eq $t.results) {
                            If ($t."$property") {
                                $n = $property + ": " + $t."$property" 
                                $table.Add($property, $t."$property")
                                Write-log " [WHOAPI] $n"
                            }
                       #}
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
        $tx
        Write-log " [WHOAPI] $($tx)"
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}
Function Get-whoapi {
    [cmdletbinding()]
    [OutputType("whoapi")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an FQDN address to lookup with domainscore",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        $fqdn
    )
    begin {
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
        $apiname = 'WHOAPI'
        $domain = $fqdn
        $r = "whois"
    }
    Process {
        if ($fqdn) {
            Try {
                
                $apikey = "$whoapikey"
                # https://api.whoapi.com/?domain=whoapi.com&r=whois&apikey=YOUR_API_KEY
                $url = "https://api.whoapi.com/?domain=$fqdn&r=$r&apikey=$apikey"
                $response = Invoke-WebRequest -Method Get -Uri "$url" -ContentType 'application/json'
            }
            Catch {
                Write-error "$($_.Exception.Message)" 
            }
            if ($response) {
                $t = $response.Content | ConvertFrom-Json
                $script:tx = $t.results
                $apiname | Trace-word -words 'WHOAPI'
                if ([switch]$raw) {
                    $t
                }
                Else {
                    $properties = ($t | Get-Member -MemberType Properties).Name
                    [hashtable]$table = @{
                        PSTypeName = "WHOAPI"
                    }
                    ForEach ($property in $properties) {
                       #If ($t."$property" -eq $t.results) {
                            If ($t."$property") {
                                $n = $property + ": " + $t."$property" 
                                $table.Add($property, $t."$property")
                                Write-log " [WHOAPI] $n"
                            }
                       #}
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
        $tx
        Write-log " [WHOAPI] $($tx)"
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}
Function Get-whoblacklist {
    [cmdletbinding()]
    [OutputType("whoapi")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Returns all services that have been found on the given host IP.",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]    
        $ipaddress
    )
    begin {
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
        $apiname = 'WHOAPI'
        # $domain = $fqdn
        $r = "blacklist"
    }
    Process {
        if ($ipaddress) {
            Try {
                
                $apikey = "$whoapikey"
                # https://api.whoapi.com/?apikey=YOUR_API_KEY&r=blacklist&domain=whoapi.com&ip=
                $url = "https://api.whoapi.com/?apikey=$apikey&r=$r&domain=whoapi.com&ip=$ipaddress"
                $response = Invoke-WebRequest -Method Get -Uri "$url" -ContentType 'application/json'
            }
            Catch {
                Write-error "$($_.Exception.Message)" 
            }
            if ($response) {
                $t = $response.Content | ConvertFrom-Json
                $script:tx = $t.blacklists
                $apiname | Trace-word -words 'WHOAPI'
                if ([switch]$raw) {
                    $t
                }
                Else {
                    $properties = ($t | Get-Member -MemberType Properties).Name
                    [hashtable]$table = @{
                        PSTypeName = "WHOAPI"
                    }
                    ForEach ($property in $properties) {
                       #If ($t."$property" -eq $t.results) {
                            If ($t."$property") {
                                $n = $property + ": " + $t."$property" 
                                $table.Add($property, $t."$property")
                                Write-log " [WHOAPI] $n"
                            }
                       #}
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
        $tx
        Write-log " [WHOAPI] $($tx)"
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}