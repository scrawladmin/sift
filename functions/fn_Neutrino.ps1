Function Get-neuIPBlocklist {
    [cmdletbinding()]
    [OutputType("ipblocklist")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "The IP Blocklist API will detect potentially malicious or dangerous IP addresses.
            Use this API for identifying malicious hosts, anonymous proxies, tor, botnets, spammers and more.
            Parameter	Type: ip
            optional: vpn-lookup =  boolean",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")]
        $ipaddress
    )

    begin {
        write-log "Function: $($MyInvocation.Mycommand)"
        $params = @()
    }
    Process {
        if ($neuuserid -and $neuapikey ) {
            if ($ipaddress) {
                $info = "" | Select-Object ip, 'user-id', 'api-key', 'vpn-lookup'
                $info.'user-id' = "$neuuserid"
                $info.'api-key' = "$neuapikey"
                $info.'vpn-lookup' = $true
                $info.ip = $ipaddress
                if ($info) {
                    $params += $info
                    if ($params) {
                        $params = $params | ConvertTo-Json
                        if ($params) {
                            Try {
                                $response = Invoke-WebRequest -Method Post -Uri "https://neutrinoapi.net/ip-blocklist" -ContentType 'application/json' -Body $params
                            }
                            Catch {
                                Write-log "$($_.Exception.Message)" 
                            }
                            if ($response) {
                                $name = 'Neutrino' | Trace-word -words 'Neutrino'
                                $t = $response.Content | ConvertFrom-Json   
                                # $t = $response.Content
                                if ([switch]$raw) {
                                    $t
                                }
                                Else {
                                    write-host "list-count : $($response.'list-count')"
                                    write-host "last-seen : $($response.'last-seen')"
                                    $response.blocklist
                                    $response.sensors 
                                    $properties = ($t | Get-Member -MemberType Properties).Name
                                    [hashtable]$table = @{
                                        PSTypeName = "Neutrino"
                                    }
                                    ForEach ($property in $properties) {
                                        If ($t."$property" -like $True) {
                                            $n = $property + ": " + $t."$property" 
                                            $table.Add($property, $t."$property")
                                            Write-log " [Neutrino] $n"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Else {
            Write-Warning "Requires Neutrino API Key" -InformationAction Continue
            return
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
Function Get-neuIPProbe {
    [cmdletbinding()]
    [OutputType("ipprobe")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Analyze and extract provider information for an IP address.
            This API will perform a live (realtime) scan against the given IP using various network level checks. 
            Parameter	Type: ip",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")]
        $ipaddress)
    begin {
        write-log "Function: $($MyInvocation.Mycommand)"
    }
    process {
        if ($neuuserid -and $neuapikey) {
            if ($ipaddress) {
                $Info = [PSCustomObject]@{ 'user-id' = "$neuuserid"; 'api-key' = "$neuapikey"; ip = "$ipaddress" }
                $params += $Info
                if ($params) {
                    $params = $params | ConvertTo-Json
                    if ($params) {
                        try {
                            $response = Invoke-WebRequest -Method Post -Uri "https://neutrinoapi.net/ip-probe" -ContentType 'application/json' -Body $params
                        }
                        Catch {
                            $($_.ErrorDetails.Message)
                            Write-log "$($_.ErrorDetails.Message)" 
                        }
                        if ($response) {
                            $name = 'Neutrino' | Trace-word -words 'Neutrino' 
                            $t = $response.Content | ConvertFrom-Json
                            if ([switch]$raw) {
                                $t
                            }
                            Else {
                                # $t    
                                $properties = ($t | Get-Member -MemberType Properties).Name
                                [hashtable]$table = @{
                                    PSTypeName = "Neutrino"
                                }
                                ForEach ($property in $properties) {
                                    If ($t."$property" -like $True) {
                                        $n = $property + ": " + $t."$property" 
                                        $table.Add($property, $t."$property")
                                        Write-log " [Neutrino] $n"
                                    }
                                    Elseif ($t."$property" -notlike $false) {
                                        $n = $property + ": " + $t."$property" 
                                        $table.Add($property, $t."$property")
                                        Write-log " [Neutrino] $n"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Else {
            Write-Warning "Requires Neutrino API Key" -InformationAction Continue
            return
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
Function Get-neuHostRep {
    [cmdletbinding()]
    [OutputType("hostrep")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Check the reputation of an IP address, domain name or URL against a comprehensive list of blacklists and blocklists.
        Parameter	Type: host = An IP address, domain name, FQDN or URL
        optional: list-rating = 3
        optional: zones = Only check these DNSBL zones/hosts. Multiple zones can be supplied as comma-separated values",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        $object
    )
    Begin {
        write-log "Function: $($MyInvocation.MyCommand)"

    }
    Process {
        if ($neuuserid -and $neuapikey) {
            if ($object) {
                $info = New-Object -TypeName psobject
                $info | Add-Member NoteProperty -Name 'user-id' -Value $neuuserid
                $info | Add-Member NoteProperty -Name 'api-key' -Value $neuapikey
                $info | Add-Member NoteProperty -Name 'host' -Value $object
                $params += $Info
                if ($params) {
                    $params = $params | ConvertTo-Json
                    if ($params) {
                        Try {
                            $response = Invoke-WebRequest -Method Post -Uri "https://neutrinoapi.net/host-reputation" -ContentType 'application/json' -Body $params
                        }
                        Catch {
                            Write-log "$($_.Exception.Message)" 
                        }
                        if ($response) {
                            $response = $response.Content | ConvertFrom-Json
                            if ($response.lists) {
                                $lists = $response.lists
                                $name = 'Neutrino' | Trace-word -words 'Neutrino'
                                if ([switch]$raw) {
                                    $response | Format-List 
                                }
                                Else {
                                    foreach ($list in $lists) {
                                        if ($list.'is-listed' -eq $true) {
                                            $list
                                        }
                                        Else {
                                            $i++
                                            # Write-Information "$($list.'list-name')  Host not listed" -InformationAction Continue
                                        }
                                    }
                                    If ($i) {
                                        Write-Information "  Host not listed on $i lists" -InformationAction Continue
                                    }
                                }
                            } 
                        }
                    }
                }
            }
        }
        Else {
            Write-Warning "Requires Neutrino API Key" -InformationAction Continue
            return
        }
    }
    End {
        Write-log "Exiting $($MyInvocation.Mycommand)"

    }
}
Function Get-neuIPInfo {
    [cmdletbinding()]
    [OutputType("ipinfo")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Get location information about an IP address and do reverse DNS (PTR) lookups.
        Parameter	Type: ip
        Optional: reverse-lookup = boolean",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")]    
        $ipaddress
    )
    Begin {
        write-log "Function: $($MyInvocation.Mycommand)"
    }
    Process {
        if ($neuuserid -and $neuapikey) {
            if ($ipaddress) {
                $info = @{
                    'user-id' = "$neuuserid"
                    'api-key' = "$neuapikey"
                    'ip'      = "$ipaddress"
                    # 'reverse-lookup' = $true
                }
                if ($info) {
                    $params = New-Object psobject -Property $info
                    if ($params) {
                        $params = $params | ConvertTo-Json
                        if ($params) {
                            try {
                                $response = Invoke-WebRequest -Method Post -Uri "https://neutrinoapi.net/ip-info" -ContentType 'application/json' -Body $params
                            }
                            catch {
                                Write-log "$($_.Exception.Message)" 
                            }
                            if ($response) {
                                If ([switch]$raw) {
                                    $response
                                }
                                $response = $response.Content | ConvertFrom-Json
                                $name = 'Neutrino' | Trace-word -words 'Neutrino'
                                $t = $response
                                $properties = ($t | Get-Member -MemberType Properties).Name
                                [hashtable]$table = @{
                                    PSTypeName = "Neutrino"
                                }
                                ForEach ($property in $properties) {
                                    If ($t."$property") {
                                        If ($t."$property") {
                                            $n = $property + ": " + $t."$property" 
                                            $table.Add($property, $t."$property")
                                            Write-log " [Neutrino] $n"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Else {
            Write-Warning "Requires Neutrino API Key" -InformationAction Continue
            return
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
Function Get-neuURLInfo {
    [cmdletbinding()]
    [OutputType("urlinfo")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Parse, analyze and retrieve content from the supplied URL.
         Parameter	Type: url
         Optional: fetch-content false	If this URL responds with html, text, json or xml then return the response. This option is useful if you want to perform further processing on the URL content (e.g. with the HTML Extract or HTML Clean APIs)
        ignore-certificate-errors false	Ignore any TLS/SSL certificate errors and load the URL anyway
        timeout 60	Timeout in seconds. Give up if still trying to load the URL after this number of seconds
        retry 0	   If the request fails for any reason try again this many times",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        $url
    )
    Begin {
        write-log "Function: $($MyInvocation.Mycommand)"
        if ($neuuserid -and $neuapikey) {
            if ($url) {
                $info = @{
                    'user-id' = "$neuuserid"
                    'api-key' = "$neuapikey"
                    'url'     = "$url"
                }
            }
        }
        Else {
            Write-Warning "Requires Neutrino API Key" -InformationAction Continue
            return
        }
    }
    Process {
        if ($info) {
            $params = New-Object psobject -Property $info
            $params = $params | ConvertTo-Json
            if ($params) {
                Try {
                    $response = Invoke-WebRequest -Method Post -Uri "https://neutrinoapi.net/url-info" -ContentType 'application/json' -Body $params
                }
                Catch {
                    Write-log "$($_.Exception.Message)" 
                }
                if ($response) {
                    $response = $response.Content | ConvertFrom-Json
                    $name = 'Neutrino' | Trace-word -words 'Neutrino'
                    $t = $response
                    #$t
                    $properties = ($t | Get-Member -MemberType Properties).Name
                    [hashtable]$table = @{
                        PSTypeName = "Neutrino"
                    }
                    ForEach ($property in $properties) {
                        If ("$property") {
                            If ($t."$property") {
                                $n = $property + ": " + $t."$property" 
                                $table.Add($property, $t."$property")
                                Write-log " [Neutrino] $n"
                            }
                        }
                    }

                }
            }
        }
    }
    End {
        If ($table) {
            $htable = New-Object -TypeName psobject -Property $table
            $htable
        }
        Write-log "Exiting $($MyInvocation.Mycommand)"
    }
}
Function Get-neuEmailvalidate {
    # -emailvalidate
    param($email)
    # Parse, validate and clean an email address.
    # Parameter	Type: email
    # Optional: fix-typos boolean Automatically attempt to fix typos in the address
    write-log "Function: Get-neuEmailvalidate"
    if ($neuuserid) {
        if ($neuapikey) {
            if ($email) {
                $Info = [PSCustomObject]@{ 'user-id' = "$neuuserid"; 'api-key' = "$neuapikey"; email = "$email" }
                $params += $Info
                if ($params) {
                    $params = $params | ConvertTo-Json
                    if ($params) {
                        try {
                            $response = Invoke-WebRequest -Method Post -Uri "https://neutrinoapi.net/email-validate" -ContentType 'application/json' -Body $params
                        }
                        Catch {
                            Write-log "$($_.Exception.Message)" 
                        }
                        if ($response) {
                            $name = 'Neutrino' | Trace-word -words 'Neutrino'
                            $response.Content | ConvertFrom-Json
                        }
                    }
                }
            }
        }
    }
}
Function Get-neuEmailverify {
    # -emailverify
    param($email)
    # SMTP based email address verification. Verify real users and filter out low-quality email addresses.
    # Parameter	Type: email
    # Optional: fix-typos boolean Automatically attempt to fix typos in the address
    write-log "Function: Get-neuEmailverify"
    if ($neuuserid) {
        if ($neuapikey) {
            if ($email) {
                $Info = [PSCustomObject]@{ 'user-id' = "$neuuserid"; 'api-key' = "$neuapikey"; email = "$email" }
                $params += $Info
                if ($params) {
                    $params = $params | ConvertTo-Json
                    if ($params) {
                        try {
                            $response = Invoke-WebRequest -Method Post -Uri "https://neutrinoapi.net/email-verify" -ContentType 'application/json' -Body $params
                        }
                        Catch {
                            Write-log "$($_.Exception.Message)" 
                        }
                        if ($response) {
                            $name = 'Neutrino' | Trace-word -words 'Neutrino'
                            $response.Content | ConvertFrom-Json
                        }
                    }
                }
            }
        }
    }
}
Function Get-neuHTMLclean {
    # -htmlclean
    param($html)
    # > Clean and sanitize untrusted HTML.
    # > Use this API to make user supplied content (or content from external sources) safe and prevent cross-site scripting attacks (XSS). 
    # Parameter	Type: html
    # Optional: output-type = 
    # The level of sanitization, possible values are:
    # plain-text: reduce the content to plain text only (no HTML tags at all)
    # simple-text: allow only very basic text formatting tags like b, em, i, strong, u
    # basic-html: allow advanced text formatting and hyper links
    # basic-html-with-images: same as basic html but also allows image tags
    # advanced-html: same as basic html with images but also allows many more common HTML tags like table, ul, dl, pre
    write-log "Function: Get-neuHTMLclean"
    if ($neuuserid) {
        if ($neuapikey) {
            if ($html) {
                $Info = [PSCustomObject]@{ 'user-id' = "$neuuserid"; 'api-key' = "$neuapikey"; content = "$html" }
                $params += $Info
                if ($params) {
                    $params = $params | ConvertTo-Json
                    if ($params) {
                        try {
                            $response = Invoke-WebRequest -Method Post -Uri "https://neutrinoapi.net/html-clean" -ContentType 'application/json' -Body $params
                        }
                        Catch {
                            Write-log "$($_.Exception.Message)" 
                        }
                        if ($response) {
                            $name = 'Neutrino' | Trace-word -words 'Neutrino'
                            $response.Content | ConvertFrom-Json
                        }
                    }
                }
            }
        }
    }
}