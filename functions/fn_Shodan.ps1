Function Get-shodanip {
    [cmdletbinding()]
    [OutputType("ipservices")]
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
    Begin {
        Write-verbose "Function: $($MyInvocation.Mycommand)"
        If ($ipaddress -and $Shodankey) {
            $url = "https://api.shodan.io/shodan/host/" + $ipaddress + "?key=$Shodankey"
        }
        Else {
            Write-Warning "Requires Shodan API Key" -InformationAction Continue
            return
        }
    }
    Process {
        if ($url) {
            try {
                # $response = Invoke-WebRequest -Method Get -Uri $url
                $response = Invoke-RestMethod -Uri $url
            }
            catch {
                write-warning "$($_.Exception.Message)" 
                return
            }
        }
        If ($response) {
            # $t = $response.Content | ConvertFrom-Json
            $name = 'SHODAN' | Trace-word -words 'SHODAN'
            # $properties = ($t | Get-Member -MemberType Properties).Name
            # [hashtable]$table = @{
            #     PSTypeName = 'SHODAN'
            # }
            # ForEach ($property in $properties) {
            #     If ($t."$property") {
            #         If ($t."$property") {
            #             $n = $property + ": " + $t."$property" 
            #             $table.Add($property, $t."$property")
            #             Write-log " [SHODAN] $n"
            #         }
            #     }
            # }
            $name
            $response
        }
    }
    End {
        # if ($table) {
        #     $htable = New-Object -TypeName psobject -Property $table
        # }
        # $htable.data | Format-List
        Write-log "PSTypeName             = SHODAN"
        Write-log "city                   = $($response.city)"
        Write-log "region_code            = $($response.region_code)"
        Write-log "os                     = $($response.os)"
        Write-log "tags                   = $($response.tags) "
        Write-log "ip                     = $($response.ip)"
        Write-log "isp                    = $($response.isp)"
        Write-log "area_code              = $($response.area_code)"
        Write-log "longitude              = $($response.longitude)"
        Write-log "last_update            = $($response.last_update)"
        Write-log "ports                  = $($response.ports)"
        Write-log "latitude               = $($response.latitude)"
        Write-log "country_code           = $($response.country_code)"
        Write-log "country_name           = $($response.country_name)"
        Write-log "domains                = $($response.domains)"
        Write-log "org                    = $($response.org)"
        Write-log "asn                    = $($response.asn)"
        Write-log "ip_str                 = $($response.ip_str)"
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}