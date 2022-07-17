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
                $response = Invoke-WebRequest -Method Get -Uri $url
            }
            catch {
                write-warning "$($_.Exception.Message)" 
                return
            }
        }
        If ($response) {
            $t = $response.Content | ConvertFrom-Json
        }
        else {
            $name = 'SHODAN' | Trace-word -words 'SHODAN'
            $properties = ($t | Get-Member -MemberType Properties).Name
            [hashtable]$table = @{
                PSTypeName = 'SHODAN'
            }
            ForEach ($property in $properties) {
                If ($t."$property") {
                    If ($t."$property") {
                        $n = $property + ": " + $t."$property" 
                        $table.Add($property, $t."$property")
                        Write-log " [SHODAN] $n"
                    }
                }
            }
        }
    }
    End {
        if ($table) {
            $htable = New-Object -TypeName psobject -Property $table
        }
        $htable.data | Format-List
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}