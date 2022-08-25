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
        $r         = "domainscore"
    }
    Process {
        if ($fqdn) {
            Try {
                
                $apikey    = "$whoapikey"
                
                $url = "https://api.whoapi.com/?domain=$domain&r=$r&apikey=$apikey"
                $response = Invoke-WebRequest -Method Get -Uri "$url" -ContentType 'application/json'
            }
            Catch {
                Write-error "$($_.Exception.Message)" 
            }
            if ($response) {
                $t = $response.Content | ConvertFrom-Json
                $apiname | Trace-word -words 'WHOAPI'
                if ([switch]$raw) {
                    $t
                }
                Else {
                    
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