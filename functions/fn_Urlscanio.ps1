Function Get-urlscanio {
    [cmdletbinding()]
    [OutputType("urlscan")]
    param(
        [parameter(Position = 0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        $url
    )
    Begin {
        Write-verbose "Function: $($MyInvocation.Mycommand)"
        $apiname = 'URLscan.io'
        if ($Urlscaniokey) {
            if ($url) {
                $Info = @{ 
                    'API-Key' = $Urlscaniokey
                }
                $data = @{ 
                    'url'        = "$url"
                    'visibility' = 'public' 
                }
            }
        }
        Else {
            Write-Warning "Requires URLscan.io API Key" -InformationAction Continue
            return
        }
    }
    Process {
        $data = New-Object psobject -Property $data
        if ($data) {
            $data = $data | ConvertTo-Json
            try {
                $response = Invoke-WebRequest "https://urlscan.io/api/v1/scan/" -Method POST -ContentType 'application/json' -Headers $Info -body $data
            }
            Catch {
                write-warning "$($_.Exception.Message)" 
                return
            }
            if ($response) {
                If ([switch]$raw) {
                    $response
                }
                else {
                    $apiname | Select-ColorString "URLscan.io" -CaseSensitive -BackgroundColor $(Get-Random 'Gray','Blue','Green','Cyan','Red','Magenta','Yellow','White')
                    # $apiname = 'URLscan.io' | Trace-word -words 'URLscan.io'
                    $t = $response.Content | ConvertFrom-Json
                    $properties = ($t | Get-Member -MemberType Properties).Name
                    [hashtable]$table = @{
                        PSTypeName = "URLscan.io"
                    }
                    ForEach ($property in $properties) {
                        If ($t."$property") {
                            If ($t."$property") {
                                $n = $property + ": " + $t."$property" 
                                $table.Add($property, $t."$property")
                                Write-log " [URLscan.io] $n"
                            }
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