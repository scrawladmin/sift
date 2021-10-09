Function Get-URLhausQuery {
    [cmdletbinding()]
    [OutputType("urlquery")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "To retrieve information about an URL",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        $url
    )
    Begin {
        if ($url) {
            $data = @{ url = "$url" }
        }
    }
    Process {
        if ($data) {
            Try {
                $res = Invoke-WebRequest -Method Post -Uri 'https://urlhaus-api.abuse.ch/v1/url/'-Body $data
            }
            Catch {
                write-log "$($_.Exception.Message)"
                return
            }
            if ($res) {
                $t = $res.content | ConvertFrom-Json
                $name = 'URLhaus' | Trace-word -words 'URLhaus'
                if ([switch]$raw) {
                    $t
                }
                Else {
                    $properties = ($t | Get-Member -MemberType Properties).Name
                    [hashtable]$table = @{}
                    ForEach ($property in $properties) {
                        If ($property -ne "payloads") {
                            If ($t."$property") {
                                $n = $property + ": " + $t."$property" 
                                $table.Add($property, $t."$property")
                                Write-log " [URLhaus] $n"
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
        }
        $htable | Format-List
        If ($t.payloads) {
            $t.payloads
        }
    }
}
