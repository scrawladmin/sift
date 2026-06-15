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
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
        if ($url) {
            $data = @{ url = "$url" }
        }
        $apiname = 'URLhaus'
    }
    Process {
        if ($data) {
            Try {
                $res = Invoke-WebRequest -Method Post -Uri 'https://urlhaus-api.abuse.ch/v1/url/'-Body $data
            }
            Catch {
                write-warning "$($_.Exception.Message)"
                return
            }
            if ($res) {
                $t = $res.content | ConvertFrom-Json
                $apiname | Select-ColorString "URLhaus" -CaseSensitive -BackgroundColor $(Get-Random 'Gray','Blue','Green','Cyan','Red','Magenta','Yellow','White')
                # $apiname = 'URLhaus' | Trace-word -words 'URLhaus'
                if ([switch]$raw) {
                    $t
                }
                Else {
                    $properties = ($t | Get-Member -MemberType Properties).Name
                    [hashtable]$table = @{
                        PSTypeName = "URLHAUS"
                    }
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
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
    }
}
Function Get-URLhausSubmit {
    [cmdletbinding()]
    [OutputType("urlsubmit")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Submit a URL to URLhaus",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        $url
    )
    Begin {
        Write-Verbose "Function: $($MyInvocation.Mycommand)"
        $apiname = 'URLhaus'
        if ($urlhauskey) {
            if ($url) {                
                $payload = [ordered]@{
                    token      = "$urlhauskey"
                    anonymous  = 0
                    submission = @([ordered]@{
                            url    = "$url"
                            threat = 'malware_download'
                            Tags   = ""
                        }
                    )
                }
                $params = $payload | ConvertTo-Json
            }
        }
        Else {
            Write-Warning "Requires URLhaus API Key" -InformationAction Continue
            return
        }
    }
    Process {
        if ($params) {
            Try {
                $res = Invoke-WebRequest -Method Post -Uri 'https://urlhaus.abuse.ch/api/' -ContentType 'application/json' -Body $params
            }
            Catch {
                write-warning "$($_.Exception.Message)"
                return
            }
            if ($res) {
                $apiname | Select-ColorString "URLhaus" -CaseSensitive -BackgroundColor $(Get-Random 'Gray','Blue','Green','Cyan','Red','Magenta','Yellow','White')
                # $apiname = 'URLhaus' | Trace-word -words 'URLhaus'
                $t = $res.Content
                [hashtable]$table = @{
                    PSTypeName = "URLHAUS"
                }
                $property = "Response"
                $n = $property + ": " + $t 
                $table.Add($property, $t)
                Write-log " [URLhaus] $n"
            }
        }
    }
    End {
        Write-Verbose "Exiting $($MyInvocation.Mycommand)"
        if ($table) {
            $htable = New-Object -TypeName psobject -Property $table
        }
        $htable | Format-List
    }
}
# jsonData = {
#     'token' : api_key,
#     'anonymous' : '0',
#     'submission' : [
#       {
#         'url' : 'http://evildomain1.tld/bad',
#         'threat' : 'malware_download',
#         'tags': [
#           'Retefe',
#           'exe'
#         ]
#       }
# }