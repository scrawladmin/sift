# https://www.powershellgallery.com/packages/PSScriptTools/2.9.0/Content/functions%5CGet-WhoIs.ps1
Function Get-WhoIs {
    [cmdletbinding()]
    [OutputType("WhoIsResult")]
    Param (
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an IPV4 address to lookup with WhoIs",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
        [ValidateScript( {
                #verify each octet is valid to simplify the regex
                $test = ($_.split(".")).where({ [int]$_ -gt 254 })
                if ($test) {
                    Throw "$_ does not appear to be a valid IPv4 address"
                    $false
                }
                else {
                    $true
                }
            })]
        [string]$IPAddress
    )

    Begin {
        Write-Verbose "Starting $($MyInvocation.Mycommand)"
        $baseURL = 'http://whois.arin.net/rest'
        #default is XML anyway
        $header = @{"Accept" = "application/xml" }

    } #begin

    Process {
        Write-Verbose "Getting WhoIs information for $IPAddress"
        $url = "$baseUrl/ip/$ipaddress"
        Try {
            $r = Invoke-Restmethod $url -Headers $header -ErrorAction stop
            # Write-Verbose ($r.net | Out-String)
            # $city = (Invoke-RestMethod $r.net.orgRef.'#text').org.city
        }
        Catch {
            $errMsg = "Sorry. There was an error retrieving WhoIs information for $IPAddress. $($_.exception.message)"
            $host.ui.WriteErrorLine($errMsg)
            Write-Error "$($_.exception.message)"
        }

        if ($r.net) {
            Write-Verbose "Creating result"
            $result = [pscustomobject]@{
                PSTypeName             = "WhoIsResult"
                IP                     = $ipaddress
                Name                   = $r.net.name
                RegisteredOrganization = $r.net.orgRef.name
                City                   = $city
                StartAddress           = $r.net.startAddress
                EndAddress             = $r.net.endAddress
                NetBlocks              = $r.net.netBlocks.netBlock | foreach-object { "$($_.startaddress)/$($_.cidrLength)" }
                Updated                = $r.net.updateDate -as [datetime]
            }
            $results = @()
            if ($r.net.orgRef.'#text') { 
                $moreinfo = (Invoke-RestMethod $r.net.orgRef.'#text').org
            }
            If ($moreinfo.streetAddress) {
                $streetsddress = [PSCustomObject]@{
                    streetAddress = $($moreinfo.streetAddress.line."#text")
                }
            }
            If ($moreinfo.comment.line) {
                $comment = $($moreinfo.comment.line."#text")             
            }
            $name = 'WHOIS' | Trace-word -words 'WHOIS'
            $results += $result
            $results += $streetsddress
            $results += $moreinfo
            $results += $comment
            $results 
            Write-log "PSTypeName             = WhoIsResult"
            Write-log "IP                     = $($ipaddress)"
            Write-log "Name                   = $($r.net.name)"
            Write-log "RegisteredOrganization = $($r.net.orgRef.name)"
            Write-log "City                   = $($city) "
            Write-log "StartAddress           = $($r.net.startAddress)"
            Write-log "EndAddress             = $($r.net.endAddress)"
            Write-log "NetBlocks              = $($r.net.netBlocks.netBlock | foreach-object {"$($_.startaddress)/$($_.cidrLength)"})"
            Write-log "Updated                = $($r.net.updateDate -as [datetime])"
            Write-log "streetAddress          = $($moreinfo.streetAddress.line."#text")"
            Write-log "$comment"
        } #If $r.net
    } #Process

    End {
        Write-Verbose "Ending $($MyInvocation.Mycommand)"
    } #end
}
