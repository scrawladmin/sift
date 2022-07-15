# https://github.com/darkoperator/Posh-VirusTotal
# https://github.com/darkoperator/Posh-VirusTotal/blob/master/LICENSE.txt
function Get-VTFileReport {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateCount(1, 4)]
        [string[]]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey = $VirusTotalkey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    )
    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/report'
        if (!($APIKey)) {
            NoAPIKeyError
        }
    }
    Process {
        $QueryResources = $Resource -join ','

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'resource' = $QueryResources; 'apikey' = $APIKey }

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }


        $ReportResult = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }

        foreach ($FileReport in $ReportResult) {
            $FileReport.pstypenames.insert(0, 'VirusTotal.File.Report')
            $FileReport
        }
        
    }
    End {
    }
}
function Get-VTIPReport {   
    # - ipreport
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # IP Address to scan for.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$IPAddress,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey = $VirusTotalkey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        if (!($APIKey)) {
            NoAPIKeyError
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'ip' = $IPAddress; 'apikey' = $APIKey }

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $IPReport = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0, 'VirusTotal.IP.Report')
        # $IPReport
        $name = 'VirusTotal' | Trace-word -words 'VirusTotal'
        [hashtable]$table = @{
            PSTypeName = "VirusTotal"
        }
        # asn: 208294
        # as_owner: Cia Triad Security LLC
        # country: DE

        # foreach ($report in $IPReport) {
        # asn
        # response_code
        # as_owner
        # verbose_msg
        # country
        if ($IPReport.as_owner) {
            write-host "Owner: $($IPReport.as_owner)"
        }
        if ($IPReport.asn) {
            write-host "ASN: $($IPReport.asn)"
        }
        if ($IPReport.country) {
            Write-host "Country: $($IPReport.country)"
        }
        # detected_downloaded_samples
        # detected_referrer_samples            
        # detected_urls
        # detected_communicating_samples
        if ($($IPReport.detected_downloaded_samples)) {
            write-host "Detected downloaded samples: $(($IPReport.detected_downloaded_samples).count)"
        }
        if ($($IPReport.detected_referrer_samples)) {
            write-host "Detected referrer samples: $(($IPReport.detected_referrer_samples).count)"
        }
        if ($($IPReport.detected_urls)) {
            write-host "Detected urls: $(($IPReport.detected_urls).count)" 
            $t = $($IPReport.detected_urls)
            $properties = ($t | Get-Member -MemberType Properties).Name         
            ForEach ($property in $properties) {
                If ("$property") {
                    If ($t."$property") {
                        $n = $property + ": " + $t."$property" 
                        $table.Add($property, $t."$property")
                        Write-log " [VirusTotal] $n"
                    }
                }
            }
        }
        if ($($IPReport.detected_downloaded_samples)) {
            write-host "Detected downloaded samples: $(($IPReport.detected_downloaded_samples).count)"
        }
        # undetected_communicating_samples
        # undetected_referrer_samples
        # undetected_urls
        # undetected_downloaded_samples
        if ($($IPReport.undetected_communicating_samples)) {
            write-host "Undetected communicating samples: $(($IPReport.undetected_communicating_samples).count)"
        }
        if ($($IPReport.undetected_referrer_samples)) {
            write-host "Undetected referrer samples: $(($IPReport.undetected_referrer_samples).count)"
        }
        if ($($IPReport.undetected_urls)) {
            write-host "Undetected urls: $(($IPReport.undetected_urls).count)"
        }
        if ($($IPReport.undetected_downloaded_samples)) {
            write-host "undetected_downloaded_samples: $(($IPReport.undetected_downloaded_samples).count)"
        }
        # resolutions
        if ($($IPReport.resolutions)) {
            write-host "Resolutions: $(($IPReport.resolutions).count)"
            # $IPReport.resolutions
            $t = $($IPReport.resolutions)
            $properties = ($t | Get-Member -MemberType Properties).Name         
            ForEach ($property in $properties) {
                If ("$property") {
                    If ($t."$property") {
                        $n = $property + ": " + $t."$property" 
                        $table.Add($property, $t."$property")
                        Write-log " [VirusTotal] $n"
                    }
                }
            }
        }
        $htable = New-Object -TypeName psobject -Property $table
        $htable | Format-List
        # }
    }
    End {
    }
}

function Get-VTDomainReport {
    # -domainreport
    [CmdletBinding(DefaultParametersetName = 'Direct')]
    Param
    (
        # Domain to scan.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Domain,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey = $VirusTotalkey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/domain/report'
        if (!($APIKey)) {
            NoAPIKeyError
        }
    }
    Process {
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'domain' = $Domain; 'apikey' = $APIKey }

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        
        $DomainReport = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }
        $DomainReport.pstypenames.insert(0, 'VirusTotal.Domain.Report')
        $name = 'VirusTotal' | Trace-word -words 'VirusTotal'
        [hashtable]$table = @{
            PSTypeName = "VirusTotal"
        }
        # $DomainReport
        # domain_siblings               : 
        # whois                         :
        # response_code                 :
        # verbose_msg                   :
        # resolutions                   :
        if ($DomainReport.resolutions) {
            Write-host "resolutions :$(($DomainReport.resolutions).count)"
        }
        # detected_downloaded_samples   : 
        # detected_referrer_samples     :
        # detected_urls                 :
        if ($DomainReport.detected_downloaded_samples) {
            Write-host "detected_downloaded_samples :$(($DomainReport.detected_downloaded_samples).count)"
        }
        if ($DomainReport.detected_referrer_samples) {
            Write-host "detected_referrer_samples :$(($DomainReport.detected_referrer_samples).count)"
        }
        if ($DomainReport.detected_urls) {
            Write-host "detected_urls :$(($DomainReport.detected_urls).count)"
        }
        $t = $($DomainReport.detected_urls)
        $properties = ($t | Get-Member -MemberType Properties).Name         
        ForEach ($property in $properties) {
            If ("$property") {
                If ($t."$property") {
                    $n = $property + ": " + $t."$property" 
                    $table.Add($property, $t."$property")
                    Write-log " [VirusTotal] $n"
                }
            }
        }
        # undetected_urls               :
        # undetected_downloaded_samples : 
        # undetected_referrer_samples   :
        if ($DomainReport.undetected_urls) {
            Write-host "undetected_urls :$(($DomainReport.undetected_urls).count)"
        }
        if ($DomainReport.undetected_downloaded_samples) {
            Write-host "undetected_downloaded_samples :$(($DomainReport.undetected_downloaded_samples).count)"
        }
        if ($DomainReport.undetected_referrer_samples) {
            Write-host "undetected_referrer_samples :$(($DomainReport.undetected_referrer_samples).count)"
        }
        $htable = New-Object -TypeName psobject -Property $table
        $htable | Format-List
        if ($DomainReport.domain_siblings) {
            $output = @()
            $DomainReport.domain_siblings | % {
                $output += [PSCustomObject]@{
                    'Domain siblings' = $_
                }
            }
            $output | Format-Table
        }
        if ($DomainReport.whois) {
            $output = @()
            $output += [PSCustomObject]@{
                'whois' = $DomainReport.whois
            }
            $output | Format-List
        }
    
    }
    End {
    }
}

function Get-VTURLReport {
    # -urlreport
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # URL or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateCount(1, 4)]
        [string[]]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey = $VirusTotalkey,

        # Automatically submit the URL for analysis if no report is found for it in VirusTotal.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [switch]$Scan,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {
        Write-debug "$($_.Exception.Message)"
        $URI = 'https://www.virustotal.com/vtapi/v2/url/report'
        
        if ($Scan) {
            $scanurl = 1
        }
        else {
            $scanurl = 0
        }

        if (!($APIKey)) {
            NoAPIKeyError
        }
    }
    Process {
        $QueryResources = $Resource -join ','

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'resource' = $QueryResources; 'apikey' = $APIKey; 'scan' = $scanurl }


        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $ReportResult = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }
        $name = 'VirusTotal' | Trace-word -words 'VirusTotal'
        foreach ($URLReport in $ReportResult) {
            $URLReport.pstypenames.insert(0, 'VirusTotal.URL.Report')
            # $URLReport
            # scan_id       : 916c9880d5ff3d3fc6d213abae60074466b1d605c93644ca22402d133151db62-1632618895
            # resource      : 146.88.240.4
            # url           : http://146.88.240.4/
            # response_code : 1
            # scan_date     : 2021-09-26 01:14:55
            # permalink     : https://www.virustotal.com/gui/url/916c9880d5ff3d3fc6d213abae60074466b1d605c93644ca22402d133151db62/det
            #                 ection/u-916c9880d5ff3d3fc6d213abae60074466b1d605c93644ca22402d133151db62-1632618895
            # verbose_msg   : Scan finished, scan information embedded in this object
            # filescan_id   :
            # positives     : 9
            # total         : 89
            # scans
            # $URLReport
            $x = $URLReport
            $properties = ($x | Get-Member -MemberType Properties).Name
            [hashtable]$table = @{}
            ForEach ($property in $properties) {
                If ($x."$property" -notlike $x.scans) {
                    $n = $property + ": " + $x."$property" 
                    $table.Add($property, $x."$property")
                    Write-log " [VirusTotal] $n"
                }
            }
            $htable = New-Object -TypeName psobject -Property $table
            $htable
            write-host "Scans: "
            $t = $URLReport.scans
            if ($t) { 
                $properties = ($t | Get-Member -MemberType Properties).Name
                [hashtable]$table2 = @{}
                ForEach ($property in $properties) {
                    If ($t."$property".detected -like $true) {
                        $n = $property + ": " + $t."$property".result
                        $table2.Add($property, $t."$property".result)
                        Write-log " [VirusTotal] $n"
                    }
                }
                $htable2 = New-Object -TypeName psobject -Property $table2
                $htable2  | Format-List
            }
        }
    }
    End {
    }
}

# Not configured 

#  .ExternalHelp Posh-VirusTotal.Help.xml
function Submit-VTURL {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # URL or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateCount(1, 4)]
        [string[]]$URL,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        # Automatically submit the URL for analysis if no report is found for it in VirusTotal.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [switch]$Scan,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/url/scan'
        if ($Scan) {
            $scanurl = 1
        }
        else {
            $scanurl = 0
        }

        if (!($APIKey)) {
            NoAPIKeyError
        }
    }
    Process {
        $URLList = $URL -join "`n"
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        
        $Body = @{'url' = $URLList; 'apikey' = $APIKey }

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $SubmitedList = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }

        foreach ($submited in $SubmitedList) {
            $submited.pstypenames.insert(0, 'VirusTotal.URL.Submission')
            $submited
        }
      
    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Submit-VTFile {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # URL or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$File,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {
        $URI = 'http://www.virustotal.com/vtapi/v2/file/scan'

        if (!($APIKey)) {
            NoAPIKeyError
        }
    }
    Process {
        $fileinfo = Get-ItemProperty -Path $File

        # Check the file size
        if ($fileinfo.length -gt 64mb) {
            Write-Error -message "VirusTotal has a limit of 64MB per file submited $($File) could not be proccessed."
            return
        }
   
        $req = [System.Net.WebRequest]::Create('http://www.virustotal.com/vtapi/v2/file/scan')
        #$req.Headers = $headers
        $req.Method = 'POST'
        $req.AllowWriteStreamBuffering = $true
        $req.SendChunked = $false
        $req.KeepAlive = $true

        # Set the Proxy values.
        if ($PSCmdlet.ParameterSetName -eq 'Proxy') {
            $ProxyObject = New-Object System.Net.WebProxy
            $ProxyObject.Address = [uri]$Proxy

            if ($ProxyUseDefaultCredentials) {
                $ProxyObject.UseDefaultCredentials = $ProxyUseDefaultCredentials
            }

            if ($ProxyCredential) {
                $ProxyObject.Credentials = $ProxyCredential.GetNetworkCredential()
            }

            $req.Proxy = $ProxyObject
        }

        # Set the proper headers.
        $headers = New-Object -TypeName System.Net.WebHeaderCollection

        # Prep the POST Headers for the message
        $headers.add('apikey', $apikey)
        $boundary = '----------------------------' + [DateTime]::Now.Ticks.ToString('x')
        $req.ContentType = 'multipart/form-data; boundary=' + $boundary
        [byte[]]$boundarybytes = [System.Text.Encoding]::ASCII.GetBytes("`r`n--" + $boundary + "`r`n")
        [string]$formdataTemplate = "`r`n--" + $boundary + "`r`nContent-Disposition: form-data; name=`"{0}`";`r`n`r`n{1}"
        [string]$formitem = [string]::Format($formdataTemplate, 'apikey', $apikey)
        [byte[]]$formitembytes = [System.Text.Encoding]::UTF8.GetBytes($formitem)
        [string]$headerTemplate = "Content-Disposition: form-data; name=`"{0}`"; filename=`"{1}`"`r`nContent-Type: application/octet-stream`r`n`r`n"
        [string]$header = [string]::Format($headerTemplate, 'file', (get-item $file).name)
        [byte[]]$headerbytes = [System.Text.Encoding]::UTF8.GetBytes($header)
        [string]$footerTemplate = "Content-Disposition: form-data; name=`"Upload`"`r`n`r`nSubmit Query`r`n" + $boundary + '--'
        [byte[]]$footerBytes = [System.Text.Encoding]::UTF8.GetBytes($footerTemplate)


        # Read the file and format the message
        $stream = $req.GetRequestStream()
        $rdr = new-object System.IO.FileStream($fileinfo.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        [byte[]]$buffer = new-object byte[] $rdr.Length
        [int]$total = [int]$count = 0
        $stream.Write($formitembytes, 0, $formitembytes.Length)
        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
        $stream.Write($headerbytes, 0, $headerbytes.Length)
        $count = $rdr.Read($buffer, 0, $buffer.Length)
        do {
            $stream.Write($buffer, 0, $count)
            $count = $rdr.Read($buffer, 0, $buffer.Length)
        }while ($count > 0)
        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
        $stream.Write($footerBytes, 0, $footerBytes.Length)
        $stream.close()

        Try {
            # Upload the file
            $response = $req.GetResponse()

            # Read the response
            $respstream = $response.GetResponseStream()
            $sr = new-object System.IO.StreamReader $respstream
            $result = $sr.ReadToEnd()
            ConvertFrom-Json $result
        }
        Catch [Net.WebException] {
            if ($Error[0].ToString() -like '*403*') {
                Write-Error 'API key is not valid.'
            }
            elseif ($Error[0].ToString() -like '*204*') {
                Write-Error 'API key rate has been reached.'
            }
        }
    }
    End {
    }
}

#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-PoshVTVersion {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    Param
     ()
 
    Begin {
        $currentversion = ''
        $installed = Get-Module -Name 'Posh-VirusTotal' 
    }
    Process {
        $webClient = New-Object System.Net.WebClient
        Try {
            $current = Invoke-Expression  $webClient.DownloadString('https://raw.github.com/darkoperator/Posh-VirusTotal/master/Posh-VirusTotal.psd1')
            $currentversion = $current.moduleversion
        }
        Catch {
            Write-Warning 'Could not retrieve the current version.'
        }
        $majorver, $minorver = $currentversion.split('.')

        if ($majorver -gt $installed.Version.Major) {
            Write-Warning 'You are running an outdated version of the module.'
        }
        elseif ($minorver -gt $installed.Version.Minor) {
            Write-Warning 'You are running an outdated version of the module.'
        } 
        
        $props = @{
            InstalledVersion = "$($installed.Version)"
            CurrentVersion   = $currentversion
        }
        New-Object -TypeName psobject -Property $props
    }
    End {
          
    }
}

#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTAPIKeyInfo {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {
        $URI = 'http://www.virustotal.com/vtapi/v2/key/details'
        if (!($APIKey)) {
            NoAPIKeyError
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'apikey' = $APIKey }

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $IPReport = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0, 'VirusTotal.IP.Report')
        $IPReport
        
    }
    End {
    }
}


# Private API
###############


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTSpecialURL {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # VirusToral Private API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {
        
        $URI = 'https://www.virustotal.com/vtapi/v2/file/scan/upload_url'
        if (!($APIKey)) {
            NoAPIKeyError
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            WrongAPIKeyError
        }
        Write-Verbose 'Key verifies as a Private API Key.'
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'apikey' = $APIKey }

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
        
        $IPReport = Invoke-RestMethod $Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0, 'VirusTotal.SpecialUploadURL')
        $IPReport
    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileComment {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5, SHA1 or SHA256 Checksum to get comments from.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/comments/get'
        if (!($APIKey)) {
            NoAPIKeyError
        }
        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            WrongAPIKeyError
        }
        Write-Verbose 'Key verifies as a Private API Key.'

        $Body = @{'apikey' = $APIKey }
    }
    Process {

        $Body.add('resource', $Resource)

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                Write-Error 'API key is not valid.' -ErrorAction Stop
            }
            elseif ($RESTError.Message -like '*204*') {
                Write-Error 'API key rate has been reached.' -ErrorAction Stop
            }
            else {
                Write-Error $RESTError
            }
        }
        $Response.pstypenames.insert(0, 'VirusTotal.Comment')
        $Response

    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Set-VTFileComment {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5, SHA1 or SHA256 Checksum to comment on.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Comment,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/comments/put'
        if (!($APIKey)) {
            NoAPIKeyError
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            WrongAPIKeyError
        }
        Write-Verbose 'Key verifies as a Private API Key.'

        $Body = @{'apikey' = $APIKey }
    }
    Process {

        $Body.add('resource', $Resource)

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }
        $Response.pstypenames.insert(0, 'VirusTotal.Comment')
        $Response

    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Set-VTFileRescan {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        # Date in which the rescan should be performed. If not specified the rescan will be performed immediately.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [datetime]$Date,

        # Period in days in which the file should be rescanned.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [int32]$Period,

        # Used in conjunction with period to specify the number of times the file should be rescanned.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [int32]$Repeat,

        # An URL where a POST notification should be sent when the rescan finishes.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [string]$NotifyURL,

        # Indicates if POST notifications should be sent only if the scan results differ from the previous one.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [bool]$NotifyChanges,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/rescan'
        if (!($APIKey)) {
            NoAPIKeyError
        }
        $Body = @{'apikey' = $APIKey }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            WrongAPIKeyError
        }
        Write-Verbose 'Key verifies as a Private API Key.'
    }
    Process {
        $Body.add('resource', $Resource)
        if ($Date) {
            $Body.add('date', ($Date.ToString('yyyyMMddhhmmss')))
        }

        if ($Period) {
            $Body.add('period', $Period)
        }

        if ($Repeat) {
            $Body.add('repeat', $Repeat)
        }

        if ($NotifyURL) {
            $Body.add('notify_url', $NotifyURL)
        }

        if ($NotifyChanges) {
            $Body.add('notify_changes_only', $NotifyChanges)
        }

        $Body.add('resource', $Resource)
        
        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }

        $Response.pstypenames.insert(0, 'VirusTotal.ReScan')
        $Response
        
    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Remove-VTFileRescan {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to remove rescan.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/rescan/delete'
        if (!($APIKey)) {
            NoAPIKeyError
        }

        $Body = @{'apikey' = $APIKey }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            WrongAPIKeyError
        }
        Write-Verbose 'Key verifies as a Private API Key.'

    }
    Process {

        $Body.add('resource', $Resource)

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
        
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        
        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                Write-Error 'API key is not valid.' -ErrorAction Stop
            }
            elseif ($RESTError.Message -like '*204*') {
                Write-Error 'API key rate has been reached.' -ErrorAction Stop
            }
            else {
                Write-Error $RESTError
            }
        }

        $Response.pstypenames.insert(0, 'VirusTotal.ReScan')
        $Response

    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileScanReport {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID of the scan.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $false)]
        [switch]$AllInfo,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/report'
        if (!($APIKey)) {
            NoAPIKeyError
        }

        $Body = @{'apikey' = $APIKey }

        if ($AllInfo) {
            $Body.Add('allinfo', 1)
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            WrongAPIKeyError
        }
        Write-Verbose 'Key verified as a Private API Key.'
    }
    Process {

        $Body.add('resource', $Resource)
        
        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                Write-Error 'API key is not valid.' -ErrorAction Stop
            }
            elseif ($RESTError.Message -like '*204*') {
                Write-Error 'API key rate has been reached.' -ErrorAction Stop
            }
            else {
                Write-Error $RESTError
            }
        }
        $Response.pstypenames.insert(0, 'VirusTotal.Scan.Report')
        $Response

    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileBehaviourReport {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum or File SHA256 Checksum of file.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        # File name and path to save Behaviour report as a Cuckoo JSON Dump.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Report,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials

    
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/behaviour'
        if (!($APIKey)) {
            NoAPIKeyError
        }
        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            WrongAPIKeyError
        }
        Write-Verbose 'Key verified as a Private API Key.'

        $Body = @{'apikey' = $APIKey }
    }
    Process {

        $Body.add('hash', $Resource)

        $ReportFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Report)
        
        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('Outfile', $ReportFullPath)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
        
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        Write-Verbose "Saving report to $($ReportFullPath)."

        $bahaviour_report = Invoke-WebRequest @Params

        $ErrorActionPreference = $OldEAP
        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }
    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileSample {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum or File SHA256 Checksum of file.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        # File name and path to save sample.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [string]$File,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/download'
        if (!($APIKey)) {
            Write-Error 'No VirusTotal API Key has been specified or set.'
        }
        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verified as a Private API Key.'

        $Body = @{'apikey' = $APIKey }
    }
    Process {

        $Body.add('hash', $Resource)

        $SampleFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('OutFile', $SampleFullPath)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        Write-Verbose "Saving report to $($SampleFullPath)."

        $SampleResponse = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }
    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileNetworkTraffic {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum or File SHA256 Checksum.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Hash,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        # File name and path to save Network Traffic in PCAP format.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [string]$File,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials

    
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/network-traffic'
        if (!($APIKey)) {
            throw 'No VirusTotal API Key has been specified or set.'
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verified as a Private API Key.'

        $Body = @{'apikey' = $APIKey }
    }
    Process {

        $Body.add('hash', $Resource)

        $NTFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)

        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('OutFile', $NTFullPath)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        

        Write-Verbose "Saving file to $($NTFullPath)."

        $NTResponse = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*') {
                throw 'API key rate has been reached.'
            }
            else {
                throw $RESTError
            }
        }
    }
    End {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Search-VTAdvancedReversed {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # A search modifier compliant file search query..
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Query,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$APIKey,

        # The offset value returned by a previously issued identical query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [int]$OffSet,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/search'
        if (!($APIKey)) {
            Write-Error 'No VirusTotal API Key has been specified or set.'
        }

        $Body = @{'apikey' = $APIKey
            'query'        = $Query
        }
        # If an offset is provided apply it.
        if ($OffSet) {
            $Body.Add('offset', $OffSet)
        }
        
        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private') {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verifies as a Private API Key.'

    }
    Process {
        
        # Start building parameters for REST Method invokation.
        $Params = @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy') {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential) {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials) {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint) {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        
        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError) {
            if ($RESTError.Message.Contains('403')) {
                Write-Error 'API key is not valid.' -ErrorAction Stop
            }
            elseif ($RESTError.Message -like '*204*') {
                Write-Error 'API key rate has been reached.' -ErrorAction Stop
            }
            else {
                Write-Error $RESTError[0]
            }
        }

        $Response.pstypenames.insert(0, 'VirusTotal.Search')
        $Response

    }
    End {
    }
}

function New-ErrorRecord {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, 
            Position = 0)]
        [System.String]
        $Exception,
        
        [Parameter(Mandatory = $true, 
            Position = 1)]
        [Alias('ID')]
        [System.String]
        $ErrorId,

        [Parameter(Mandatory = $true, 
            Position = 2)]
        [Alias('Category')]
        [System.Management.Automation.ErrorCategory]
        [ValidateSet('NotSpecified', 'OpenError', 'CloseError', 'DeviceError',
            'DeadlockDetected', 'InvalidArgument', 'InvalidData',
            'InvalidOperation', 'InvalidResult', 'InvalidType',
            'MetadataError', 'NotImplemented', 'NotInstalled', 
            'ObjectNotFound', 'OperationStopped', 'OperationTimeout',
            'SyntaxError', 'ParserError', 'PermissionDenied',
            'ResourceBusy', 'ResourceExists', 'ResourceUnavailable',
            'ReadError', 'WriteError', 'FromStdErr',
            'SecurityError', 'ProtocolError', 'ConnectionError',
            'AuthenticationError', 'LimitsExceeded', 'QuotaExceeded',
            'NotEnabled')]
        $ErrorCategory,

        [Parameter(Mandatory = $true, 
            Position = 3)]
        [System.Object]
        $TargetObject,
        
        [Parameter(Mandatory = $true)]
        [System.String]
        $Message
    )

    Begin {}
    Process {}
    End {}
}

function WrongAPIKeyError($KeyInfo) {
    $message = 'The key provided is not a Private API Key'
    $exception = New-Object InvalidOperationException $message
    $errorID = 'PermissionDenied'
    $errorCategory = [Management.Automation.ErrorCategory]::PermissionDenied
    $errorRecord = New-Object Management.Automation.ErrorRecord $exception, $errorID, $errorCategory, $KeyInfo
    $PSCmdlet.ThrowTerminatingError($errorRecord)
}

function NoAPIKeyError($KeyInfo) {
    $message = 'No VirtusTotal API key is set or specified'
    $exception = New-Object InvalidOperationException $message
    $errorID = 'InvalidArgument'
    $errorCategory = [Management.Automation.ErrorCategory]::InvalidArgument
    $errorRecord = New-Object Management.Automation.ErrorRecord $exception, $errorID, $errorCategory, $KeyInfo
    $PSCmdlet.ThrowTerminatingError($errorRecord)
}

# export-modulemember -function '*-VT*','*-PoshVT*'
