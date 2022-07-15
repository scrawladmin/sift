Function New-Request {
    Param ($object, $obejct2)
    Write-Verbose "Function: $($MyInvocation.Mycommand)"
    If ([switch]$ippulse) {
        [string]$ipaddress = $ipaddress
        Get-ippulse $ipaddress
    }
    If ([switch]$fqdnpulse) {
        Get-fqdnpulse $object
    }
    If ([switch]$ipprobe) {
        Get-neuIPProbe $object
    }
    If ([switch]$ipblocklist) {
        [string]$object = $ipaddress
        Get-neuIPBlockList $object
    }
    If ([switch]$hostrep) {
        Get-neuHostRep $object
    }
    If ([switch]$ipinfo) {
        Get-neuIPInfo $object
    }
    If ([switch]$urlinfo) {
        Get-neuURLInfo $object
    }
    If ([switch]$emailvalidate) {
        Get-neuEmailvalidate $object
    }
    If ([switch]$emailverify) {
        Get-neuEmailverify $object
    }
    # If ([switch]$htmlclean) {
    #     Get-neuHTMLclean $object
    # }
    If ([switch]$traceroute) {
        Test-MTR $target ; ; Start-mtr $target
    }
    If ([switch]$ping) {
        Ping-Flood $ipaddress
    }
    If ([switch]$whois) {
        [string]$ipaddress = $ipaddress
        Get-whois $ipaddress
    }
    If ([switch]$ipreport) {
        [string]$ipaddress = $ipaddress
        Get-VTIPReport $ipaddress
    }
    If ([switch]$urlreport) {
        # [string]$url = $object
        Get-VTURLReport $object -scan
    }
    If ([switch]$filereport) {
        $object = (Get-FileHash $object -Algorithm SHA256).Hash
        Get-VTFileReport $object
    }
    If ([switch]$domainreport) {
        [string]$fqdn = $object
        Get-VTDomainReport $fqdn
    }
    If ([switch]$iplookup) {
        Get-ipstack $object
    }
    If ([switch]$urlscan) {
        Get-urlscanio $object
    }
    If ([switch]$iprep) {
        Get-fraudguardiprep $object
    }
    If ([switch]$ipservices) {
        [string]$ipaddress = $ipaddress
        Get-shodanip $ipaddress
    }
    if ([switch]$ptr) {
        [string]$ipaddress = $ipaddress
        Get-MxLookup -Command ptr -IPAddress $ipaddress
    }
    if ([switch]$mx) {
        [string]$object = $fqdn
        Get-MxLookup -Command mx -Domain $object
    }
    if ([switch]$a) {
        [string]$object = $fqdn
        Get-MxLookup -Command a -Domain $object
    }
    if ([switch]$dns) {
        [string]$object = $fqdn
        Get-MxLookup -Command dns -Domain $object
    }
    if ([switch]$spf) {
        [string]$object = $fqdn
        Get-MxLookup -Command spf -Domain $object
    }
    if ([switch]$txt) {
        [string]$object = $fqdn
        Get-MxLookup -Command txt -Domain $object
    }
    if ([switch]$soa) {
        [string]$object = $fqdn
        Get-MxLookup -Command soa -Domain $object
    }
    if ([switch]$blacklist) {
        [string]$object = $fqdn
        Get-MxLookup -Command blacklist -Domain $object
    }
    If ([switch]$ipblacklist) {
        [string]$ipaddress = $ipaddress
        Get-hetrixIPblacklist $ipaddress
    }
    If ([switch]$fqdnblacklist) {
        Get-hetrixDomainblacklist $object
    }
    If ([switch]$urlquery) {
        Get-URLhausQuery $object
    }
    If ([string]$APIKey -and [securestring]$masterpassword) {
        set-APIKey $APIKey $masterpassword
    }
    If ([switch]$unlock -and [securestring]$masterpassword) {
        Read-APIKey $masterpassword
    }

}
Function Get-Logo {
    Write-Verbose "Function: $($MyInvocation.Mycommand)" 
    Write-Host "
    _________.__  _____  __   
   /   _____/|__|/ ____\/  |_ 
   \_____  \ |  \   __\\   __\
   /        \|  ||  |   |  |  
  /_______  /|__||__|   |__|  
          \/                  
" -F C
}
Function Set-Console {
    Write-Verbose "Function: $($MyInvocation.Mycommand)"
    If ( $logo -ne "off") {
        if (!$PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
            Clear-Host
            $host.ui.RawUi.WindowTitle = "...::: Sift :::..."
            [console]::ForegroundColor = "White"
            [console]::BackgroundColor = "Black"
            $host.PrivateData.VerboseForegroundColor = 'White'
            Get-Logo
        }
    }
    Else {
        $host.ui.RawUi.WindowTitle = "...::: Sift :::..."
        [console]::ForegroundColor = "White"
        [console]::BackgroundColor = "Black"
        $host.PrivateData.VerboseForegroundColor = 'White'
    }
}
Function Write-log {
    param ($logmessage)
    if ($log) {
        Add-Content $log "[$loggingdate] $logmessage "
    }
}

Function Test-PSversion {
    Write-Verbose "Function: $($MyInvocation.Mycommand)"
    $psSeven = ( $PSVersionTable.PSVersion.Major -eq 7 ) 
    If ($psSeven -eq $true ) {
        $script:psSeven = 1
    }
    Else {
        $script:psSeven = $null
    }
}

# https://gist.github.com/PrateekKumarSingh/715b0576a0cd08769b967db7a86355ff
Function Trace-Word {
    [Cmdletbinding()]
    [Alias("Highlight")]
    Param(
        [Parameter(ValueFromPipeline = $true, Position = 0)] [string[]] $content,
        [Parameter(Position = 1)] 
        [ValidateNotNull()]
        [String[]] $words = $(throw "Provide word[s] to be highlighted!")
    )
    
    Begin {
        
        $Color = @{       
            0  = 'Yellow'      
            1  = 'Magenta'     
            2  = 'Red'         
            3  = 'Cyan'        
            4  = 'Green'       
            5  = 'Blue'        
            6  = 'DarkGray'    
            7  = 'Gray'        
            8  = 'DarkYellow'    
            9  = 'DarkMagenta'    
            10 = 'DarkRed'     
            11 = 'DarkCyan'    
            12 = 'DarkGreen'    
            13 = 'DarkBlue'        
        }

        $ColorLookup = @{}

        For ($i = 0; $i -lt $words.count ; $i++) {
            if ($i -eq 13) {
                $j = 0
            }
            else {
                $j = $i
            }

            $ColorLookup.Add($words[$i], $Color[$j])
            $j++
        }
        
    }
    Process {
        $content | ForEach-Object {
    
            $TotalLength = 0
               
            $_.split() | `
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ` #Filter-out whiteSpaces
            ForEach-Object {
                if ($TotalLength -lt ($Host.ui.RawUI.BufferSize.Width - 10)) {
                    #"TotalLength : $TotalLength"
                    $Token = $_
                    $displayed = $False
                            
                    Foreach ($Word in $Words) {
                        if ($Token -like "*$Word*") {
                            $Before, $after = $Token -Split "$Word"
                              
                                        
                            #"[$Before][$Word][$After]{$Token}`n"
                                    
                            Write-Host $Before -NoNewline ; 
                            Write-Host $Word -NoNewline -Fore Black -Back $ColorLookup[$Word];
                            Write-Host $after -NoNewline ; 
                            $displayed = $true                                   
                            #Start-Sleep -Seconds 1    
                            #break  
                        }

                    } 
                    If (-not $displayed) {   
                        Write-Host "$Token " -NoNewline                                    
                    }
                    else {
                        Write-Host " " -NoNewline  
                    }
                    $TotalLength = $TotalLength + $Token.Length + 1
                }
                else {                      
                    Write-Host '' #New Line  
                    $TotalLength = 0 

                }

                #Start-Sleep -Seconds 0.5
                        
            }
            Write-Host '' #New Line               
        }
    }
    end
    {    }

}
#Trace-Word -content (Get-Content iis.log) -words "IIS", 's', "exe", "10", 'system'
# https://github.com/copdips/PSScripts/blob/master/Text/Select-ColorString.ps1
function Select-ColorString {
    <#
   .SYNOPSIS

   Find the matches in a given content by the pattern and write the matches in color like grep.

   .NOTES

   inspired by: https://ridicurious.com/2018/03/14/highlight-words-in-powershell-console/

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString a

   Both line 'aa bb cc' and line 'A line' are displayed as both contain "a" case insensitive.

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString a -NotMatch

   Nothing will be displayed as both lines have "a".

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString a -CaseSensitive

   Only line 'aa bb cc' is displayed with color on all occurrences of "a" case sensitive.

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString '(a)|(\sb)' -CaseSensitive -BackgroundColor White

   Only line 'aa bb cc' is displayed with background color White on all occurrences of regex '(a)|(\sb)' case sensitive.

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString b -KeepNotMatch

   Both line 'aa bb cc' and 'A line' are displayed with color on all occurrences of "b" case insensitive,
   and for lines without the keyword "b", they will be only displayed but without color.

   .EXAMPLE

   > Get-Content app.log -Wait -Tail 100 | Select-ColorString "error|warning|critical" -MultiColorsForSimplePattern -KeepNotMatch

   Search the 3 key words "error", "warning", and "critical" in the last 100 lines of the active file app.log and display the 3 key words in 3 colors.
   For lines without the keys words, hey will be only displayed but without color.

   .EXAMPLE

   > Get-Content "C:\Windows\Logs\DISM\dism.log" -Tail 100 -Wait | Select-ColorString win

   Find and color the keyword "win" in the last ongoing 100 lines of dism.log.

   .EXAMPLE

   > Get-WinEvent -FilterHashtable @{logname='System'; StartTime = (Get-Date).AddDays(-1)} | Select-Object time*,level*,message | Select-ColorString win

   Find and color the keyword "win" in the System event log from the last 24 hours.
   #>

    [Cmdletbinding(DefaultParametersetName = 'Match')]
    param(
        [Parameter(
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$Pattern = $(throw "$($MyInvocation.MyCommand.Name) : " `
                + "Cannot bind null or empty value to the parameter `"Pattern`""),

        [Parameter(
            ValueFromPipeline = $true,
            HelpMessage = "String or list of string to be checked against the pattern")]
        [String[]]$Content,

        [Parameter()]
        [ValidateSet(
            'Black',
            'DarkBlue',
            'DarkGreen',
            'DarkCyan',
            'DarkRed',
            'DarkMagenta',
            'DarkYellow',
            'Gray',
            'DarkGray',
            'Blue',
            'Green',
            'Cyan',
            'Red',
            'Magenta',
            'Yellow',
            'White')]
        [String]$ForegroundColor = 'Black',

        [Parameter()]
        [ValidateSet(
            'Black',
            'DarkBlue',
            'DarkGreen',
            'DarkCyan',
            'DarkRed',
            'DarkMagenta',
            'DarkYellow',
            'Gray',
            'DarkGray',
            'Blue',
            'Green',
            'Cyan',
            'Red',
            'Magenta',
            'Yellow',
            'White')]
        [ValidateScript( {
                if ($Host.ui.RawUI.BackgroundColor -eq $_) {
                    throw "Current host background color is also set to `"$_`", " `
                        + "please choose another color for a better readability"
                }
                else {
                    return $true
                }
            })]
        [String]$BackgroundColor = 'White',

        [Parameter()]
        [Switch]$CaseSensitive,

        [Parameter(
            HelpMessage = "Available only if the pattern is simple non-regex string " `
                + "separated by '|', use this switch with fast CPU.")]
        [Switch]$MultiColorsForSimplePattern,

        [Parameter(
            ParameterSetName = 'NotMatch',
            HelpMessage = "If true, write only not matching lines; " `
                + "if false, write only matching lines")]
        [Switch]$NotMatch,

        [Parameter(
            ParameterSetName = 'Match',
            HelpMessage = "If true, write all the lines; " `
                + "if false, write only matching lines")]
        [Switch]$KeepNotMatch
    )

    begin {
        $paramSelectString = @{
            Pattern       = $Pattern
            AllMatches    = $true
            CaseSensitive = $CaseSensitive
        }
        $writeNotMatch = $KeepNotMatch -or $NotMatch

        [System.Collections.ArrayList]$colorList = [System.Enum]::GetValues([System.ConsoleColor])
        $currentBackgroundColor = $Host.ui.RawUI.BackgroundColor
        $colorList.Remove($currentBackgroundColor.ToString())
        $colorList.Remove($ForegroundColor)
        $colorList.Reverse()
        $colorCount = $colorList.Count

        if ($MultiColorsForSimplePattern) {
            # Get all the console foreground and background colors mapping display effet:
            # https://gist.github.com/timabell/cc9ca76964b59b2a54e91bda3665499e
            $patternToColorMapping = [Ordered]@{}
            # Available only if the pattern is a simple non-regex string separated by '|', use this with fast CPU.
            # We dont support regex as -Pattern for this switch as it will need much more CPU.
            # This switch is useful when you need to search some words,
            # for example searching "error|warn|crtical" these 3 words in a log file.
            $expectedMatches = $Pattern.split("|")
            $expectedMatchesCount = $expectedMatches.Count
            if ($expectedMatchesCount -ge $colorCount) {
                Write-Host "The switch -MultiColorsForSimplePattern is True, " `
                    + "but there're more patterns than the available colors number " `
                    + "which is $colorCount, so rotation color list will be used." `
                    -ForegroundColor Yellow
            }
            0..($expectedMatchesCount - 1) | % {
                $patternToColorMapping.($expectedMatches[$_]) = $colorList[$_ % $colorCount]
            }

        }
    }

    process {
        foreach ($line in $Content) {
            $matchList = $line | Select-String @paramSelectString

            if (0 -lt $matchList.Count) {
                if (-not $NotMatch) {
                    $index = 0
                    foreach ($myMatch in $matchList.Matches) {
                        $length = $myMatch.Index - $index
                        Write-Host $line.Substring($index, $length) -NoNewline

                        $expectedBackgroupColor = $BackgroundColor
                        if ($MultiColorsForSimplePattern) {
                            $expectedBackgroupColor = $patternToColorMapping[$myMatch.Value]
                        }

                        $paramWriteHost = @{
                            Object          = $line.Substring($myMatch.Index, $myMatch.Length)
                            NoNewline       = $true
                            ForegroundColor = $ForegroundColor
                            BackgroundColor = $expectedBackgroupColor
                        }
                        Write-Host @paramWriteHost

                        $index = $myMatch.Index + $myMatch.Length
                    }
                    Write-Host $line.Substring($index)
                }
            }
            else {
                if ($writeNotMatch) {
                    Write-Host "$line"
                }
            }
        }
    }

    end {
    }
}
<#
https://www.powershellgallery.com/packages/Formulaic/0.2.1.0/Content/Get-StandardDeviation.ps1
.Synopsis
    Gets the standard deviation of a series of numbers
.Description
    Gets the standard deviation of a series of numbers
.Example
    Get-StandardDeviation 2,4,6,8
#>
function Get-StandardDeviation {
    param(
        # The series of numbers
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [Double[]]
        $Number
    )
    begin {
        $numberSeries = @()
    }
    process {
        $numberSeries += $number
    }
    end {
        # Start the total at zero
        $total = 0
        foreach ($n in $numberSeries) {
            # Add $n to the total
            $total += $n
        }
        # The average is the total divided by the number of items $($numberSeries.Count)
        $average = $total / $($numberSeries.Count)
        $deviationTotal = 0
        foreach ($n in $NumberSeries) {
            # Add $n to the total
            $deviationTotal += [Math]::Pow(($n - $average), 2)
        }
        $scriptBlock += 
        $deviationAverage = $deviationTotal / $($numberSeries.Count)
        $standardDeviation = [Math]::Sqrt($deviationAverage)
        $sb = [ScriptBlock]::Create($scriptBlock)        
        $null = . $sb
        $standardDeviation
    }
} 

function Set-APIKey {
    [CmdletBinding()]
    Param
    (
        # API Key.
        [Parameter(Mandatory = $true)]
        [string]$APIKey,
        [securestring]$MasterPassword
    )

    Begin {
    }
    Process {
        $SecureKeyString = ConvertTo-SecureString -String $APIKey -AsPlainText -Force

        # Generate a random secure Salt
        $SaltBytes = New-Object byte[] 32
        $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $RNG.GetBytes($SaltBytes)

        $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword

        # Derive Key, IV and Salt from Key
        $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
        $KeyBytes = $Rfc2898Deriver.GetBytes(32)

        $EncryptedString = $SecureKeyString | ConvertFrom-SecureString -Key $KeyBytes
        if ([switch]$neutrino ) {
            $FolderName = "neutrino"
        }
        if ([switch]$virustotal ) {
            $FolderName = "VirusTotal"
        }
        if ([switch]$ipstack ) {
            $FolderName = "IPstack"
        }
        if ([switch]$urlscanio ) {
            $FolderName = "Urlscanio"
        }
        if ([switch]$shodan ) {
            $FolderName = "Shodan"
        }
        if ([switch]$hetrix ) {
            $FolderName = "Hetrixtools"
        }
        if ([switch]$fraudguard ) {
            $FolderName = "Fraudguard"
        }
        if ([switch]$mxtoolbox ) {
            $FolderName = "MXtoolbox"
        }
        $ConfigName = 'api.key'
        $saltname = 'salt.rnd'
        
        if (!(Test-Path "$($env:AppData)\$FolderName")) {
            Write-Verbose -Message 'Seems this is the first time the config has been set.'
            Write-Verbose -Message "Creating folder $("$($env:AppData)\$FolderName")"
            New-Item -ItemType directory -Path "$($env:AppData)\$FolderName" | Out-Null
        }
        Write-Verbose -Message "Saving the information to configuration file $("$($env:AppData)\$FolderName\$ConfigName")"
        "$($EncryptedString)"  | Set-Content  "$($env:AppData)\$FolderName\$ConfigName" -Force
        Set-Content -Value $SaltBytes -Encoding utf32 -Path "$($env:AppData)\$FolderName\$saltname" -Force
    }
    End {
    }
}

function Read-APIKey {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [securestring]$MasterPassword )

    # Test if configuration file exists.
    if ([switch]$unlock ) {
        $FolderNames = "neutrino", "MXtoolbox", "VirusTotal", "IPstack", "Urlscanio", "Shodan", "Hetrixtools", "Fraudguard"
        foreach ($foldername in $FolderNames) {
            if ((Test-Path "$($env:AppData)\$FolderName\api.key")) {

                Write-Verbose -Message "Reading key from $($env:AppData)\$FolderName\api.key."
                $ConfigFileContent = Get-Content -Path "$($env:AppData)\$FolderName\api.key"
                $SaltBytes = Get-Content -Encoding utf32 -Path "$($env:AppData)\$FolderName\salt.rnd" 


                Write-Verbose -Message "Secure string is $($ConfigFileContent)"
                $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword

                # Derive Key, IV and Salt from Key
                $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
                $KeyBytes = $Rfc2898Deriver.GetBytes(32)

                $SecString = ConvertTo-SecureString -key $KeyBytes $ConfigFileContent

                # Decrypt the secure string.
                $SecureStringToBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecString)
                $global:APIKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto($SecureStringToBSTR)

                # Set session variable with the key.
                Write-Verbose -Message "Setting key $($APIKey) to variable for use by other commands."
               
                Set-Variable -Name $($foldername + "key") -Option Constant -Scope Global -Value $APIKey
               
                Write-Verbose -Message 'Key has been set.'
            }
            else {
                Write-Verbose "Configuration has not been set, API Key $FolderName"
            }
        }
    }
}