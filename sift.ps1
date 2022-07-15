<#
.SYNOPSIS
    A collection of PowerShell scripts to utilize 3rd party APIs and research IPs, URLs, and Domains
.DESCRIPTION

.PARAMETER unlock
    sift -unlock
    uses masterpassword to unlock encrypted keys and cache for use till terminal exits
.PARAMETER addkey 
    sift -addkey -neutrino
    adds neutrino api key with masterpassword used as salt to encrypted file to store
.PARAMETER ipaddress
    IPv4 Address in Decimal
.PARAMETER fqdn
    google.com
.PARAMETER target
    8.8.8.8
    google.com
.PARAMETER url
    https://bit.ly/somesketchurl
.PARAMETER filepath
    C:\path\to\file.pdf
.EXAMPLE
    sift -ipaddress 8.8.8.8 -ipservices
.EXAMPLE
    sift -target 8.8.8.8 -traceroute
    sift -target one.one.one.one -traceroute
.EXAMPLE
    sift -url http://8.8.8.8:35215/bin.sh -urlinfo
.EXAMPLE
    sift -fqdn gooogle.com -fqdnblacklist
.NOTES
    Author: scrawladmin
    Date:   9-26-2021   
.LINK
    https://github.com/scrawladmin/sift

#>
Param(

    [Parameter(ParameterSetName = "ipaddress", Position = 0)]
    [ipaddress[]]
    $ipaddress,

    [Parameter(ParameterSetName = "fqdn", Position = 0)]
    [string[]]
    $fqdn,

    [Parameter(ParameterSetName = "mtr", Position = 0)]
    $target,

    [Parameter(ParameterSetName = "url", Position = 0)]
    [string[]]
    $url,

    [Parameter(ParameterSetName = "virustotal-filereport", Position = 0)]
    [string[]]
    $filepath,

    #  ! HIT THE MAX AMOUNT OF OF PARAMETERSETNAMEs !
    # [Parameter(ParameterSetName = "neutrino-urlemail", Position = 0)]
    # [Parameter(ParameterSetName = "neutrino-urlverify", Position = 0)]
    # [string[]]
    # $email,

    [Parameter(ParameterSetName = "set_key", Position = 0)]
    [switch]
    $addkey,

    [Parameter(ParameterSetName = "set_key", Position = 1)]
    [switch]
    $neutrino,

    [Parameter(ParameterSetName = "set_key", Position = 1)]
    [switch]
    $virustotal,

    [Parameter(ParameterSetName = "set_key", Position = 1)]
    [switch]
    $ipstack,

    [Parameter(ParameterSetName = "set_key", Position = 1)]
    [switch]
    $urlscanio,

    [Parameter(ParameterSetName = "set_key", Position = 1)]
    [switch]
    $shodan,

    [Parameter(ParameterSetName = "set_key", Position = 1)]
    [switch]
    $hetrix,

    [Parameter(ParameterSetName = "set_key", Position = 1)]
    [switch]
    $fraudguard,

    [Parameter(ParameterSetName = "set_key", Position = 1)]
    [switch]
    $mxtoolbox,

    [Parameter(ParameterSetName = "unlock_keys", Position = 1)]
    [switch]
    $unlock,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $ipblocklist,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $ipprobe,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [Parameter(ParameterSetName = "url", Position = 1)]
    [switch]
    $hostrep,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $ipinfo,

    [Parameter(ParameterSetName = "url", Position = 1)]
    [switch]
    $urlinfo,

    #  ! HIT THE MAX AMOUNT OF OF PARAMETERSETNAMEs !
    # [Parameter(ParameterSetName = "neutrino-urlemail", Position = 1)]
    # [switch]
    # $emailvalidate,

    # [Parameter(ParameterSetName = "neutrino-urlverify", Position = 1)]
    # [switch]
    # $emailverify,

    # [Parameter(ParameterSetName = "neutrino-html", Position = 1)]
    # [switch]
    # $htmlclean,

    [Parameter(ParameterSetName = "mtr", Position = 1)]
    [switch]
    $traceroute,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $ping,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $whois,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $ipreport,

    [Parameter(ParameterSetName = "url", Position = 1)]
    [switch]
    $urlreport,

    [Parameter(ParameterSetName = "virustotal-filereport", Position = 1)]
    [switch]
    $filereport,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [switch]
    $domainreport,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $iplookup,

    [Parameter(ParameterSetName = "url", Position = 1)]
    [switch]
    $urlscan,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $iprep,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $ipservices,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [switch]
    $mx,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [switch]
    $a,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [switch]
    $dns,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [switch]
    $spf,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [switch]
    $txt,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [switch]
    $soa,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $ptr,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [switch]
    $blacklist,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $ipblacklist,

    [Parameter(ParameterSetName = "fqdn", Position = 1)]
    [switch]
    $fqdnblacklist,

    [Parameter(ParameterSetName = "url", Position = 1)]
    [switch]
    $urlquery,

    [Parameter(ParameterSetName = "ipaddress", Position = 1)]
    [switch]
    $ippulse,

    [Parameter(ParameterSetName = "fqdn", Position = 0)]
    [switch]
    $fqdnpulse

    # [Parameter(Mandatory = $false, ParameterSetName = "ipaddress", Position = 2)]
    # [Parameter(Mandatory = $false, ParameterSetName = "ipaddress", Position = 2)]
    # [Parameter(Mandatory = $false, ParameterSetName = "ipaddress", Position = 2)]
    # [Parameter(Mandatory = $false, ParameterSetName = "ipaddress", Position = 2)]
    # [Parameter(Mandatory = $false, ParameterSetName = "ipaddress", Position = 2)]
    # [Parameter(Mandatory = $false, ParameterSetName = "fqdn", Position = 2)]
    # [Parameter(Mandatory = $false, ParameterSetName = "neutrino-hostrep2", Position = 2)]
    # [Parameter(Mandatory = $false, ParameterSetName = "ipaddress", Position = 2)]
    # [switch]
    # $raw
)

$script:currentdir = $PSScriptRoot
$script:loggingDate = get-date -Format MM-dd-yyyy-hh:mm:ss
$script:logDate = Get-Date -Format MM-dd-yyyy

Get-ChildItem -Path $currentdir\functions -Filter *.ps1 | % { . $_.FullName }
If (!(Test-Path $currentdir\log)) { 
    New-Item -ItemType Directory -Path $currentdir -Name log -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
}

Set-Console  >$null 2>&1
Test-PSversion
Set-Settings
Write-Verbose "checking command"
If ($ipaddress) {
    New-Request $ipaddress
}
ElseIf ($fqdn) {
    New-Request $fqdn
}
ElseIf ($url) {
    New-Request $url
}
ElseIf ($email) {
    New-Request $email
}
# ElseIf ($html) {
#     New-Request $html
# }
ElseIf ($target) {
    New-Request $target
}
ElseIf ($filepath) {
    New-Request $filepath
}
ElseIf ([switch]$unlock) {
    $masterpassword = read-host "Enter a masterPassword" -AsSecureString
    New-request $masterpassword 
}
ElseIf ([switch]$addkey) {
    $masterpassword = read-host "Enter a masterPassword" -AsSecureString
    $APIKey = read-host "Enter api key"
    New-request $APIKey $masterpassword 
}
Else {
    Write-Verbose "command failed"
}


