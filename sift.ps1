<#
.SYNOPSIS
    PowerShell script to utilize 3rd party APIs and research IPs,URLs,etc... 
.DESCRIPTION

.PARAMETER ipaddress
    IPv4 Address in Decimal
.PARAMETER fqdn
    google.com
.PARAMETER target
    8.8.8.8
    google.com
.PARAMETER url
    https://bit.ly/somesketchurl
.PARAMETER email
    neo@aol.com
.PARAMETER filepath
    C:\path\to\file.pdf
.EXAMPLE
    neo.ps1 -ipaddress 8.8.8.8 -ipservices
.NOTES
    Author: scrawladmin
    Date:   9-26-2021   
.LINK
    https://github.com/scrawladmin/sift

#>
Param(
    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-ipblock", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-ipprobe", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-ipinfo", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-hostrep", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "ping", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "whois", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "virustotal-ipreport", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "ipstack-iplookup", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "fraudguard-iprep", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "shodan-ipservices", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-ptr", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "hetrixtools-IPblacklist", Position = 0)]
    [ipaddress[]]
    $ipaddress,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrinohostrep1", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "virustotal-domainreport", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-mx", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-a", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-dns", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-spf", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-txt", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-soa", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-blacklist", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "hetrixtools-fqdnblacklist", Position = 0)]
    [string[]]
    $fqdn,

    [Parameter(Mandatory = $true, ParameterSetName = "mtr", Position = 0)]
    $target,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrinohostrep2", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "neutrinourlinfo", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "virustotal-urlreport", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "urlscanio-urlscan", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "urlhaus-urlquery", Position = 0)]
    [string[]]
    $url,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-urlemail", Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-urlverify", Position = 0)]
    [string[]]
    $email,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-html", Position = 0)]
    [string[]]
    $html,

    [Parameter(Mandatory = $true, ParameterSetName = "virustotal-filereport", Position = 0)]
    [string[]]
    $filepath,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-ipblock", Position = 1)]
    [switch]
    $ipblocklist,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-ipprobe", Position = 1)]
    [switch]
    $ipprobe,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrinohostrep1", Position = 1)]
    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-hostrep", Position = 1)]
    [Parameter(Mandatory = $true, ParameterSetName = "neutrinohostrep2", Position = 1)]
    [switch]
    $hostrep,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-ipinfo", Position = 1)]
    [switch]
    $ipinfo,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrinourlinfo", Position = 1)]
    [switch]
    $urlinfo,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-urlemail", Position = 1)]
    [switch]
    $emailvalidate,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-urlverify", Position = 1)]
    [switch]
    $emailverify,

    [Parameter(Mandatory = $true, ParameterSetName = "neutrino-html", Position = 1)]
    [switch]
    $htmlclean,

    [Parameter(Mandatory = $true, ParameterSetName = "mtr", Position = 1)]
    [switch]
    $traceroute,

    [Parameter(Mandatory = $true, ParameterSetName = "ping", Position = 1)]
    [switch]
    $ping,

    [Parameter(Mandatory = $true, ParameterSetName = "whois", Position = 1)]
    [switch]
    $whois,

    [Parameter(Mandatory = $true, ParameterSetName = "virustotal-ipreport", Position = 1)]
    [switch]
    $ipreport,

    [Parameter(Mandatory = $true, ParameterSetName = "virustotal-urlreport", Position = 1)]
    [switch]
    $urlreport,

    [Parameter(Mandatory = $true, ParameterSetName = "virustotal-filereport", Position = 1)]
    [switch]
    $filereport,

    [Parameter(Mandatory = $true, ParameterSetName = "virustotal-domainreport", Position = 1)]
    [switch]
    $domainreport,

    [Parameter(Mandatory = $true, ParameterSetName = "ipstack-iplookup", Position = 1)]
    [switch]
    $iplookup,

    [Parameter(Mandatory = $true, ParameterSetName = "urlscanio-urlscan", Position = 1)]
    [switch]
    $urlscan,

    [Parameter(Mandatory = $true, ParameterSetName = "fraudguard-iprep", Position = 1)]
    [switch]
    $iprep,

    [Parameter(Mandatory = $true, ParameterSetName = "shodan-ipservices", Position = 1)]
    [switch]
    $ipservices,

    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-mx", Position = 1)]
    [switch]
    $mx,

    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-a", Position = 1)]
    [switch]
    $a,

    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-dns", Position = 1)]
    [switch]
    $dns,

    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-spf", Position = 1)]
    [switch]
    $spf,

    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-txt", Position = 1)]
    [switch]
    $txt,

    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-soa", Position = 1)]
    [switch]
    $soa,

    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-ptr", Position = 1)]
    [switch]
    $ptr,

    [Parameter(Mandatory = $true, ParameterSetName = "MXtoolbox-blacklist", Position = 1)]
    [switch]
    $blacklist,

    [Parameter(Mandatory = $true, ParameterSetName = "hetrixtools-IPblacklist", Position = 1)]
    [switch]
    $ipblacklist,

    [Parameter(Mandatory = $true, ParameterSetName = "hetrixtools-fqdnblacklist", Position = 1)]
    [switch]
    $fqdnblacklist,

    [Parameter(Mandatory = $true, ParameterSetName = "urlhaus-urlquery", Position = 1)]
    [switch]
    $urlquery,


    [Parameter(Mandatory = $false, ParameterSetName = "fraudguard-iprep", Position = 2)]
    [Parameter(Mandatory = $false, ParameterSetName = "ipstack-iplookup", Position = 2)]
    [Parameter(Mandatory = $false, ParameterSetName = "neutrino-ipblock", Position = 2)]
    [Parameter(Mandatory = $false, ParameterSetName = "neutrino-ipprobe", Position = 2)]
    [Parameter(Mandatory = $false, ParameterSetName = "neutrino-hostrep", Position = 2)]
    [Parameter(Mandatory = $false, ParameterSetName = "neutrinohostrep1", Position = 2)]
    [Parameter(Mandatory = $false, ParameterSetName = "neutrino-hostrep2", Position = 2)]
    [Parameter(Mandatory = $false, ParameterSetName = "neutrino-ipinfo", Position = 2)]
    [switch]
    $raw
)

$script:currentdir = $PSScriptRoot
$script:loggingDate = get-date -Format MM-dd-yyyy-hh:mm:ss
$script:logDate = Get-Date -Format MM-dd-yyyy

Get-ChildItem -Path $currentdir\functions -Filter *.ps1 | ForEach-Object { . $_.FullName }
If (!(Test-Path $currentdir\log)) { 
    mkdir $currentdir\log >$null 2>&1 
}
Set-Console  >$null 2>&1
Test-PSversion
Set-Settings
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
ElseIf ($html) {
    New-Request $html
}
ElseIf ($target) {
    New-Request $target
}
ElseIf ($filepath) {
    New-Request $filepath
}
