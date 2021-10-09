NAME
    
    sift

SYNOPSIS
    
    A collection of PowerShell scripts to utilize 3rd party APIs and research IPs, URLs, and Domains


SYNTAX
    
    sift [-ipaddress] <IPAddress[]> [-ippulse] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-ipblacklist] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-ptr] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-ipservices] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-iprep] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-iplookup] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-ipreport] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-whois] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-ping] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-hostrep] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-ipinfo] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-ipprobe] [<CommonParameters>]

    sift [-ipaddress] <IPAddress[]> [-ipblocklist] [<CommonParameters>]

    sift [-fqdn] <String[]> [-fqdnpulse] [<CommonParameters>]

    sift [-fqdn] <String[]> [-fqdnblacklist] [<CommonParameters>]

    sift [-fqdn] <String[]> [-blacklist] [<CommonParameters>]

    sift [-fqdn] <String[]> [-soa] [<CommonParameters>]

    sift [-fqdn] <String[]> [-txt] [<CommonParameters>]

    sift [-fqdn] <String[]> [-spf] [<CommonParameters>]

    sift [-fqdn] <String[]> [-dns] [<CommonParameters>]

    sift [-fqdn] <String[]> [-a] [<CommonParameters>]

    sift [-fqdn] <String[]> [-mx] [<CommonParameters>]

    sift [-fqdn] <String[]> [-domainreport] [<CommonParameters>]

    sift [-fqdn] <String[]> [-hostrep] [<CommonParameters>]

    sift [-target] <Object> [-traceroute] [<CommonParameters>]

    sift [-url] <String[]> [-urlquery] [<CommonParameters>]

    sift [-url] <String[]> [-urlscan] [<CommonParameters>]

    sift [-url] <String[]> [-urlreport] [<CommonParameters>]

    sift [-url] <String[]> [-urlinfo] [<CommonParameters>]

    sift [-url] <String[]> [-hostrep] [<CommonParameters>]

    sift [-filepath] <String[]> [-filereport] [<CommonParameters>]


DESCRIPTION


RELATED LINKS
    
    https://github.com/scrawladmin/sift
    https://gist.github.com/tylerapplebaum/dc527a3bd875f11871e2
    https://github.com/darkoperator/Posh-VirusTotal
    https://www.powershellgallery.com/packages/MxLookup/1.0.0
    https://www.powershellgallery.com/packages/PSScriptTools/2.9.0/Content/functions%5CGet-WhoIs.ps1


REMARKS
    
    To see the examples, type: "get-help sift -examples".
    For more information, type: "get-help sift -detailed".
    For technical information, type: "get-help sift -full".
    For online help, type: "get-help sift -online"
    
   
   
INSTALL   

   1. Download, Unzip, Add to Path in Powershell User Profile.
   2. Add API info to fn_settings.ps1



![](https://github.com/scrawladmin/sift/blob/main/sift.gif)
