NAME
    
    sift

SYNOPSIS
    
    A collection of PowerShell scripts to utilize 3rd party APIs and research IPs, URLs, and Domains


SYNTAX
    

    sift.ps1 [[-ipaddress] <IPAddress[]>] [[-ipblocklist]] [[-ipprobe]] [[-hostrep]]
    [[-ipinfo]] [[-ping]] [[-whois]] [[-ipreport]] [[-iplookup]] [[-iprep]] [[-ipservices]] [[-ptr]] [[-ipblacklist]]
    [[-ippulse]] [<CommonParameters>]

    sift.ps1 [[-fqdn] <String[]>] [[-hostrep]] [[-domainreport]] [[-mx]] [[-a]]
    [[-dns]] [[-spf]] [[-txt]] [[-soa]] [[-blacklist]] [[-fqdnblacklist]] [[-fqdnpulse]] [<CommonParameters>]

    sift.ps1 [[-target] <Object>] [[-traceroute]] [<CommonParameters>]

    sift.ps1 [[-url] <String[]>] [[-hostrep]] [[-urlinfo]] [[-urlreport]] [[-urlscan]]
    [[-urlquery]] [<CommonParameters>]

    sift.ps1 [[-filepath] <String[]>] [[-filereport]] [<CommonParameters>]

    sift.ps1 [[-addkey]] [[-neutrino]] [[-virustotal]] [[-ipstack]] [[-urlscanio]]
    [[-shodan]] [[-hetrix]] [[-fraudguard]] [<CommonParameters>]

    sift.ps1 [[-unlock]] [<CommonParameters>]


DESCRIPTION

![](https://github.com/scrawladmin/sift/blob/main/sift.gif)

RELATED LINKS
    
    https://github.com/scrawladmin/sift
    https://gist.github.com/tylerapplebaum/dc527a3bd875f11871e2
    https://github.com/darkoperator/Posh-VirusTotal
    https://www.powershellgallery.com/packages/MxLookup/1.0.0
    https://www.powershellgallery.com/packages/PSScriptTools/2.9.0/Content/functions%5CGet-WhoIs.ps1
    https://github.com/PrateekKumarSingh/Graphical
    https://gist.github.com/PrateekKumarSingh/715b0576a0cd08769b967db7a86355ff
    https://github.com/copdips/PSScripts/blob/master/Text/Select-ColorString.ps1


REMARKS
    
    To see the examples, type: "get-help sift -examples".
    For more information, type: "get-help sift -detailed".
    For technical information, type: "get-help sift -full".
    For online help, type: "get-help sift -online"
    
   
   
INSTALL   

   1. Download, Unzip, Add to Path in Powershell User Profile.
   2. Add API info with -addkey param




