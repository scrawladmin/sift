NAME
    
    sift

SYNOPSIS
    
    A collection of PowerShell scripts to utilize 3rd party APIs and research IPs, URLs, and Domains


SYNTAX
    

    sift [[-ipaddress] <IPAddress[]>] [[-ipblocklist]] [[-ipprobe]] [[-hostrep]]
    [[-ipinfo]] [[-ping]] [[-whois]] [[-ipreport]] [[-iplookup]] [[-iprep]] [[-ipservices]] [[-ptr]] [[-ipblacklist]]
    [[-ippulse]] [-raw] [<CommonParameters>]

    sift [[-fqdn] <String[]>] [[-hostrep]] [[-domainreport]] [[-mx]] [[-a]]
    [[-dns]] [[-spf]] [[-txt]] [[-soa]] [[-blacklist]] [[-fqdnblacklist]] [[-fqdnpulse]] [-raw] [<CommonParameters>]

    sift [[-target] <Object>] [[-traceroute]] [-raw] [<CommonParameters>]

    sift [[-url] <String[]>] [[-hostrep]] [[-urlinfo]] [[-urlreport]] [[-urlscan]]
    [[-urlquery]] [-raw] [<CommonParameters>]

    sift [[-filepath] <String[]>] [[-filereport]] [-raw] [<CommonParameters>]

    sift [[-email] <String[]>] [[-emailvalidate]] [[-emailverify]] [-raw]
    [<CommonParameters>]

    sift [[-html] <String[]>] [[-htmlclean]] [-raw] [<CommonParameters>]

    sift [[-addkey]] [[-neutrino]] [[-virustotal]] [[-ipstack]] [[-urlscanio]]
    [[-shodan]] [[-hetrix]] [[-fraudguard]] [[-mxtoolbox]] [-raw] [<CommonParameters>]

    sift [[-pwned]] [-raw] [<CommonParameters>]

    sift [[-unlock]] [-raw] [<CommonParameters>]

    sift [[-phone]] [[-phonevalidate]] [-raw] [<CommonParameters>]


DESCRIPTION

![](https://github.com/scrawladmin/sift/blob/main/sift.gif)

RELATED LINKS
    
https://www.neutrinoapi.com/   
https://mxtoolbox.com/c/products/mxtoolboxapi   
https://otx.alienvault.com/api   
https://fraudguard.io/   
https://developer.shodan.io/   
https://www.virustotal.com/gui/my-apikey   
https://docs.hetrixtools.com/api/v3/   
https://urlscan.io/docs/api/   
https://ipstack.com/api-key   
https://haveibeenpwned.com/API/v2   
https://whois.arin.net/   
https://urlhaus.abuse.ch/api/   



REMARKS
    
    To see the examples, type: "get-help sift -examples".
    For more information, type: "get-help sift -detailed".
    For technical information, type: "get-help sift -full".
    For online help, type: "get-help sift -online"
    
   
   
INSTALL   

    1. Download, Unzip, Add to Path in Powershell User Profile.




