NAME
    sift.ps1

SYNOPSIS
    A collection of PowerShell scripts to utilize 3rd party APIs and research IPs, URLs, and Domains


SYNTAX
    sift.ps1 [[-ipaddress] <IPAddress[]>] [[-ipblocklist]] [[-ipprobe]] [[-hostrep]] [[-ipinfo]] [[-ping]]
    [[-whois]] [[-ipreport]] [[-iplookup]] [[-iprep]] [[-ipservices]] [[-ptr]] [[-ipblacklist]] [[-whoblacklist]] [[-ippulse]] [-raw]
    [<CommonParameters>]

    sift.ps1 [[-fqdn] <String[]>] [[-hostrep]] [[-domainreport]] [[-hostnamerep]] [[-mx]] [[-a]] [[-dns]]
    [[-whoisapi]] [[-spf]] [[-txt]] [[-soa]] [[-blacklist]] [[-fqdnblacklist]] [[-fqdnpulse]] [[-domainscore]] [[-domainscorecheck]] [-raw]
    [<CommonParameters>]

    sift.ps1 [[-target] <Object>] [[-traceroute]] [-raw] [<CommonParameters>]

    sift.ps1 [[-url] <String[]>] [[-hostrep]] [[-urlinfo]] [[-urlreport]] [[-urlscan]] [[-urlquery]]
    [[-urlsubmit]] [-raw] [<CommonParameters>]

    sift.ps1 [[-filepath] <String[]>] [[-filereport]] [-raw] [<CommonParameters>]

    sift.ps1 [[-email] <String[]>] [[-emailvalidate]] [[-emailverify]] [-raw] [<CommonParameters>]

    sift.ps1 [[-html] <String[]>] [[-htmlclean]] [-raw] [<CommonParameters>]

    sift.ps1 [[-addkey]] [[-neutrino]] [[-virustotal]] [[-ipstack]] [[-urlscanio]] [[-shodan]] [[-hetrix]]
    [[-fraudguard]] [[-mxtoolbox]] [[-urlhaus]] [[-whoapi]] [-raw] [<CommonParameters>]

    sift.ps1 [[-pwned]] [-raw] [<CommonParameters>]

    sift.ps1 [[-phone] <Int64>] [-raw] [<CommonParameters>]

    sift.ps1 [[-unlock]] [-raw] [<CommonParameters>]


DESCRIPTION


RELATED LINKS
    https://github.com/scrawladmin/sift

REMARKS
    To see the examples, type: "Get-Help sift.ps1 -Examples"
    For more information, type: "Get-Help sift.ps1 -Detailed"
    For technical information, type: "Get-Help sift.ps1 -Full"
    For online help, type: "Get-Help sift.ps1 -Online"
